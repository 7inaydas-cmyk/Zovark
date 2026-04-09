package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// localLimiter is an in-memory fallback rate limiter used when Redis is unavailable.
// It prevents fail-open behavior by enforcing limits locally.
var localLimiter = struct {
	sync.Mutex
	counts map[string]int
	window map[string]time.Time
}{counts: make(map[string]int), window: make(map[string]time.Time)}

func localRateCheck(key string, limit int, dur time.Duration) bool {
	localLimiter.Lock()
	defer localLimiter.Unlock()
	now := time.Now()
	w, ok := localLimiter.window[key]
	if !ok || now.Sub(w) > dur {
		localLimiter.counts[key] = 1
		localLimiter.window[key] = now
		return true
	}
	if localLimiter.counts[key] >= limit {
		return false
	}
	localLimiter.counts[key]++
	return true
}

// ============================================================
// PER-TENANT API RATE LIMITING WITH REDIS (Issue #11)
// ============================================================

var redisClient *redis.Client

func initRedis() {
	// Valkey is wire-compatible with Redis. Prefer VALKEY_URL, fall back
	// to REDIS_URL for legacy compat. The go-redis client works unchanged.
	rawURL := getEnvOrDefault("VALKEY_URL", getEnvOrDefault("REDIS_URL", "valkey:6379"))
	password := getEnvOrDefault("VALKEY_PASSWORD", getEnvOrDefault("REDIS_PASSWORD", ""))

	// Try parsing as a full redis:// URL first (handles redis://:password@host:port/db)
	if opts, err := redis.ParseURL(rawURL); err == nil {
		opts.PoolSize = 20
		opts.MinIdleConns = 5
		opts.DialTimeout = 2 * time.Second
		opts.ReadTimeout = 3 * time.Second
		opts.WriteTimeout = 3 * time.Second
		redisClient = redis.NewClient(opts)
	} else {
		// Fallback: treat as host:port
		addr := rawURL
		if len(addr) > 8 && addr[:8] == "redis://" {
			addr = addr[8:]
		}
		redisClient = redis.NewClient(&redis.Options{
			Addr:         addr,
			Password:     password,
			DB:           0,
			PoolSize:     20,
			MinIdleConns: 5,
			DialTimeout:  2 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Printf("[WARN] Redis ping failed (will use local fallback): %v", err)
	} else {
		log.Println("Redis connection pool initialized (pool_size=20)")
	}
}

// slidingWindowIncrement implements a Redis-based sliding window rate limiter.
// Returns (current count, allowed, error).
func slidingWindowIncrement(tenantID, endpoint string, windowSeconds, limit int) (int, bool, error) {
	now := time.Now().Unix()
	windowStart := now - int64(windowSeconds)
	key := fmt.Sprintf("ratelimit:%s:%s:%d", tenantID, endpoint, windowSeconds)
	member := fmt.Sprintf("%d:%d", now, time.Now().UnixNano())

	ctx := context.Background()

	// Pipeline: ZADD + ZREMRANGEBYSCORE + ZCARD + EXPIRE in one round trip
	pipe := redisClient.Pipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: member})
	pipe.ZRemRangeByScore(ctx, key, "-inf", fmt.Sprintf("%d", windowStart))
	zcardCmd := pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, time.Duration(windowSeconds+10)*time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		log.Printf("[WARN] Redis rate limit unavailable, using local fallback: %v", err)
		allowed := localRateCheck(key, limit, time.Duration(windowSeconds)*time.Second)
		return 0, allowed, err
	}

	count := int(zcardCmd.Val())
	return count, count <= limit, nil
}

// getTenantRateLimits reads per-tenant rate limit overrides from settings JSONB.
func getTenantRateLimits(ctx context.Context, tenantID string) (perMinute int, perHour int) {
	perMinute = 100 // Default: 100 req/min
	perHour = 1000  // Default: 1000 req/hour

	var settings map[string]interface{}
	err := dbPool.QueryRow(ctx,
		"SELECT settings FROM tenants WHERE id = $1", tenantID,
	).Scan(&settings)
	if err != nil {
		return perMinute, perHour
	}

	if rl, ok := settings["rate_limit_per_minute"]; ok {
		if v, ok := rl.(float64); ok {
			perMinute = int(v)
		}
	}
	if rl, ok := settings["rate_limit_per_hour"]; ok {
		if v, ok := rl.(float64); ok {
			perHour = int(v)
		}
	}

	return perMinute, perHour
}

// tenantRateLimitMiddleware enforces per-tenant rate limiting using Redis sliding windows.
func tenantRateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Internal bypass: Forge (and other admin-authorized internal
		// load generators) set this header to skip rate limiting. The
		// admin JWT must still be valid — this is authorization, not
		// authentication. Without this, benchmark runs get silently 429'd.
		// NOTE: middleware sets "user_role" not "role" (see middleware.go:105)
		if c.GetHeader("X-Zovark-Internal") == "forge" {
			if role, _ := c.Get("user_role"); role == "admin" {
				c.Next()
				return
			}
		}

		tenantID, exists := c.Get("tenant_id")
		if !exists {
			c.Next()
			return
		}

		tid := tenantID.(string)
		endpoint := c.FullPath()
		if endpoint == "" {
			endpoint = c.Request.URL.Path
		}

		perMinute, perHour := getTenantRateLimits(c.Request.Context(), tid)

		// Check per-minute limit
		countMin, allowedMin, err := slidingWindowIncrement(tid, endpoint, 60, perMinute)
		if err != nil {
			log.Printf("[WARN] Redis rate limit unavailable, using local fallback: %v", err)
			if !allowedMin {
				retryAfter := int64(60)
				c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
				c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", perMinute))
				c.Header("X-RateLimit-Remaining", "0")
				c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Unix()+retryAfter))
				respondError(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
					fmt.Sprintf("Rate limit exceeded: %d requests per minute. Retry after %d seconds.", perMinute, retryAfter))
				c.Abort()
				return
			}
			c.Next()
			return
		}

		if !allowedMin {
			retryAfter := 60 - (time.Now().Unix() % 60)
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", perMinute))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Unix()+retryAfter))
			respondError(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
				fmt.Sprintf("Rate limit exceeded: %d requests per minute. Retry after %d seconds.", perMinute, retryAfter))
			c.Abort()
			return
		}

		// Check per-hour limit
		countHour, allowedHour, err := slidingWindowIncrement(tid, endpoint, 3600, perHour)
		if err != nil {
			log.Printf("[WARN] Redis rate limit unavailable, using local fallback: %v", err)
			if !allowedHour {
				retryAfter := int64(3600)
				c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
				c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", perHour))
				c.Header("X-RateLimit-Remaining", "0")
				c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Unix()+retryAfter))
				respondError(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
					fmt.Sprintf("Rate limit exceeded: %d requests per hour. Retry after %d seconds.", perHour, retryAfter))
				c.Abort()
				return
			}
			c.Next()
			return
		}

		if !allowedHour {
			retryAfter := 3600 - (time.Now().Unix() % 3600)
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", perHour))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Unix()+retryAfter))
			respondError(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
				fmt.Sprintf("Rate limit exceeded: %d requests per hour. Retry after %d seconds.", perHour, retryAfter))
			c.Abort()
			return
		}

		// Set rate limit headers
		remainingMin := perMinute - countMin
		if remainingMin < 0 {
			remainingMin = 0
		}
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", perMinute))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remainingMin))

		_ = countHour // Used in the check above

		c.Next()
	}
}
