package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		log.Printf("[%s] %s %d %v", c.Request.Method, c.Request.URL.Path, c.Writer.Status(), latency)
	}
}

func corsMiddleware() gin.HandlerFunc {
	config := cors.DefaultConfig()

	// Read allowed origins from env (comma-separated), default to localhost for dev
	originsEnv := os.Getenv("ZOVARK_CORS_ORIGINS")
	if originsEnv != "" {
		origins := strings.Split(originsEnv, ",")
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
		config.AllowOrigins = origins
	} else {
		config.AllowOrigins = []string{"http://localhost:3000", "http://localhost:3100", "http://localhost:5173"}
	}

	config.AllowCredentials = true
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	config.ExposeHeaders = []string{"Set-Cookie"}
	return cors.New(config)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check API key first (M2M authentication)
		if authenticateAPIKey(c) {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		// Fallback to query param for SSE connections (browsers can't set headers on EventSource)
		if authHeader == "" {
			if qToken := c.Query("token"); qToken != "" {
				authHeader = "Bearer " + qToken
			}
		}
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
			return
		}

		tokenString := parts[1]

		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(appConfig.JWTSecret), nil
		})

		if err != nil {
			log.Printf("JWT parsing error: %v", err)
			msg := "Invalid token"
			if strings.Contains(err.Error(), "token is expired") {
				msg = "Token expired"
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg})
			return
		}

		if !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		claims, ok := token.Claims.(*CustomClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		// Inject tenant and user references into request context
		c.Set("tenant_id", claims.TenantID)
		c.Set("user_id", claims.UserID)
		c.Set("user_role", claims.Role)

		c.Next()
	}
}

func requireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}

		roleStr, ok := userRole.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}

		for _, role := range allowedRoles {
			if roleStr == role {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
	}
}
