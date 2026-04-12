"""Anti-stampede protections for ZOVARK worker.

Thundering Herd / Cache Stampede protections:
1. Request coalescing: Multiple identical requests share one computation
2. Probabilistic early refresh: Refresh cache before expiry to prevent stampede
3. Shard-aware locking: Distributed locks for cache population

Tables used: coalescing_locks (for DB-backed locks)
Uses Redis for in-memory coalescing.
"""

import json
import os
import random
import time

import psycopg2
from temporalio import activity

import logger


def _get_redis():
    """Get Redis connection. Returns None if unavailable."""
    try:
        import redis
        url = os.environ.get("REDIS_URL", "redis://:hydra-redis-dev-2026@redis:6379/0")  # FIX #16
        return redis.from_url(url, decode_responses=True)
    except Exception:
        return None


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


REDIS_COALESCE_PREFIX = "zovark:coalesce:"
REDIS_COALESCE_RESULT_PREFIX = "zovark:coalesce_result:"
REDIS_SHARD_LOCK_PREFIX = "zovark:shard_lock:"


# ---------------------------------------------------------------------------
# Request Coalescer
# ---------------------------------------------------------------------------

class RequestCoalescer:
    """Multiple identical requests wait for a single computation.

    Uses Redis SETNX for distributed lock. Waiters poll with exponential
    backoff (100ms, 200ms, 400ms, max 2s). If lock holder crashes, lock
    expires after ttl_seconds.
    """

    def __init__(self):
        self._redis = None

    def _get_redis(self):
        if self._redis is None:
            self._redis = _get_redis()
        return self._redis

    def coalesce(self, cache_key: str, compute_fn, ttl_seconds: int = 300, tenant_id: str = None):
        """Execute compute_fn with coalescing protection.

        If another worker is already computing for this key, wait for the
        result instead of computing again.

        Args:
            cache_key: Unique key for this computation
            compute_fn: Callable that returns the result
            ttl_seconds: Lock TTL and result cache TTL
            tenant_id: Tenant UUID for namespace isolation (Security P0#7)
        Returns:
            Result from compute_fn (or from the other worker's computation)
        """
        r = self._get_redis()
        if r is None:
            # No Redis — just compute directly
            return compute_fn()

        # Namespace keys by tenant_id to prevent cross-tenant result sharing
        ns = f"{tenant_id}:{cache_key}" if tenant_id else cache_key
        lock_key = f"{REDIS_COALESCE_PREFIX}{ns}"
        result_key = f"{REDIS_COALESCE_RESULT_PREFIX}{ns}"

        # Check if result already cached
        try:
            cached = r.get(result_key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass

        # Try to acquire lock
        try:
            acquired = r.set(lock_key, "1", nx=True, ex=ttl_seconds)
        except Exception:
            return compute_fn()

        if acquired:
            # We are the leader — compute and store result
            try:
                result = compute_fn()
                r.setex(result_key, ttl_seconds, json.dumps(result, default=str))
                return result
            finally:
                try:
                    r.delete(lock_key)
                except Exception:
                    pass
        else:
            # Wait for the leader to finish
            return self._wait_for_result(r, result_key, lock_key, ttl_seconds)

    def _wait_for_result(self, r, result_key: str, lock_key: str, max_wait: int):
        """Poll for result with exponential backoff."""
        backoff_ms = 100
        max_backoff_ms = 2000
        elapsed = 0.0
        timeout = min(max_wait, 30)  # Never wait more than 30s

        while elapsed < timeout:
            try:
                cached = r.get(result_key)
                if cached:
                    return json.loads(cached)
                # Check if lock still held
                if not r.exists(lock_key):
                    # Lock released but no result — leader may have failed
                    break
            except Exception:
                break

            sleep_secs = backoff_ms / 1000.0
            time.sleep(sleep_secs)
            elapsed += sleep_secs
            backoff_ms = min(backoff_ms * 2, max_backoff_ms)

        return None  # Timeout or leader failed — caller should handle


# ---------------------------------------------------------------------------
# Probabilistic Early Refresh
# ---------------------------------------------------------------------------

class ProbabilisticRefresh:
    """Refresh cache entries probabilistically before expiry.

    As TTL approaches 0, the probability of refreshing increases.
    This prevents all workers from trying to refresh at the same moment.
    """

    @staticmethod
    def should_refresh(key: str, ttl_remaining: int, total_ttl: int) -> bool:
        """Determine if this cache entry should be refreshed early.

        Args:
            key: Cache key (used for logging only)
            ttl_remaining: Seconds remaining until expiry
            total_ttl: Original TTL in seconds
        Returns:
            True if this worker should refresh the entry
        """
        if total_ttl <= 0 or ttl_remaining <= 0:
            return True

        ratio = ttl_remaining / total_ttl
        # P(refresh) increases as TTL decreases
        # At 20% TTL remaining, ~80% chance of refresh
        threshold = max(0, 1.0 - ratio * random.random())
        should = threshold > 0.5

        if should and ratio < 0.2:
            logger.info("Probabilistic refresh triggered",
                        key=key, ttl_remaining=ttl_remaining, total_ttl=total_ttl)

        return should


# ---------------------------------------------------------------------------
# Shard-Aware Distributed Lock
# ---------------------------------------------------------------------------

class ShardLock:
    """Shard-aware distributed locking for cache population.

    Uses Redis SET NX EX for lock acquisition with owner verification
    on release to prevent releasing another worker's lock.
    """

    def __init__(self):
        self._redis = None

    def _get_redis(self):
        if self._redis is None:
            self._redis = _get_redis()
        return self._redis

    def acquire(self, shard_key: str, worker_id: str, ttl: int = 30) -> bool:
        """Acquire a shard lock.

        Args:
            shard_key: The shard to lock
            worker_id: ID of the worker acquiring the lock
            ttl: Lock TTL in seconds
        Returns:
            True if lock acquired
        """
        r = self._get_redis()
        if r is None:
            return True  # Fail open

        lock_key = f"{REDIS_SHARD_LOCK_PREFIX}{shard_key}"
        try:
            result = r.set(lock_key, worker_id, nx=True, ex=ttl)
            acquired = bool(result)
            if acquired:
                logger.info("Shard lock acquired", shard_key=shard_key, worker_id=worker_id)
            return acquired
        except Exception as e:
            logger.warn("Shard lock acquire failed, failing open", error=str(e))
            return True

    def release(self, shard_key: str, worker_id: str) -> bool:
        """Release a shard lock (only if we own it).

        Args:
            shard_key: The shard to unlock
            worker_id: ID of the worker releasing the lock
        Returns:
            True if lock was released
        """
        r = self._get_redis()
        if r is None:
            return True

        lock_key = f"{REDIS_SHARD_LOCK_PREFIX}{shard_key}"

        # Lua script: only delete if we own it
        release_script = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        else
            return 0
        end
        """
        try:
            result = r.eval(release_script, 1, lock_key, worker_id)
            released = bool(result)
            if released:
                logger.info("Shard lock released", shard_key=shard_key, worker_id=worker_id)
            return released
        except Exception as e:
            logger.warn("Shard lock release failed", error=str(e))
            return False


# Module-level instances
_coalescer = RequestCoalescer()
_refresher = ProbabilisticRefresh()
_shard_lock = ShardLock()


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------

@activity.defn
async def coalesced_llm_call(params: dict) -> dict:
    """Make an LLM call with request coalescing and caching.

    Checks investigation_cache first. If cache miss, acquires coalescing lock
    and makes LLM call. Other workers with the same cache key will wait for
    the result instead of making duplicate calls.

    Args:
        params: {cache_key, tenant_id, prompt, model_tier}
    Returns:
        {result, cache_hit, coalesced}
    """
    cache_key = params.get("cache_key")
    tenant_id = params.get("tenant_id")
    prompt = params.get("prompt", "")
    model_tier = params.get("model_tier", "fast")

    # Check cache first (tenant-scoped key for isolation — Security P0#7)
    r = _get_redis()
    cache_ns = f"{tenant_id}:{cache_key}" if tenant_id and cache_key else cache_key
    if r and cache_key:
        try:
            cached = r.get(f"zovark:inv_cache:{cache_ns}")
            if cached:
                logger.info("Coalesced LLM call: cache hit", cache_key=cache_key)
                return {"result": json.loads(cached), "cache_hit": True, "coalesced": False}
        except Exception:
            pass

    # Compute function for coalescing
    def _do_llm_call():
        from model_config import get_tier_config as _get_tier_config
        tier_config = _get_tier_config(model_tier)
        llm_endpoint = os.environ.get("ZOVARK_LLM_ENDPOINT", "http://zovark-inference:8080/v1/chat/completions")
        api_key = os.environ.get("ZOVARK_LLM_KEY", "zovark-llm-key-2026")

        payload = {
            "model": tier_config["model"],
            "messages": [
                {"role": "system", "content": "You are a senior security analyst. Respond with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": tier_config["temperature"],
            "max_tokens": tier_config["max_tokens"],
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        # Synchronous call (used within coalescer)
        import urllib.request
        req = urllib.request.Request(
            llm_endpoint,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode())
                content = result["choices"][0]["message"]["content"].strip()
                return {"content": content, "usage": result.get("usage", {})}
        except Exception as e:
            logger.error("Coalesced LLM call failed", error=str(e))
            return {"content": "", "usage": {}, "error": str(e)}

    if cache_key:
        result = _coalescer.coalesce(cache_key, _do_llm_call, ttl_seconds=300, tenant_id=tenant_id)
        if result is None:
            # Coalescing timeout — compute directly
            result = _do_llm_call()
            coalesced = False
        else:
            coalesced = True
    else:
        result = _do_llm_call()
        coalesced = False

    # Store in cache (tenant-scoped key — Security P0#7)
    if r and cache_key and result:
        try:
            r.setex(f"zovark:inv_cache:{cache_ns}", 300, json.dumps(result, default=str))
        except Exception:
            pass

    logger.info("Coalesced LLM call complete",
                tenant_id=tenant_id, cache_key=cache_key, coalesced=coalesced)

    return {"result": result, "cache_hit": False, "coalesced": coalesced}


@activity.defn
async def check_stampede_protection(params: dict) -> dict:
    """Check if stampede protections should be activated.

    Evaluates alert ingestion rate and applies backpressure or drop
    policies when the system is overwhelmed.

    Args:
        params: {tenant_id, alert_rate_per_sec}
    Returns:
        {throttle, backpressure, drop_below_severity}
    """
    tenant_id = params.get("tenant_id")
    alert_rate = params.get("alert_rate_per_sec", 0)

    throttle = False
    backpressure = False
    drop_below_severity = None

    if alert_rate > 10000:
        # Critical overload: drop low-severity alerts
        throttle = True
        backpressure = True
        drop_below_severity = "medium"
        logger.warn("Stampede protection: dropping low-severity alerts",
                    tenant_id=tenant_id, alert_rate=alert_rate)
    elif alert_rate > 1000:
        # High load: enable backpressure
        throttle = True
        backpressure = True
        logger.warn("Stampede protection: backpressure enabled",
                    tenant_id=tenant_id, alert_rate=alert_rate)
    elif alert_rate > 100:
        # Moderate load: throttle
        throttle = True
        logger.info("Stampede protection: throttling enabled",
                    tenant_id=tenant_id, alert_rate=alert_rate)

    # Log surge event to DB
    if throttle:
        try:
            conn = _get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO alert_surge_events
                            (tenant_id, alert_rate_per_sec, throttle_enabled,
                             backpressure_enabled, drop_below_severity)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (tenant_id, alert_rate, throttle, backpressure, drop_below_severity))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.warn("Surge event logging failed", error=str(e))

    return {
        "throttle": throttle,
        "backpressure": backpressure,
        "drop_below_severity": drop_below_severity,
    }
