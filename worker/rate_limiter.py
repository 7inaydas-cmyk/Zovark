"""Lease-based rate limiter — replaces INCR/DECR with atomic Redis leases.

Each task acquires a lease (SET NX + EX), heartbeats extend TTL,
and release deletes the key. If Redis is down, fail open.

Lease key pattern: tenant:{tenant_id}:lease:{task_id}
TTL: 60 seconds (heartbeat every 20s extends it)
"""

import os
import redis
import logger

_redis_conn = None

# Lua script: atomic acquire + count check
# KEYS[1] = lease key, KEYS[2] = tenant active set key
# ARGV[1] = worker_id, ARGV[2] = TTL seconds, ARGV[3] = max_concurrent, ARGV[4] = task_id
_ACQUIRE_SCRIPT = """
local current = redis.call('SCARD', KEYS[2])
if current >= tonumber(ARGV[3]) then
    return 0
end
local ok = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', tonumber(ARGV[2]))
if ok then
    redis.call('SADD', KEYS[2], ARGV[4])
    redis.call('EXPIRE', KEYS[2], 3600)
    return 1
else
    return 0
end
"""

# Lua script: atomic release
# KEYS[1] = lease key, KEYS[2] = tenant active set key
# ARGV[1] = task_id
_RELEASE_SCRIPT = """
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return 1
"""

_acquire_sha = None
_release_sha = None


def _get_redis():
    global _redis_conn
    if _redis_conn is None:
        url = os.environ.get("VALKEY_URL") or os.environ.get("REDIS_URL", "redis://valkey:6379/0")
        _redis_conn = redis.from_url(url, decode_responses=True)
    return _redis_conn


def _ensure_scripts(r):
    """Register Lua scripts (cached by SHA)."""
    global _acquire_sha, _release_sha
    if _acquire_sha is None:
        _acquire_sha = r.script_load(_ACQUIRE_SCRIPT)
    if _release_sha is None:
        _release_sha = r.script_load(_RELEASE_SCRIPT)


def _lease_key(tenant_id: str, task_id: str) -> str:
    return f"tenant:{tenant_id}:lease:{task_id}"


def _active_set_key(tenant_id: str) -> str:
    return f"tenant:{tenant_id}:active_leases"


def acquire_lease(tenant_id: str, task_id: str, worker_id: str, max_concurrent: int = 50, ttl: int = 60) -> bool:
    """Atomically acquire a lease if under the concurrency limit.

    Returns True if lease acquired, False if rate limited.
    Fails open (returns True) if Redis is unavailable.
    """
    try:
        r = _get_redis()
        _ensure_scripts(r)
        lease_key = _lease_key(tenant_id, task_id)
        active_key = _active_set_key(tenant_id)
        result = r.evalsha(_acquire_sha, 2, lease_key, active_key, worker_id, ttl, max_concurrent, task_id)
        acquired = bool(result)
        if acquired:
            logger.info("Lease acquired", tenant_id=tenant_id, task_id=task_id, worker_id=worker_id)
        else:
            logger.warn("Lease denied (rate limited)", tenant_id=tenant_id, max_concurrent=max_concurrent)
        return acquired
    except redis.RedisError as e:
        # Fail open — allow the task if Redis is down
        logger.warn("Redis unavailable, failing open", error=str(e))
        return True


def release_lease(tenant_id: str, task_id: str) -> None:
    """Release a lease. Idempotent — safe to call multiple times."""
    try:
        r = _get_redis()
        _ensure_scripts(r)
        lease_key = _lease_key(tenant_id, task_id)
        active_key = _active_set_key(tenant_id)
        r.evalsha(_release_sha, 2, lease_key, active_key, task_id)
        logger.info("Lease released", tenant_id=tenant_id, task_id=task_id)
    except redis.RedisError as e:
        logger.warn("Redis unavailable on release", error=str(e))


def heartbeat_lease(tenant_id: str, task_id: str, ttl: int = 60) -> None:
    """Extend lease TTL. Call every ~20 seconds during long-running tasks."""
    try:
        r = _get_redis()
        lease_key = _lease_key(tenant_id, task_id)
        r.expire(lease_key, ttl)
    except redis.RedisError as e:
        logger.warn("Lease heartbeat failed", error=str(e))


def get_active_count(tenant_id: str) -> int:
    """Get the number of active leases for a tenant."""
    try:
        r = _get_redis()
        return r.scard(_active_set_key(tenant_id))
    except redis.RedisError as e:
        logger.warn("Active count failed", error=str(e))
        return 0


# TODO: For >100 concurrent tasks per tenant, migrate from SET to sorted sets
# with score=expiry_timestamp for O(log N) cleanup of expired leases.
