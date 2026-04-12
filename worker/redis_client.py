import os
import redis

_redis_conn = None


def _get_redis():
    global _redis_conn
    if _redis_conn is None:
        url = os.environ.get("REDIS_URL", "redis://:hydra-redis-dev-2026@redis:6379/0")  # FIX #16
        _redis_conn = redis.from_url(url, decode_responses=True)
    return _redis_conn


def get_active_count(tenant_id: str) -> int:
    r = _get_redis()
    val = r.get(f"zovark:active:{tenant_id}")
    return int(val) if val else 0


def increment_active(tenant_id: str) -> int:
    r = _get_redis()
    key = f"zovark:active:{tenant_id}"
    val = r.incr(key)
    r.expire(key, 3600)  # 1 hour TTL safety net
    return val


def decrement_active(tenant_id: str) -> int:
    r = _get_redis()
    key = f"zovark:active:{tenant_id}"
    val = r.decr(key)
    if val < 0:
        r.set(key, 0)
        r.expire(key, 3600)
        return 0
    return val


def check_rate_limit(tenant_id: str, max_concurrent: int) -> bool:
    """Returns True if under limit, False if over."""
    r = _get_redis()
    key = f"zovark:active:{tenant_id}"
    val = r.incr(key)
    r.expire(key, 3600)
    if val > max_concurrent:
        r.decr(key)
        return False
    return True
