"""Valkey client wrapper.

Note: uses the redis-py library because Valkey is wire-compatible
with Redis. No valkey-py library exists yet — redis-py is the
de-facto Valkey client.
"""
import os
import redis  # redis-py works with Valkey unmodified

_valkey_conn = None


def _get_valkey():
    global _valkey_conn
    if _valkey_conn is None:
        # Prefer VALKEY_URL, fall back to REDIS_URL for legacy compat
        url = os.environ.get("VALKEY_URL") or os.environ.get(
            "REDIS_URL", "redis://valkey:6379/0"
        )
        _valkey_conn = redis.from_url(url, decode_responses=True)
    return _valkey_conn


# Backwards-compat alias
_get_redis = _get_valkey


def get_active_count(tenant_id: str) -> int:
    r = _get_valkey()
    val = r.get(f"zovark:active:{tenant_id}")
    return int(val) if val else 0


def increment_active(tenant_id: str) -> int:
    r = _get_valkey()
    key = f"zovark:active:{tenant_id}"
    val = r.incr(key)
    r.expire(key, 3600)  # 1 hour TTL safety net
    return val


def decrement_active(tenant_id: str) -> int:
    r = _get_valkey()
    key = f"zovark:active:{tenant_id}"
    val = r.decr(key)
    if val < 0:
        r.set(key, 0)
        r.expire(key, 3600)
        return 0
    return val


def check_rate_limit(tenant_id: str, max_concurrent: int) -> bool:
    """Returns True if under limit, False if over."""
    r = _get_valkey()
    key = f"zovark:active:{tenant_id}"
    val = r.incr(key)
    r.expire(key, 3600)
    if val > max_concurrent:
        r.decr(key)
        return False
    return True
