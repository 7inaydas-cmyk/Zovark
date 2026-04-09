"""DEPRECATED: use valkey_client instead.

This shim re-exports from valkey_client so legacy `from redis_client
import ...` still works without breaking anything.
"""
from valkey_client import (  # noqa: F401
    _get_valkey as _get_redis,
    get_active_count,
    increment_active,
    decrement_active,
    check_rate_limit,
)
