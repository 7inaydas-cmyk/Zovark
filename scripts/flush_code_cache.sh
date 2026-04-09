#!/bin/bash
set -e
REDIS_PASS="${REDIS_PASSWORD:-zovark_valkey_dev_2026}"
echo "Flushing Zovark code cache..."
COUNT=$(docker compose exec -T valkey valkey-cli -a "$REDIS_PASS" --no-auth-warning \
  EVAL "local keys = redis.call('keys', 'zovark:code_cache:*'); for _,k in ipairs(keys) do redis.call('del', k) end; return #keys" 0 2>/dev/null)
echo "Flushed ${COUNT:-0} cached entries."
