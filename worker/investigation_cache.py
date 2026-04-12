"""Investigation result cache — skip re-investigation for identical indicators.

SHA-256 hash of normalized, sorted indicators -> cached verdict + report.
Severity-based TTL: critical=1hr, high=4hr, medium=24hr, low=48hr.

Enhanced (Issue #38):
- Redis-based caching layer (check Redis before DB)
- Semantic dedup: if new alert embedding >0.95 similar to cached, return cached
- TTL management by severity
"""

import hashlib
import json
import os
import re
import psycopg2


# Severity-based TTL in hours
SEVERITY_TTL = {
    "critical": 1,
    "high": 4,
    "medium": 24,
    "low": 48,
    "informational": 48,
}

# Semantic dedup similarity threshold
SEMANTIC_DEDUP_THRESHOLD = 0.95

# Redis config
REDIS_URL = os.environ.get("REDIS_URL", "redis://:hydra-redis-dev-2026@redis:6379/0")  # FIX #16
REDIS_CACHE_PREFIX = "zovark:inv_cache:"
REDIS_CACHE_TTL = 3600  # 1 hour default Redis TTL (seconds)


def _get_redis():
    """Get Redis connection. Returns None if Redis unavailable."""
    try:
        import redis
        return redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        return None


def _normalize_indicators(indicators):
    """Extract and normalize IOCs from input dict."""
    iocs = set()
    text = json.dumps(indicators) if isinstance(indicators, dict) else str(indicators)

    # IPs
    for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text):
        if not ip.startswith(('0.', '127.', '255.')):
            iocs.add(f"ip:{ip}")

    # Domains
    for d in re.findall(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b', text):
        d_lower = d.lower()
        if d_lower not in ('example.com', 'localhost.localdomain'):
            iocs.add(f"domain:{d_lower}")

    # SHA256 hashes
    for h in re.findall(r'\b[a-fA-F0-9]{64}\b', text):
        iocs.add(f"sha256:{h.lower()}")

    # MD5 hashes
    for h in re.findall(r'\b[a-fA-F0-9]{32}\b', text):
        iocs.add(f"md5:{h.lower()}")

    return sorted(iocs)


def compute_cache_key(task_input, tenant_id=None):
    """Compute SHA-256 cache key from normalized indicators, scoped by tenant.

    Tenant isolation: cache keys include tenant_id to prevent cross-tenant
    cache poisoning (Security P0#7).
    """
    indicators = _normalize_indicators(task_input)
    if not indicators:
        return None
    key_data = {"tenant_id": tenant_id, "indicators": indicators} if tenant_id else {"indicators": indicators}
    payload = json.dumps(key_data, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def get_ttl_for_severity(severity):
    """Get TTL in hours based on severity level."""
    return SEVERITY_TTL.get(severity, 24)


def _check_redis(cache_key):
    """Check Redis cache layer first. Returns dict or None."""
    try:
        r = _get_redis()
        if r is None:
            return None

        cached = r.get(f"{REDIS_CACHE_PREFIX}{cache_key}")
        if cached:
            result = json.loads(cached)
            result['cache_hit'] = True
            result['cache_source'] = 'redis'
            return result
    except Exception as e:
        print(f"investigation_cache: Redis check failed (non-fatal): {e}")
    return None


def _store_redis(cache_key, data, ttl_hours=24):
    """Store in Redis cache layer. Fire-and-forget."""
    try:
        r = _get_redis()
        if r is None:
            return

        ttl_seconds = ttl_hours * 3600
        r.setex(
            f"{REDIS_CACHE_PREFIX}{cache_key}",
            ttl_seconds,
            json.dumps(data),
        )
    except Exception as e:
        print(f"investigation_cache: Redis store failed (non-fatal): {e}")


def check_cache(task_input, tenant_id=None):
    """Check if a cached result exists for these indicators.

    Checks Redis first, then falls back to PostgreSQL.
    Scoped by tenant_id for isolation (Security P0#7).
    Returns dict with cached result or None.
    """
    cache_key = compute_cache_key(task_input, tenant_id=tenant_id)
    if not cache_key:
        return None

    # Layer 1: Check Redis
    redis_hit = _check_redis(cache_key)
    if redis_hit:
        return redis_hit

    # Layer 2: Check PostgreSQL
    try:
        db_url = os.environ.get(
            "DATABASE_URL",
            "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark"
        )
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT investigation_id, task_id, verdict, risk_score,
                           confidence, entity_count, summary, ttl_hours
                    FROM investigation_cache
                    WHERE cache_key = %s AND expires_at > NOW()
                    LIMIT 1
                """, (cache_key,))
                row = cur.fetchone()
                if row:
                    result = {
                        'cache_hit': True,
                        'cache_source': 'postgres',
                        'cache_key': cache_key,
                        'investigation_id': str(row[0]),
                        'task_id': str(row[1]) if row[1] else None,
                        'verdict': row[2],
                        'risk_score': row[3],
                        'confidence': row[4],
                        'entity_count': row[5],
                        'summary': row[6],
                    }
                    # Backfill Redis for next time
                    ttl_hours = row[7] if row[7] else 24
                    _store_redis(cache_key, result, ttl_hours)
                    return result
        finally:
            conn.close()
    except Exception as e:
        print(f"investigation_cache: check failed (non-fatal): {e}")

    return None


def check_semantic_dedup(embedding, severity=None, tenant_id=None):
    """Check if a semantically similar investigation is cached.

    Uses pgvector cosine similarity to find cached results with
    embedding similarity > SEMANTIC_DEDUP_THRESHOLD (0.95).
    Scoped by tenant_id for isolation (Security P0#7).

    Args:
        embedding: List of floats (embedding vector)
        severity: Severity level for TTL lookup
        tenant_id: Tenant UUID for isolation

    Returns:
        Dict with cached result or None.
    """
    if not embedding:
        return None

    try:
        db_url = os.environ.get(
            "DATABASE_URL",
            "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark"
        )
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                # Find investigations with high embedding similarity (tenant-scoped)
                threshold_distance = 1.0 - SEMANTIC_DEDUP_THRESHOLD  # cosine distance
                query = """
                    SELECT
                        ic.investigation_id, ic.task_id, ic.verdict,
                        ic.risk_score, ic.confidence, ic.entity_count,
                        ic.summary, ic.cache_key,
                        1.0 - (i.embedding <-> %s::vector) as similarity
                    FROM investigation_cache ic
                    JOIN investigations i ON i.id = ic.investigation_id
                    WHERE ic.expires_at > NOW()
                      AND i.embedding IS NOT NULL
                      AND i.embedding <-> %s::vector < %s
                """
                params = [str(embedding), str(embedding), threshold_distance]
                if tenant_id:
                    query += " AND i.tenant_id = %s"
                    params.append(tenant_id)
                query += " ORDER BY i.embedding <-> %s::vector LIMIT 1"
                params.append(str(embedding))
                cur.execute(query, tuple(params))
                row = cur.fetchone()
                if row:
                    return {
                        'cache_hit': True,
                        'cache_source': 'semantic_dedup',
                        'investigation_id': str(row[0]),
                        'task_id': str(row[1]) if row[1] else None,
                        'verdict': row[2],
                        'risk_score': row[3],
                        'confidence': row[4],
                        'entity_count': row[5],
                        'summary': row[6],
                        'cache_key': row[7],
                        'similarity': round(float(row[8]), 4),
                    }
        finally:
            conn.close()
    except Exception as e:
        print(f"investigation_cache: semantic dedup failed (non-fatal): {e}")

    return None


def store_cache(task_input, investigation_id, task_id=None,
                verdict=None, risk_score=None, confidence=None,
                entity_count=None, summary=None, ttl_hours=None,
                severity=None, tenant_id=None):
    """Store investigation result in cache.

    TTL is determined by severity if provided, otherwise uses ttl_hours or default 24h.
    Stores in both Redis and PostgreSQL. Scoped by tenant_id (Security P0#7).
    """
    cache_key = compute_cache_key(task_input, tenant_id=tenant_id)
    if not cache_key:
        return

    # Determine TTL from severity
    if ttl_hours is None:
        ttl_hours = get_ttl_for_severity(severity) if severity else 24

    # Store in Redis (fast layer)
    redis_data = {
        'cache_key': cache_key,
        'investigation_id': str(investigation_id),
        'task_id': str(task_id) if task_id else None,
        'verdict': verdict,
        'risk_score': risk_score,
        'confidence': confidence,
        'entity_count': entity_count,
        'summary': summary,
    }
    _store_redis(cache_key, redis_data, ttl_hours)

    # Store in PostgreSQL (durable layer)
    try:
        db_url = os.environ.get(
            "DATABASE_URL",
            "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark"
        )
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO investigation_cache
                        (cache_key, investigation_id, task_id, verdict,
                         risk_score, confidence, entity_count, summary,
                         ttl_hours, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                            NOW() + make_interval(hours => %s))
                    ON CONFLICT (cache_key) DO UPDATE SET
                        investigation_id = EXCLUDED.investigation_id,
                        task_id = EXCLUDED.task_id,
                        verdict = EXCLUDED.verdict,
                        risk_score = EXCLUDED.risk_score,
                        confidence = EXCLUDED.confidence,
                        entity_count = EXCLUDED.entity_count,
                        summary = EXCLUDED.summary,
                        ttl_hours = EXCLUDED.ttl_hours,
                        expires_at = NOW() + make_interval(hours => EXCLUDED.ttl_hours),
                        created_at = NOW()
                """, (
                    cache_key, investigation_id, task_id, verdict,
                    risk_score, confidence, entity_count, summary,
                    ttl_hours, ttl_hours,
                ))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"investigation_cache: store failed (non-fatal): {e}")
