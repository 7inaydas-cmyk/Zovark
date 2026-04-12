"""PII detection and masking for LLM interactions.

Detects sensitive data using regex patterns. Masks PII before sending to
external LLMs, stores entity mapping for unmasking responses.

Tables used: pii_detections, pii_masking_rules
"""

import json
import os
import re
import uuid

import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity

import logger


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


def _get_redis():
    """Get Redis connection. Returns None if unavailable."""
    try:
        import redis
        url = os.environ.get("REDIS_URL", "redis://:hydra-redis-dev-2026@redis:6379/0")  # FIX #16
        return redis.from_url(url, decode_responses=True)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# PII Pattern Definitions
# ---------------------------------------------------------------------------

# Ordered by specificity: more specific patterns first to avoid false positives
PATTERNS = {
    "aws_key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
    "api_key": re.compile(r'\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9]{20,}\b', re.IGNORECASE),
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "ipv6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "phone": re.compile(r'\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b'),
    "hostname": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
}

# Internal/safe IPs that should not be masked
_SAFE_IP_PREFIXES = ("0.", "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                     "192.168.", "255.")

# Common hostnames to skip
_SAFE_HOSTNAMES = {"example.com", "localhost.localdomain", "localhost", "zovark.local"}

REDIS_PII_PREFIX = "zovark:pii_map:"
REDIS_PII_TTL = 3600  # 1 hour


# ---------------------------------------------------------------------------
# Core PIIDetector class
# ---------------------------------------------------------------------------

class PIIDetector:
    """Detect and mask PII using regex patterns."""

    def __init__(self, custom_rules=None):
        """Initialize with optional custom rules.

        Args:
            custom_rules: list of dicts with {pattern_name, regex, replacement_prefix}
        """
        self.patterns = dict(PATTERNS)
        self.custom_rules = custom_rules or []
        for rule in self.custom_rules:
            name = rule.get("pattern_name")
            regex = rule.get("regex")
            if name and regex:
                try:
                    self.patterns[name] = re.compile(regex)
                except re.error:
                    logger.warn("Invalid custom PII regex", pattern_name=name)

    def detect(self, text: str) -> list:
        """Detect PII in text.

        Returns:
            List of {type, start, end, value}
        """
        if not text:
            return []

        detections = []
        seen_spans = set()

        for pii_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                span = (match.start(), match.end())
                # Skip overlapping detections
                if any(s <= span[0] < e or s < span[1] <= e for s, e in seen_spans):
                    continue

                value = match.group()

                # Filter out safe IPs
                if pii_type == "ipv4" and any(value.startswith(p) for p in _SAFE_IP_PREFIXES):
                    continue

                # Filter out safe hostnames
                if pii_type == "hostname" and value.lower() in _SAFE_HOSTNAMES:
                    continue

                detections.append({
                    "type": pii_type,
                    "start": match.start(),
                    "end": match.end(),
                    "value": value,
                })
                seen_spans.add(span)

        # Sort by position
        detections.sort(key=lambda d: d["start"])
        return detections

    def mask(self, text: str, tenant_id: str) -> tuple:
        """Mask PII in text.

        Returns:
            (masked_text, entity_map) where entity_map maps token -> original value
        """
        detections = self.detect(text)
        if not detections:
            return text, {}

        entity_map = {}
        counters = {}
        # Process in reverse order to preserve positions
        masked_text = text
        for det in reversed(detections):
            pii_type = det["type"]
            counters[pii_type] = counters.get(pii_type, 0) + 1
            token = f"[{pii_type.upper()}_{counters[pii_type]}]"
            entity_map[token] = det["value"]
            masked_text = masked_text[:det["start"]] + token + masked_text[det["end"]:]

        return masked_text, entity_map

    def unmask(self, text: str, entity_map: dict) -> str:
        """Restore original PII values in text.

        Args:
            text: Text with masked tokens
            entity_map: Mapping of token -> original value
        Returns:
            Text with original values restored
        """
        if not entity_map:
            return text
        result = text
        for token, original in entity_map.items():
            result = result.replace(token, original)
        return result


# Module-level detector singleton
_default_detector = PIIDetector()


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------

@activity.defn
async def detect_pii(params: dict) -> dict:
    """Detect PII in text and log detections.

    Args:
        params: {text, tenant_id, field_path, direction}
    Returns:
        {found, detections, masked_text, entity_map_id}
    """
    text = params.get("text", "")
    tenant_id = params.get("tenant_id")
    field_path = params.get("field_path", "unknown")
    direction = params.get("direction", "outbound")

    # Load custom rules for tenant
    custom_rules = []
    try:
        conn = _get_db()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT pattern_name, regex, replacement_prefix
                    FROM pii_masking_rules
                    WHERE (tenant_id = %s OR tenant_id IS NULL) AND enabled = true
                    ORDER BY priority ASC
                """, (tenant_id,))
                custom_rules = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception as e:
        logger.warn("Failed to load PII rules", error=str(e))

    detector = PIIDetector(custom_rules=custom_rules) if custom_rules else _default_detector
    detections = detector.detect(text)
    masked_text, entity_map = detector.mask(text, tenant_id)

    entity_map_id = None
    if detections:
        entity_map_id = str(uuid.uuid4())

        # Store entity map in Redis
        r = _get_redis()
        if r:
            try:
                r.setex(
                    f"{REDIS_PII_PREFIX}{entity_map_id}",
                    REDIS_PII_TTL,
                    json.dumps(entity_map),
                )
            except Exception as e:
                logger.warn("Redis PII store failed", error=str(e))

        # Log detections to DB
        try:
            conn = _get_db()
            try:
                with conn.cursor() as cur:
                    for det in detections:
                        cur.execute("""
                            INSERT INTO pii_detections
                                (tenant_id, field_path, pii_type, direction, entity_map_id)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (tenant_id, field_path, det["type"], direction, entity_map_id))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.warn("PII detection logging failed", error=str(e))

    logger.info("PII detection complete",
                tenant_id=tenant_id, found=len(detections), direction=direction)

    return {
        "found": len(detections) > 0,
        "detections": [{"type": d["type"], "start": d["start"], "end": d["end"]} for d in detections],
        "masked_text": masked_text,
        "entity_map_id": entity_map_id,
    }


@activity.defn
async def mask_for_llm(params: dict) -> dict:
    """Mask PII before sending prompt to external LLM.

    Args:
        params: {prompt_text, tenant_id, task_id}
    Returns:
        {masked_text, entity_map_key, pii_count}
    """
    prompt_text = params.get("prompt_text", "")
    tenant_id = params.get("tenant_id")
    task_id = params.get("task_id")

    detector = _default_detector
    detections = detector.detect(prompt_text)
    masked_text, entity_map = detector.mask(prompt_text, tenant_id)

    entity_map_key = None
    if entity_map:
        entity_map_key = f"pii:{tenant_id}:{task_id}:{uuid.uuid4().hex[:8]}"
        r = _get_redis()
        if r:
            try:
                r.setex(
                    f"{REDIS_PII_PREFIX}{entity_map_key}",
                    REDIS_PII_TTL,
                    json.dumps(entity_map),
                )
            except Exception as e:
                logger.warn("Redis PII map store failed", error=str(e))

    logger.info("PII masking for LLM",
                tenant_id=tenant_id, task_id=task_id, pii_count=len(detections))

    return {
        "masked_text": masked_text,
        "entity_map_key": entity_map_key,
        "pii_count": len(detections),
    }


@activity.defn
async def unmask_response(params: dict) -> str:
    """Unmask PII in LLM response using stored entity map.

    Args:
        params: {response_text, entity_map_key}
    Returns:
        Unmasked text string
    """
    response_text = params.get("response_text", "")
    entity_map_key = params.get("entity_map_key")

    if not entity_map_key:
        return response_text

    entity_map = {}
    r = _get_redis()
    if r:
        try:
            raw = r.get(f"{REDIS_PII_PREFIX}{entity_map_key}")
            if raw:
                entity_map = json.loads(raw)
        except Exception as e:
            logger.warn("Redis PII map fetch failed", error=str(e))

    if not entity_map:
        logger.warn("No entity map found for unmasking", key=entity_map_key)
        return response_text

    result = _default_detector.unmask(response_text, entity_map)
    return result


@activity.defn
async def load_tenant_pii_rules(tenant_id: str) -> list:
    """Load custom PII masking rules for a tenant.

    Args:
        tenant_id: Tenant UUID
    Returns:
        List of rule dicts {pattern_name, regex, replacement_prefix, enabled, priority}
    """
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT pattern_name, regex, replacement_prefix, enabled, priority
                FROM pii_masking_rules
                WHERE (tenant_id = %s OR tenant_id IS NULL) AND enabled = true
                ORDER BY priority ASC
            """, (tenant_id,))
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    finally:
        conn.close()
