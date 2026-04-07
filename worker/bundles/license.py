"""
License enforcement — Ed25519 signature verification.
Fail-closed: any error → DENY premium access (Invariant #6).
Grace period: 30 days (encoded in signed payload, NOT configurable by admin).
"""
import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_DB_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark",
)

# Cache: (tenant_id -> (LicenseResult, expire_time))
_cache: dict[str, tuple["LicenseResult", float]] = {}
_CACHE_TTL = 300  # 5 minutes


@dataclass
class LicenseResult:
    status: str  # VALID, GRACE, EXPIRED, DENIED
    tier: str  # community, professional, enterprise
    features: list[str] = field(default_factory=list)
    days_remaining: int = 0
    message: str = ""


_DENIED = LicenseResult(status="DENIED", tier="community", features=[], days_remaining=0, message="No valid license")
_COMMUNITY = LicenseResult(status="VALID", tier="community", features=[], days_remaining=0, message="Community tier (no license)")


def _get_conn():
    import psycopg2
    return psycopg2.connect(_DB_URL)


def verify_license(payload_json: str, public_key_b64: str) -> LicenseResult:
    """Verify Ed25519 signature on license payload. Returns DENIED on ANY error."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        payload = json.loads(payload_json)

        # Extract and remove signature for verification
        signature_b64 = payload.pop("signature", None)
        if not signature_b64:
            return LicenseResult(status="DENIED", tier="community", message="Missing signature")

        # Deterministic serialization (sorted keys, no whitespace)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        # Verify signature
        public_key_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        signature = base64.b64decode(signature_b64)

        try:
            public_key.verify(signature, canonical.encode("utf-8"))
        except InvalidSignature:
            return LicenseResult(status="DENIED", tier="community", message="Invalid signature")

        # Check expiry
        expires_at = payload.get("expires_at", "")
        grace_days = payload.get("grace_days", 30)
        tier = payload.get("tier", "community")
        features = payload.get("features", [])

        try:
            expires = datetime.fromisoformat(expires_at)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return LicenseResult(status="DENIED", tier="community", message="Invalid expires_at")

        now = datetime.now(timezone.utc)
        days_remaining = (expires - now).days

        if days_remaining >= 0:
            return LicenseResult(
                status="VALID", tier=tier, features=features,
                days_remaining=days_remaining, message="License valid",
            )

        # Check grace period
        grace_remaining = days_remaining + grace_days
        if grace_remaining >= 0:
            return LicenseResult(
                status="GRACE", tier=tier, features=features,
                days_remaining=grace_remaining,
                message=f"License expired, grace period: {grace_remaining} days remaining",
            )

        return LicenseResult(
            status="EXPIRED", tier="community", features=[],
            days_remaining=0, message="License expired beyond grace period",
        )

    except Exception as e:
        logger.warning("License verification failed: %s", e)
        return LicenseResult(status="DENIED", tier="community", message=str(e))


def get_current_license(tenant_id: str) -> LicenseResult:
    """Read license from system_configs. Cached for 5 minutes. Fail-closed."""
    try:
        # Check cache
        now = time.time()
        if tenant_id in _cache:
            cached, expire_at = _cache[tenant_id]
            if now < expire_at:
                return cached

        # Query DB
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT config_key, config_value FROM system_configs
                    WHERE tenant_id = %s AND config_key IN ('license.public_key', 'license.payload')
                """, (tenant_id,))
                rows = {r[0]: r[1] for r in cur.fetchall()}
        finally:
            conn.close()

        public_key = rows.get("license.public_key", "")
        payload = rows.get("license.payload", "")

        if not public_key or not payload:
            result = _COMMUNITY
        else:
            result = verify_license(payload, public_key)

        # Cache
        _cache[tenant_id] = (result, now + _CACHE_TTL)
        return result

    except Exception as e:
        logger.warning("License check failed (fail-closed): %s", e)
        return _DENIED


def check_feature(tenant_id: str, feature: str) -> bool:
    """Check if a feature is available under the current license."""
    try:
        result = get_current_license(tenant_id)
        if result.status in ("VALID", "GRACE"):
            return feature in result.features
        return False
    except Exception:
        return False


def invalidate_cache(tenant_id: str) -> None:
    """Clear cached license for a tenant (after install/update)."""
    _cache.pop(tenant_id, None)
