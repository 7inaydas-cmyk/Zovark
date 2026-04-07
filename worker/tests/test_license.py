"""
Tests for license enforcement (Sprint C3).
Tests Ed25519 verification, expiry, grace period, fail-closed.
"""
import base64
import json
import pytest
from datetime import datetime, timezone, timedelta


def _generate_keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    return private, base64.b64encode(public.public_bytes_raw()).decode()


def _sign_payload(payload: dict, private_key) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = private_key.sign(canonical.encode("utf-8"))
    return base64.b64encode(sig).decode()


class TestVerifyLicense:
    def test_valid_license_passes(self):
        from worker.bundles.license import verify_license

        private, pub_b64 = _generate_keypair()
        payload = {
            "tenant_id": "test-tenant",
            "tier": "enterprise",
            "features": ["copilot", "bundles"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "grace_days": 30,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        payload["signature"] = _sign_payload(payload, private)

        result = verify_license(json.dumps(payload), pub_b64)
        assert result.status == "VALID"
        assert result.tier == "enterprise"
        assert "copilot" in result.features
        assert result.days_remaining > 300

    def test_expired_license_rejected(self):
        from worker.bundles.license import verify_license

        private, pub_b64 = _generate_keypair()
        payload = {
            "tenant_id": "test-tenant",
            "tier": "professional",
            "features": ["bundles"],
            "expires_at": (datetime.now(timezone.utc) - timedelta(days=60)).isoformat(),
            "grace_days": 30,
            "issued_at": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
        }
        payload["signature"] = _sign_payload(payload, private)

        result = verify_license(json.dumps(payload), pub_b64)
        assert result.status == "EXPIRED"

    def test_grace_period(self):
        from worker.bundles.license import verify_license

        private, pub_b64 = _generate_keypair()
        payload = {
            "tenant_id": "test-tenant",
            "tier": "enterprise",
            "features": ["copilot"],
            "expires_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
            "grace_days": 30,
            "issued_at": (datetime.now(timezone.utc) - timedelta(days=375)).isoformat(),
        }
        payload["signature"] = _sign_payload(payload, private)

        result = verify_license(json.dumps(payload), pub_b64)
        assert result.status == "GRACE"
        assert result.days_remaining >= 19
        assert "copilot" in result.features

    def test_invalid_signature_denied(self):
        from worker.bundles.license import verify_license

        private, pub_b64 = _generate_keypair()
        payload = {
            "tenant_id": "test-tenant",
            "tier": "enterprise",
            "features": [],
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "grace_days": 30,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        payload["signature"] = _sign_payload(payload, private)

        # Tamper with payload
        tampered = json.loads(json.dumps(payload))
        tampered["tier"] = "community"
        result = verify_license(json.dumps(tampered), pub_b64)
        assert result.status == "DENIED"

    def test_missing_signature_denied(self):
        from worker.bundles.license import verify_license

        _, pub_b64 = _generate_keypair()
        payload = {"tenant_id": "test", "tier": "enterprise"}
        result = verify_license(json.dumps(payload), pub_b64)
        assert result.status == "DENIED"

    def test_invalid_json_denied(self):
        from worker.bundles.license import verify_license

        _, pub_b64 = _generate_keypair()
        result = verify_license("not json", pub_b64)
        assert result.status == "DENIED"

    def test_empty_public_key_denied(self):
        from worker.bundles.license import verify_license

        payload = json.dumps({"signature": "abc"})
        result = verify_license(payload, "")
        assert result.status == "DENIED"


class TestFeatureCheck:
    def test_community_has_no_premium_features(self):
        from worker.bundles.license import LicenseResult

        result = LicenseResult(status="VALID", tier="community", features=[])
        assert "copilot" not in result.features
        assert "bundles" not in result.features

    def test_enterprise_has_all_features(self):
        from worker.bundles.license import LicenseResult

        result = LicenseResult(
            status="VALID", tier="enterprise",
            features=["copilot", "bundles", "advanced_plans"],
        )
        assert "copilot" in result.features
        assert "bundles" in result.features

    def test_denied_status_no_features(self):
        from worker.bundles.license import _DENIED

        assert _DENIED.status == "DENIED"
        assert _DENIED.features == []
        assert _DENIED.tier == "community"


class TestCacheInvalidation:
    def test_invalidate_removes_entry(self):
        from worker.bundles.license import _cache, invalidate_cache, LicenseResult
        import time

        _cache["test-tenant"] = (
            LicenseResult(status="VALID", tier="enterprise"),
            time.time() + 300,
        )
        assert "test-tenant" in _cache
        invalidate_cache("test-tenant")
        assert "test-tenant" not in _cache
