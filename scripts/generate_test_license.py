#!/usr/bin/env python3
"""Generate a test license for development. NOT for production use."""
import base64
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TENANT_ID = "e1c1bc5d-576f-4613-b6c3-99952b37b3ce"  # Dev admin tenant
DB_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")


def main():
    # Generate keypair
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()

    # Build payload
    payload = {
        "tenant_id": TENANT_ID,
        "tier": "enterprise",
        "features": [
            "advanced_plans", "copilot", "bundles", "custom_detection",
            "multi_model", "siem_connectors", "priority_support",
        ],
        "expires_at": "2027-01-01T00:00:00Z",
        "grace_days": 30,
        "issued_at": "2026-04-07T00:00:00Z",
    }

    # Sign (canonical serialization: sorted keys, no whitespace)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = private_key.sign(canonical.encode("utf-8"))
    payload["signature"] = base64.b64encode(signature).decode()

    payload_json = json.dumps(payload)

    print(f"Public key (base64): {public_key_b64}")
    print(f"Payload: {payload_json[:100]}...")

    # Insert into DB
    import psycopg2
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE system_configs SET config_value = %s
                WHERE tenant_id = %s AND config_key = 'license.public_key'
            """, (public_key_b64, TENANT_ID))
            cur.execute("""
                UPDATE system_configs SET config_value = %s
                WHERE tenant_id = %s AND config_key = 'license.payload'
            """, (payload_json, TENANT_ID))
            conn.commit()
            print(f"License installed for tenant {TENANT_ID}")
            print(f"Tier: enterprise, expires: 2027-01-01, features: {len(payload['features'])}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
