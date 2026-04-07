-- Migration 068: License system configs (Sprint C3)
-- Additive only (Invariant #5)

-- Add license config entries for all tenants
INSERT INTO system_configs (tenant_id, config_key, config_value, is_secret, description)
SELECT t.id, 'license.public_key', '', false, 'Ed25519 public key for license verification (base64)'
FROM tenants t
WHERE NOT EXISTS (
    SELECT 1 FROM system_configs sc
    WHERE sc.tenant_id = t.id AND sc.config_key = 'license.public_key'
);

INSERT INTO system_configs (tenant_id, config_key, config_value, is_secret, description)
SELECT t.id, 'license.payload', '', false, 'Signed license payload (JSON)'
FROM tenants t
WHERE NOT EXISTS (
    SELECT 1 FROM system_configs sc
    WHERE sc.tenant_id = t.id AND sc.config_key = 'license.payload'
);
