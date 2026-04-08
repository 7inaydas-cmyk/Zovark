-- Migration 069: Cross-tenant entities + entity graph indexes
-- Additive-only (safe rollback)

-- cross_tenant_entities: privacy-preserving intelligence sharing
-- NO tenant_id column — all tenants read the same shared data
-- NO RLS — intentionally shared across tenants
CREATE TABLE IF NOT EXISTS cross_tenant_entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_hash VARCHAR(64) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    sighting_count INTEGER NOT NULL DEFAULT 1,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    avg_confidence REAL NOT NULL DEFAULT 0.5,
    avg_risk_score REAL DEFAULT NULL,
    malicious_count INTEGER NOT NULL DEFAULT 0,
    benign_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(entity_hash)
);

CREATE INDEX IF NOT EXISTS idx_cross_tenant_hash ON cross_tenant_entities(entity_hash);
CREATE INDEX IF NOT EXISTS idx_cross_tenant_type ON cross_tenant_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_cross_tenant_last_seen ON cross_tenant_entities(last_seen DESC);

-- Add missing columns to entities if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'entities' AND column_name = 'seen_count') THEN
        ALTER TABLE entities ADD COLUMN seen_count INTEGER NOT NULL DEFAULT 1;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'entities' AND column_name = 'confidence') THEN
        ALTER TABLE entities ADD COLUMN confidence REAL NOT NULL DEFAULT 0.5;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'entities' AND column_name = 'source_investigation_id') THEN
        ALTER TABLE entities ADD COLUMN source_investigation_id UUID;
    END IF;
END$$;

-- Add missing columns to entity_edges if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'entity_edges' AND column_name = 'weight') THEN
        ALTER TABLE entity_edges ADD COLUMN weight INTEGER NOT NULL DEFAULT 1;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'entity_edges' AND column_name = 'first_seen') THEN
        ALTER TABLE entity_edges ADD COLUMN first_seen TIMESTAMPTZ NOT NULL DEFAULT now();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'entity_edges' AND column_name = 'last_seen') THEN
        ALTER TABLE entity_edges ADD COLUMN last_seen TIMESTAMPTZ NOT NULL DEFAULT now();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'entity_edges' AND column_name = 'evidence') THEN
        ALTER TABLE entity_edges ADD COLUMN evidence JSONB DEFAULT '[]';
    END IF;
END$$;

-- Add entity_edges tenant index for graph queries
CREATE INDEX IF NOT EXISTS idx_entity_edges_tenant_type ON entity_edges(tenant_id, edge_type);

-- GRANT to zovark_app user
GRANT SELECT, INSERT, UPDATE ON cross_tenant_entities TO zovark_app;
