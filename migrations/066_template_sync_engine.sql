-- Migration 066: Template Sync Engine + Intelligence Layer
-- Date: 2026-04-06
-- PRD: v4 Sprint A
--
-- ADDITIVE ONLY — no ALTER on existing tables.
-- v3.2.1 code ignores new tables safely.
-- Rollback: DROP TABLE IF EXISTS ... CASCADE (reverse order)

BEGIN;

-- ==========================================
-- BUNDLE SYSTEM (instance-scoped)
-- ==========================================

-- Extension metadata for agent_skills (not ALTER)
CREATE TABLE IF NOT EXISTS agent_skills_metadata (
    skill_id UUID PRIMARY KEY REFERENCES agent_skills(id) ON DELETE CASCADE,
    tier VARCHAR(20) DEFAULT 'community'
        CHECK (tier IN ('community', 'premium')),
    bundle_id VARCHAR(100),
    bundle_version VARCHAR(20),
    autoresearch_validated BOOLEAN DEFAULT false,
    upstream_version VARCHAR(20),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Dynamic investigation plans — INSTANCE-SCOPED (no tenant_id)
CREATE TABLE IF NOT EXISTS investigation_plans_db (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_key VARCHAR(100) NOT NULL,
    tier VARCHAR(20) DEFAULT 'community'
        CHECK (tier IN ('community', 'premium')),
    version VARCHAR(20) NOT NULL,
    bundle_id VARCHAR(100),
    bundle_sequence INTEGER NOT NULL DEFAULT 0,
    plan_data JSONB NOT NULL,
    active BOOLEAN DEFAULT true,
    replaces VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(plan_key, version)
);

CREATE INDEX IF NOT EXISTS idx_plans_db_active
    ON investigation_plans_db(plan_key) WHERE active = true;

-- Installed bundles — INSTANCE-SCOPED
CREATE TABLE IF NOT EXISTS installed_bundles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_id VARCHAR(100) UNIQUE NOT NULL,
    sequence_number INTEGER NOT NULL,
    tier VARCHAR(20) NOT NULL
        CHECK (tier IN ('community', 'premium')),
    installed_at TIMESTAMPTZ DEFAULT NOW(),
    installed_by VARCHAR(100),
    changelog TEXT,
    contents_summary JSONB,
    rollback_snapshot JSONB,
    rolled_back BOOLEAN DEFAULT false,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_installed_bundles_seq
    ON installed_bundles(sequence_number DESC);

-- Risk calibration anchors — INSTANCE-SCOPED
CREATE TABLE IF NOT EXISTS risk_calibration_anchors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    risk INTEGER NOT NULL CHECK (risk >= 0 AND risk <= 100),
    bundle_id VARCHAR(100),
    bundle_sequence INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(attack_type, description)
);

-- Revocation list — INSTANCE-SCOPED
CREATE TABLE IF NOT EXISTS revoked_bundles (
    bundle_id VARCHAR(100) PRIMARY KEY,
    revoked_at TIMESTAMPTZ DEFAULT NOW(),
    reason TEXT
);

-- Detection tools — versioned, conflict-safe, INSTANCE-SCOPED
CREATE TABLE IF NOT EXISTS bundle_detection_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    version VARCHAR(20) NOT NULL,
    tier VARCHAR(20) DEFAULT 'community'
        CHECK (tier IN ('community', 'premium')),
    bundle_id VARCHAR(100),
    bundle_sequence INTEGER NOT NULL DEFAULT 0,
    function_code TEXT NOT NULL,
    risk_weights JSONB,
    test_cases JSONB,
    sast_passed BOOLEAN DEFAULT false,
    sast_report JSONB,
    active BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(name, version)
);

-- ==========================================
-- INTELLIGENCE LAYER (tenant-scoped)
-- ==========================================

-- Attack paths — correlations across investigations
CREATE TABLE IF NOT EXISTS attack_paths (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    path_id VARCHAR(100) UNIQUE NOT NULL,
    chain_type VARCHAR(50) NOT NULL,
    confidence FLOAT NOT NULL DEFAULT 0.0,
    investigations UUID[] NOT NULL,
    mitre_chain TEXT[],
    composite_risk INTEGER NOT NULL,
    time_span_hours FLOAT,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'active'
        CHECK (status IN ('active', 'contained',
                          'resolved', 'false_positive')),
    containment_action TEXT,
    requires_analyst_review BOOLEAN DEFAULT true,
    correlation_rule VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_attack_paths_tenant
    ON attack_paths(tenant_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_active
    ON attack_paths(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_attack_paths_risk
    ON attack_paths(composite_risk DESC);

-- Attack path dead letter queue
CREATE TABLE IF NOT EXISTS attack_path_dlq (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL,
    error_message TEXT NOT NULL,
    error_type VARCHAR(100),
    retry_count INTEGER DEFAULT 0,
    resolved BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_dlq_unresolved
    ON attack_path_dlq(resolved) WHERE resolved = false;

-- Asset registry
CREATE TABLE IF NOT EXISTS asset_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier VARCHAR(255) NOT NULL,
    identifier_type VARCHAR(50) NOT NULL
        CHECK (identifier_type IN
            ('host', 'ip', 'user', 'service', 'subnet')),
    criticality INTEGER DEFAULT 50
        CHECK (criticality >= 0 AND criticality <= 100),
    exposure VARCHAR(20) DEFAULT 'internal'
        CHECK (exposure IN
            ('external', 'dmz', 'internal', 'isolated')),
    privilege_level VARCHAR(20) DEFAULT 'standard'
        CHECK (privilege_level IN
            ('system', 'admin', 'privileged', 'standard', 'service')),
    tags JSONB DEFAULT '[]',
    notes TEXT,
    occurrence_count INTEGER DEFAULT 0,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(identifier, identifier_type, tenant_id)
);

-- Asset occurrences — PARTITIONED by month, 90-day TTL
CREATE TABLE IF NOT EXISTS asset_occurrences (
    identifier VARCHAR(255) NOT NULL,
    identifier_type VARCHAR(50) NOT NULL,
    occurrence_count INTEGER DEFAULT 1,
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    attack_types TEXT[] DEFAULT '{}',
    tenant_id UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (identifier, identifier_type,
                 tenant_id, created_at)
) PARTITION BY RANGE (created_at);

-- Create partitions for the next 3 months
CREATE TABLE IF NOT EXISTS asset_occurrences_2026_04
    PARTITION OF asset_occurrences
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE IF NOT EXISTS asset_occurrences_2026_05
    PARTITION OF asset_occurrences
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS asset_occurrences_2026_06
    PARTITION OF asset_occurrences
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

-- Remediation tracking
CREATE TABLE IF NOT EXISTS remediation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES agent_tasks(id),
    attack_path_id UUID REFERENCES attack_paths(id),
    action_type VARCHAR(50) NOT NULL
        CHECK (action_type IN (
            'patch', 'config_change', 'access_revoke',
            'rule_update', 'block', 'isolate',
            'investigate_further', 'accept_risk',
            'false_positive')),
    description TEXT NOT NULL,
    assigned_to VARCHAR(255),
    status VARCHAR(20) DEFAULT 'open'
        CHECK (status IN ('open', 'in_progress', 'completed',
            'verified', 'failed', 'wont_fix')),
    priority INTEGER DEFAULT 50,
    verification_attempts INTEGER DEFAULT 0,
    last_verification_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    verification_method VARCHAR(50),
    verification_result JSONB,
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_remediation_tenant
    ON remediation_actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_remediation_status
    ON remediation_actions(status) WHERE status IN ('open', 'in_progress');

-- ==========================================
-- RLS POLICIES for new tenant-scoped tables
-- ==========================================

ALTER TABLE attack_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_path_dlq ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_actions ENABLE ROW LEVEL SECURITY;

-- Policies for zovark_app user
DO $$
BEGIN
    -- attack_paths
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'attack_paths' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON attack_paths
            USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
    END IF;

    -- attack_path_dlq
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'attack_path_dlq' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON attack_path_dlq
            USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
    END IF;

    -- asset_registry
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'asset_registry' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON asset_registry
            USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
    END IF;

    -- remediation_actions
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'remediation_actions' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON remediation_actions
            USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
    END IF;
END $$;

-- Force RLS for zovark_app
ALTER TABLE attack_paths FORCE ROW LEVEL SECURITY;
ALTER TABLE attack_path_dlq FORCE ROW LEVEL SECURITY;
ALTER TABLE asset_registry FORCE ROW LEVEL SECURITY;
ALTER TABLE remediation_actions FORCE ROW LEVEL SECURITY;

-- Grant permissions to zovark_app (from migration 065 default privileges,
-- but explicit for safety)
GRANT SELECT, INSERT, UPDATE, DELETE ON attack_paths TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON attack_path_dlq TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON asset_registry TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON asset_occurrences TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_actions TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_skills_metadata TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON investigation_plans_db TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON installed_bundles TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON risk_calibration_anchors TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON revoked_bundles TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON bundle_detection_tools TO zovark_app;

COMMIT;
