-- Migration 067 (renumbered from 051 to resolve prefix conflict)
-- Sprint 1H: Bootstrap Pipeline enhancements
-- Adds detection_hints + last_synced to mitre_techniques,
-- creates dedicated kev_catalog table for CISA KEV entries.

-- Add missing columns to mitre_techniques (idempotent)
ALTER TABLE mitre_techniques ADD COLUMN IF NOT EXISTS detection_hints TEXT;
ALTER TABLE mitre_techniques ADD COLUMN IF NOT EXISTS last_synced TIMESTAMPTZ DEFAULT NOW();

-- Dedicated CISA KEV catalog (normalized, separate from bootstrap_corpus)
CREATE TABLE IF NOT EXISTS kev_catalog (
    cve_id VARCHAR(20) PRIMARY KEY,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    vulnerability_name TEXT,
    description TEXT,
    date_added DATE,
    due_date DATE,
    required_action TEXT,
    known_ransomware_use BOOLEAN DEFAULT FALSE,
    notes TEXT,
    last_synced TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_kev_vendor ON kev_catalog(vendor);
CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_catalog(date_added DESC);
CREATE INDEX IF NOT EXISTS idx_kev_due_date ON kev_catalog(due_date);
