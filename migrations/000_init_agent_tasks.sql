-- Migration 000: agent_tasks base table
-- FIX #24: agent_tasks was only in init.sql, not in any numbered migration.
-- This migration ensures the table exists when bootstrapping from migrations alone.
-- All subsequent migrations (040, 044, 047, 055, 061, etc.) ALTER this table.
--
-- Safe to run on an existing DB — uses IF NOT EXISTS throughout.

CREATE TABLE IF NOT EXISTS agent_tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    task_type VARCHAR(100) NOT NULL,
    input JSONB NOT NULL DEFAULT '{}',
    output JSONB,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'planning', 'approved', 'executing', 'completed',
        'failed', 'cancelled', 'awaiting_approval', 'rejected', 'queued', 'deduplicated'
    )),
    error_message TEXT,
    workflow_id VARCHAR(255),
    workflow_run_id VARCHAR(255),
    skill_id UUID,
    tokens_used_input INTEGER NOT NULL DEFAULT 0,
    tokens_used_output INTEGER NOT NULL DEFAULT 0,
    execution_ms INTEGER,
    severity VARCHAR(20),
    worker_id VARCHAR(255),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_tenant ON agent_tasks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(status);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_created ON agent_tasks(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_tenant_status ON agent_tasks(tenant_id, status);
