-- Migration 068 (renumbered from 052 to resolve prefix conflict)
-- Sprint 1J: Rate limit audit trail
-- Records lease acquisition/release events for debugging and metrics.
-- Leases themselves live in Redis; this table is for historical analysis.

CREATE TABLE IF NOT EXISTS rate_limit_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    task_id UUID,
    worker_id TEXT,
    event_type TEXT NOT NULL CHECK (event_type IN ('acquired', 'released', 'rejected', 'expired')),
    active_count INTEGER DEFAULT 0,
    max_concurrent INTEGER DEFAULT 50,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_tenant ON rate_limit_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rate_limit_type ON rate_limit_events(event_type, created_at DESC);

-- Cleanup policy: events older than 7 days can be pruned
COMMENT ON TABLE rate_limit_events IS 'Sprint 1J: Rate limit lease audit trail. Prune entries older than 7 days.';
