-- Migration 065: Enforce RLS via zovark_app user
-- The zovark superuser bypasses RLS. zovark_app does not.
-- Worker and API should connect as zovark_app for tenant isolation.

-- Grant permissions to zovark_app
GRANT CONNECT ON DATABASE zovark TO zovark_app;
GRANT USAGE ON SCHEMA public TO zovark_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO zovark_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO zovark_app;

-- Ensure future tables also get grants
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO zovark_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO zovark_app;

-- Force RLS on tables that have it enabled but not forced
ALTER TABLE investigation_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_memory FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_skills ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_skills FORCE ROW LEVEL SECURITY;
ALTER TABLE governance_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance_config FORCE ROW LEVEL SECURITY;
ALTER TABLE template_promotion_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE template_promotion_approvals FORCE ROW LEVEL SECURITY;

-- Create RLS policies for newly-enabled tables (if missing)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'investigation_memory' AND policyname = 'tenant_isolation') THEN
    CREATE POLICY tenant_isolation ON investigation_memory
      USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'governance_config' AND policyname = 'tenant_isolation') THEN
    CREATE POLICY tenant_isolation ON governance_config
      USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
  END IF;
END
$$;

-- Verify
SELECT relname, relrowsecurity, relforcerowsecurity
FROM pg_class
WHERE relname IN ('agent_tasks', 'investigations', 'audit_events', 'entities',
                  'entity_edges', 'investigation_memory', 'analyst_feedback',
                  'template_promotion_approvals', 'agent_skills', 'governance_config')
ORDER BY relname;
