-- Migration 067: Add remediation event types to audit_events check constraint
-- Sprint C1: Remediation Engine

-- Drop and recreate the event_type check constraint with remediation events
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check
CHECK (event_type IN (
    'investigation_started',
    'investigation_completed',
    'code_executed',
    'approval_requested',
    'approval_granted',
    'approval_denied',
    'approval_timeout',
    'entity_extracted',
    'detection_generated',
    'user_login',
    'user_registered',
    'injection_detected',
    'cross_tenant_hit',
    'threat_score_updated',
    'self_healing_scan',
    'self_healing_diagnosis',
    'self_healing_patch_applied',
    'self_healing_patch_failed',
    'self_healing_rollback',
    'dry_run_validation_failed',
    'memory_enrichment_applied',
    'model_timeout',
    'telemetry_access_denied',
    'schema_validation_error',
    'postgres_lock',
    -- Sprint C1: Remediation events
    'remediation_suggested',
    'remediation_verification_started',
    'remediation_action_updated'
));

-- Also add the kill-switch config default
INSERT INTO system_configs (tenant_id, config_key, config_value, is_secret, description)
SELECT t.id, 'remediation.auto_verify_enabled', 'false', false,
       'Kill switch for automated remediation verification (default: disabled)'
FROM tenants t
WHERE NOT EXISTS (
    SELECT 1 FROM system_configs sc
    WHERE sc.tenant_id = t.id AND sc.config_key = 'remediation.auto_verify_enabled'
);
