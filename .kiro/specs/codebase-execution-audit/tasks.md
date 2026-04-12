# Tasks — Codebase Execution Audit

## Task List

- [x] 1. Runtime Path Tracing — Go API Routes
  - [x] 1.1 Enumerate all routes registered in `api/main.go` and classify each as `live`, `feature-gated`, or `dead`
  - [x] 1.2 Identify any `*Handler` function defined in `api/*.go` but not registered in `api/main.go` (orphaned handlers)
  - [x] 1.3 Verify `workflowName` in `api/task_handlers.go` resolves to the correct Temporal workflow type and flag the default as a misconfiguration (BUG-002)
  - [x] 1.4 Audit all `requireRole(...)` calls in `api/main.go` and confirm every role string is a member of `{admin, analyst, viewer, api_key}`
  - [x] 1.5 Trace string fields from SIEM ingest request bodies through `splunkIngestHandler` and `elasticIngestHandler` to `createIngestTask` and identify any fields stored in `agent_tasks.input` without `sanitizeSIEMField` (SEC-005)

- [x] 2. Runtime Path Tracing — Worker Activities and Workflows
  - [x] 2.1 Trace `InvestigationWorkflowV2.run()` in `worker/stages/investigation_workflow.py` and list every activity it invokes via `workflow.execute_activity(...)`
  - [x] 2.2 Compare the full activities list in `worker/main.py` against activities invoked by `InvestigationWorkflowV2` and all other registered workflows; produce a list of activities registered but never called by any workflow
  - [x] 2.3 Verify every function in `worker/main.py`'s activities list is decorated with `@activity.defn` in its source module; flag any that are not
  - [x] 2.4 Verify every name exported from `worker/activities/__init__.py` is defined with `@activity.defn` in `worker/_legacy_activities.py`
  - [x] 2.5 Confirm the export name in `worker/activities/__init__.py` matches the function name in `_legacy_activities.py` for each re-export (round-trip name identity)

- [x] 3. Runtime Path Tracing — NATS Consumer Dispatch Bug
  - [x] 3.1 Read `worker/nats_consumer.py:_process_message()` and confirm it does not call any function that starts a Temporal workflow (BUG-001)
  - [x] 3.2 Confirm `create_nats_consumer()` calls `subscribe("ALERTS.>")` without a custom handler argument, meaning `_default_handler` is always used and alerts are silently dropped (BUG-001)
  - [x] 3.3 Grep all Python files for calls to `process_alert()` and confirm it is dead code — never called from the dispatch path (DEAD-002)
  - [x] 3.4 Verify that when a NATS message is received, the current code path either starts a Temporal workflow or records a structured error; document the gap

- [x] 4. Bug Identification — Go API
  - [x] 4.1 Confirm `workflowName` default is `"ExecuteTaskWorkflow"` not `"InvestigationWorkflowV2"` and document the production impact (BUG-002)
  - [x] 4.2 Read `api/auth.go:refreshHandler` and confirm it does not query the DB for user existence before issuing a new access token (BUG-003)
  - [x] 4.3 Read `api/auth.go:logoutHandler` and confirm it only clears the cookie without server-side token revocation (BUG-004)
  - [x] 4.4 Read `api/db.go:beginTenantTx` and verify the tenant context `SET LOCAL` executes before any data query in the same transaction; verify all callers use the returned `tx` for subsequent queries
  - [x] 4.5 Grep `api/*.go` for `dbPool.QueryRow` and `dbPool.Exec` calls that use `context.Background()` directly (no deadline) inside request handlers and flag each as a potential goroutine leak

- [x] 5. Bug Identification — Python Worker
  - [x] 5.2 Read `worker/stages/ingest.py:fetch_task` and confirm it calls `psycopg2.connect()` directly via `_get_db()` instead of using the shared pool from `worker/database/pool_manager.py` (BUG-005)
  - [x] 5.3 Read `worker/stages/analyze.py` and confirm `import redis as _redis` appears at module level without a try/except guard (SEC-007)
  - [x] 5.4 Read `worker/stages/analyze.py:_analyze_v3_tools` and verify the fallback behavior when no saved plan is found and `ZOVARK_MODE=templates-only` — confirm it returns an empty plan silently rather than falling through to LLM selection
  - [x] 5.5 Read `worker/stages/store.py:_update_task_status` and verify the `needs_human_review` logic: confirm it sets `needs_review=True` when `risk_score < threshold` (correct behavior) and document the logic clearly

- [x] 6. Security Issues — Authentication and Token Handling
  - [x] 6.1 Read `api/middleware.go:authMiddleware` and confirm it does not check `claims.Subject == "access"`, allowing a refresh token to be used as an access token (SEC-001)
  - [x] 6.2 Read `api/auth.go:loginHandler` and confirm `Secure: c.Request.TLS != nil` is conditional, making the refresh token cookie insecure behind a TLS-terminating reverse proxy (SEC-002)
  - [x] 6.3 Read `api/admin_breakglass.go:handleBreakglassLogin` and confirm the in-memory rate limiter (3 attempts/minute/IP) is present and functioning
  - [x] 6.4 Read `api/oidc.go:ssoLoginHandler` and `ssoCallbackHandler` and confirm the OIDC state is stored in a cookie (not server-side Redis/DB) and assess the CSRF risk (SEC-003)
  - [x] 6.5 Read `api/apikeys.go:createAPIKeyHandler` and confirm API key values are stored as SHA-256 hashes (`key_hash`), not plaintext

- [x] 7. Security Issues — Input Validation and Injection
  - [x] 7.1 Read `api/siem.go:webhookAlertHandler` and confirm HMAC validation is conditional on `webhook_secret` being configured, meaning log sources without a secret accept unauthenticated payloads (SEC-004)
  - [x] 7.2 Read `splunkIngestHandler` and `elasticIngestHandler` in `api/siem_ingest.go` and confirm the raw `payload.Event` map is stored as `input["siem_event"]` without field-level sanitization (SEC-005)
  - [x] 7.3 Grep `worker/stages/analyze.py` for calls to `sanitize_siem_event()` from `worker/stages/input_sanitizer.py` and confirm whether it is called before LLM prompt construction
  - [x] 7.4 Read `worker/stages/analyze.py:_wrap_siem` and confirm the boundary delimiter is derived from `os.urandom` or equivalent, not from user-controlled input
  - [x] 7.5 Grep `api/*.go` for SQL queries that incorporate `task_type` and confirm all use parameterized binding (`$1`) rather than string interpolation

- [x] 8. Security Issues — Secrets Handling
  - [x] 8.1 Grep all `*.py` and `*.go` files (excluding `.env.example`, `CLAUDE.md`, test fixtures) for the strings `hydra_dev_2026`, `hydra-redis-dev-2026`, `sk-zovark-dev-2026`, `TestPass2026` and report each occurrence with file and line
  - [x] 8.2 Verify that `ingest.py`, `analyze.py`, `assess.py`, and `store.py` each use the `try: from settings import settings` pattern as the primary credential source
  - [x] 8.3 Confirm no credential string from the CLAUDE.md Credentials table appears in any file outside `.env.example`, `CLAUDE.md`, and test fixtures
  - [x] 8.4 Read `api/vault.go:GetSecret` and confirm the fallback `getEnvOrDefault` call does not log the returned value at INFO level or above
  - [x] 8.5 Read `worker/settings.py` and confirm `llm_key` is defined as `str` not `SecretStr`, and flag this as a credential exposure risk (SEC-006)

- [x] 9. Security Issues — Sandbox and Code Execution
  - [x] 9.1 Read `worker/stages/execute.py:_execute_v2_sandbox` and trace when `_run_fast_fill` is called; confirm it is only reachable when `FAST_FILL=true` AND `execution_mode=sandbox`
  - [x] 9.2 Read `worker/stages/execute.py:_check_blocked_strings` and confirm it uses `code.lower()` and `pattern.lower()` for case-insensitive matching, so `Import Os` is blocked as well as `import os`
  - [x] 9.3 Read `worker/stages/analyze.py:MOCK_REQUESTS_SHIM` and confirm `MockRequests.get/post` return static `MockResponse` objects with no network calls or system command execution
  - [x] 9.4 Read `worker/stages/execute.py:_run_in_sandbox` and confirm the Docker command includes `--user 65534:65534`, `--cap-drop=ALL`, `--network=none`, and `--read-only`
  - [x] 9.5 Read `worker/stages/execute.py` top-level and confirm that when `SANDBOX_POLICY` is `None` (YAML load failure), `FORBIDDEN_IMPORTS` and `FORBIDDEN_PATTERNS` fall back to hardcoded safe defaults

- [x] 10. Cleanup — Dead Code and Unused Imports
  - [x] 10.1 Identify all Python modules imported in `worker/main.py` whose exported functions are never called by any registered workflow or activity in the primary investigation path
  - [x] 10.2 Enumerate all `*Handler` functions in `api/*.go` and diff against route registrations in `api/main.go`; list any orphaned handlers
  - [x] 10.3 Confirm `_TOOL_CALLING_SYSTEM` in `worker/stages/analyze.py:529` is only assigned and never referenced elsewhere in the file (DEAD-001); flag for removal
  - [x] 10.4 List all files in `worker/skills/` and determine whether each is invoked from any registered Temporal activity or workflow; confirm `run_deobfuscation` is registered but check if any workflow calls it
  - [x] 10.5 Check whether a `worker/stages/skills/` subdirectory exists and, if so, whether its contents are referenced from any pipeline stage

- [x] 11. Cleanup — Orphaned Migrations and Schema Drift
  - [x] 11.1 List all migration file prefixes in `migrations/`, verify the sequence is contiguous except for the documented 056-058 gap, and flag any undocumented gaps
  - [x] 11.2 Read `migrations/049_sprint1e_hardening.sql` and `migrations/003_sprint1e_hardening.sql` and confirm they do not apply conflicting or duplicate schema changes to the same tables
  - [x] 11.3 Read `migrations/039_drop_legacy_tables.sql`, extract all dropped table names, and grep `api/` and `worker/` to confirm none are still referenced in queries
  - [x] 11.4 Extract all table names from SQL queries in `worker/stages/store.py` (`agent_tasks`, `investigations`, `investigation_memory`, `audit_events`, `llm_audit_log`) and confirm each has a `CREATE TABLE` statement in `migrations/`
  - [x] 11.5 Grep `worker/stages/store.py` for `investigation_memory` and confirm the singular form is used consistently; grep `migrations/` for the `CREATE TABLE` statement and confirm the name matches

- [x] 12. Cleanup — Configuration and Environment Variable Hygiene
  - [x] 12.1 Grep `worker/` for `os.environ.get` and `os.getenv` calls, extract all variable names, and verify each has a corresponding field in `ZovarkSettings` in `worker/settings.py`
  - [x] 12.2 Read `api/main.go:43` and confirm the `DATABASE_URL` default uses `zovark_dev_2026` instead of the correct `hydra_dev_2026` (BUG-007)
  - [x] 12.3 Read `worker/main.py:95-96` and confirm `MAX_CONCURRENT_ACTIVITIES=8` and `MAX_CONCURRENT_WORKFLOWS=16` differ from the CLAUDE.md documented values of 16/32 (BUG-008)
  - [x] 12.4 Compare the `REDIS_URL` default password across `worker/stages/ingest.py`, `worker/stages/analyze.py`, and `worker/stages/store.py`; confirm `store.py` uses the wrong password (CONFIG-001)
  - [x] 12.5 Read `api/main.go:Config` init and confirm `LLMKey` reads from `ZOVARK_LLM_KEY` (correct `ZOVARK_` prefix convention)
