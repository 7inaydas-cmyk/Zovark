# Requirements Document

## Introduction

This spec covers a full execution audit of Zovark v3.2.1 — a production AI SOC system. The audit spans the Go API (`api/`) and Python worker (`worker/`) codebases and targets four concerns: (1) runtime path tracing to distinguish live code from dead code, (2) bug identification across both languages, (3) security issues including auth, input validation, secrets handling, and sandbox escapes, and (4) cleanup opportunities including unused imports, dead routes, and orphaned migrations.

The primary runtime path is: SIEM alert → Go API (`:8090`) → Redpanda/NATS → `worker/nats_consumer.py` → Temporal `InvestigationWorkflowV2` → 6-stage pipeline (ingest → analyze → execute → assess → govern → store). All findings must be traceable to specific files and line ranges.

## Glossary

- **Audit_System**: The tooling and process defined by this spec that performs static and dynamic analysis of the Zovark codebase.
- **Go_API**: The Go service in `api/` that exposes HTTP endpoints and dispatches work to Temporal.
- **Worker**: The Python Temporal worker in `worker/` that executes investigation workflows and activities.
- **Primary_Path**: The runtime execution path from SIEM alert ingestion through `InvestigationWorkflowV2` to verdict storage.
- **Dead_Code**: Any function, route, activity, workflow, or module that is registered or defined but never reachable from the Primary_Path or any other live trigger.
- **Legacy_Layout**: The `worker/_legacy_activities.py` / `worker/_legacy_workflows.py` pattern where actual implementations live in underscore-prefixed files and `activities/__init__.py` / `workflows/__init__.py` re-export them.
- **NATS_Consumer**: `worker/nats_consumer.py` — the component that receives alerts from Redpanda and is supposed to start Temporal workflows.
- **Feature_Flag**: The `ZOVARK_EXECUTION_MODE` environment variable (`tools` = v3, `sandbox` = v2).
- **AST_Prefilter**: The 4-layer static analysis gate in `worker/stages/execute.py` that blocks dangerous imports and builtins before sandbox execution.
- **Sandbox**: The Docker-based code execution environment used in v2 mode (`ZOVARK_EXECUTION_MODE=sandbox`).

---

## Requirements

### Requirement 1: Runtime Path Tracing — Go API Routes

**User Story:** As a security engineer, I want to know which of the 90+ registered Go API routes are actually exercised in production, so that I can identify dead routes that add attack surface without providing value.

#### Acceptance Criteria

1. THE Audit_System SHALL enumerate all routes registered in `api/main.go` and classify each as: `live` (reachable from a documented production trigger), `feature-gated` (reachable only under a specific env var or profile), or `dead` (no known trigger).
2. WHEN a route handler function is defined in a `.go` file but not registered in `api/main.go`, THE Audit_System SHALL flag it as an orphaned handler.
3. THE Audit_System SHALL verify that every route marked `live` has a corresponding handler function that compiles without errors.
4. WHEN a route is protected by `requireRole(...)`, THE Audit_System SHALL confirm the role list is consistent with the RBAC model documented in `CLAUDE.md` (admin / analyst / viewer / api_key).
5. THE Audit_System SHALL identify any route that accepts user-controlled input without calling `sanitizeSIEMField` or an equivalent sanitization function before passing data to downstream systems.

---

### Requirement 2: Runtime Path Tracing — Worker Activities and Workflows

**User Story:** As a platform engineer, I want to know which of the 107 registered Temporal activities and 17 workflows are actually invoked during a normal alert investigation, so that I can remove or quarantine dead registrations that increase startup time and maintenance burden.

#### Acceptance Criteria

1. THE Audit_System SHALL trace the call graph from `InvestigationWorkflowV2.run()` and list every activity it directly invokes via `workflow.execute_activity(...)`.
2. THE Audit_System SHALL compare the activities registered in `worker/main.py` against those invoked by `InvestigationWorkflowV2` and all other registered workflows, and produce a list of activities that are registered but never called by any workflow.
3. WHEN an activity is imported in `worker/main.py` but the source module does not define it with `@activity.defn`, THE Audit_System SHALL flag it as a registration mismatch.
4. THE Audit_System SHALL verify that every function listed in `worker/activities/__init__.py` is also defined (with `@activity.defn`) in `worker/_legacy_activities.py`.
5. FOR ALL functions exported from `worker/activities/__init__.py`, THE Audit_System SHALL confirm that the export name matches the function name in `_legacy_activities.py` (round-trip property: import → re-export → name identity).

---

### Requirement 3: Runtime Path Tracing — NATS Consumer Dispatch Bug

**User Story:** As a platform engineer, I want to confirm that alerts received by the NATS consumer actually start Temporal workflows, so that I can be sure no alerts are silently dropped.

#### Acceptance Criteria

1. THE Audit_System SHALL verify that `NATSAlertConsumer._process_message()` in `worker/nats_consumer.py` calls a function that starts a Temporal workflow for each received alert.
2. WHEN `NATSAlertConsumer._default_handler()` is the only handler invoked for a received message, THE Audit_System SHALL flag this as a critical bug because the default handler only logs and does not start a Temporal workflow.
3. THE Audit_System SHALL confirm that `NATSAlertConsumer.process_alert()` is called from within the message dispatch path (either `_process_message` or a registered handler), or flag it as dead code if it is not.
4. WHEN `NATSAlertConsumer.subscribe("ALERTS.>")` is called without a custom handler argument, THE Audit_System SHALL flag this as a misconfiguration because the default handler does not dispatch to Temporal.
5. THE Audit_System SHALL verify that the NATS consumer, when a message is received, either starts a Temporal workflow or records a structured error — it SHALL NOT silently discard the message.

---

### Requirement 4: Bug Identification — Go API

**User Story:** As a security engineer, I want all bugs in the Go API identified with file and line references, so that I can prioritize and fix them before they cause production incidents.

#### Acceptance Criteria

1. THE Audit_System SHALL verify that `workflowName` referenced in `api/siem_ingest.go`'s `createIngestTask()` is defined and resolves to the correct Temporal workflow type name, or flag it as an undefined variable bug.
2. THE Audit_System SHALL verify that `refreshHandler` in `api/auth.go` checks whether the user account still exists and is active in the database before issuing a new access token, or flag the absence of this check as a session persistence bug.
3. THE Audit_System SHALL verify that the logout handler (`logoutHandler`) invalidates the refresh token server-side (e.g., via a token blocklist or DB revocation), or flag the cookie-only approach as an incomplete logout bug.
4. WHEN `beginTenantTx()` is called in `api/db.go`, THE Audit_System SHALL verify that the tenant context is set before any data query in the same transaction, to confirm Row-Level Security is enforced on all tenant-scoped tables.
5. THE Audit_System SHALL identify any Go API handler that calls `dbPool.QueryRow` or `dbPool.Exec` without a context deadline, and flag each as a potential goroutine leak under DB contention.

---

### Requirement 5: Bug Identification — Python Worker

**User Story:** As a platform engineer, I want all bugs in the Python worker identified with file and line references, so that I can fix them before they cause silent data loss or incorrect verdicts.

#### Acceptance Criteria

1. THE Audit_System SHALL verify that the `REDIS_URL` default value in `worker/stages/store.py` uses the correct Redis password (`hydra-redis-dev-2026`) and flag any mismatch as a configuration bug that will cause dedup entry updates to silently fail.
2. THE Audit_System SHALL verify that `worker/stages/ingest.py`'s `fetch_task()` function uses the shared `psycopg2` connection pool from `worker/database/pool_manager.py` rather than calling `psycopg2.connect()` directly, or flag the direct connection as a pool bypass bug.
3. THE Audit_System SHALL verify that `worker/stages/analyze.py` does not import `redis` at module level in a way that causes an `ImportError` if the `redis` package is unavailable at import time, or flag it as a fragile import.
4. WHEN `_analyze_v3_tools()` in `worker/stages/analyze.py` fails to find a saved plan in the DB and also fails to find one in `investigation_plans.json`, THE Audit_System SHALL verify that the function falls through to LLM tool selection rather than returning an empty plan silently.
5. THE Audit_System SHALL verify that `worker/stages/store.py`'s `_update_task_status()` never sets `needs_human_review = False` for a completed investigation with `risk_score < ZOVARK_HUMAN_REVIEW_THRESHOLD`, since the current logic always sets `needs_review = True` when risk is below threshold regardless of verdict.

---

### Requirement 6: Security Issues — Authentication and Token Handling

**User Story:** As a security engineer, I want all authentication and token-handling vulnerabilities identified, so that I can remediate them before a regulated customer audit.

#### Acceptance Criteria

1. THE Audit_System SHALL verify that JWT tokens are validated for the `Subject` claim (`access` vs `refresh`) in `authMiddleware()`, or flag the absence of this check as a token confusion vulnerability where a refresh token could be used as an access token.
2. THE Audit_System SHALL verify that the `Secure` flag on the `refresh_token` cookie in `loginHandler` is set unconditionally (not only when `c.Request.TLS != nil`), or flag the conditional as a cookie downgrade risk in reverse-proxy deployments.
3. THE Audit_System SHALL verify that the break-glass login endpoint (`/api/v1/admin/breakglass/login`) enforces rate limiting, or flag the absence as a brute-force risk on the emergency auth path.
4. THE Audit_System SHALL verify that OIDC callback state parameters are validated against a server-side nonce to prevent CSRF on the SSO flow, or flag the absence as an OIDC CSRF vulnerability.
5. THE Audit_System SHALL verify that API key values are stored as hashed digests (not plaintext) in the database, or flag plaintext storage as a credential exposure risk.

---

### Requirement 7: Security Issues — Input Validation and Injection

**User Story:** As a security engineer, I want all input validation gaps identified across the ingest path, so that I can confirm no attacker-controlled data reaches the LLM or database without sanitization.

#### Acceptance Criteria

1. THE Audit_System SHALL verify that `webhookAlertHandler` in `api/main.go` performs HMAC signature validation on the incoming request body before processing, or flag the absence as an unauthenticated ingest endpoint.
2. THE Audit_System SHALL verify that the raw `siem_event` map passed from `splunkIngestHandler` and `elasticIngestHandler` to `createIngestTask` has all string fields sanitized via `sanitizeSIEMField` before being stored in `agent_tasks.input`, or flag unsanitized fields.
3. THE Audit_System SHALL verify that `worker/stages/input_sanitizer.py`'s `sanitize_siem_event()` is called on the `siem_event` dict before it is passed to any LLM prompt construction in `analyze.py`, and that the sanitized output is used (not the original).
4. WHEN `_wrap_siem()` in `worker/stages/analyze.py` constructs the randomized boundary delimiter, THE Audit_System SHALL verify that the boundary string cannot appear in attacker-controlled SIEM data (i.e., it is derived from `os.urandom`, not from user input).
5. THE Audit_System SHALL verify that the `mapAlertToTaskType()` function in `api/siem_ingest.go` cannot produce a `task_type` string that, when used as a PostgreSQL parameter, enables SQL injection — specifically that the sanitized output is always used as a bound parameter, never interpolated into a query string.

---

### Requirement 8: Security Issues — Secrets Handling

**User Story:** As a compliance engineer, I want all hardcoded secrets and insecure credential patterns identified, so that I can replace them with Vault-backed secrets before a CMMC or HIPAA audit.

#### Acceptance Criteria

1. THE Audit_System SHALL scan all Python and Go source files for hardcoded credential strings matching patterns for passwords, API keys, and JWT secrets, and report each occurrence with file path and line number.
2. THE Audit_System SHALL verify that `worker/stages/ingest.py`, `worker/stages/analyze.py`, `worker/stages/assess.py`, and `worker/stages/store.py` each use `settings.py` (Pydantic Settings) as the primary credential source and only fall back to hardcoded defaults when `settings.py` is unavailable (e.g., in unit tests).
3. THE Audit_System SHALL verify that no credential string from `CLAUDE.md`'s Credentials table (e.g., `hydra_dev_2026`, `hydra-redis-dev-2026`, `sk-zovark-dev-2026`) appears in any file outside of `.env.example`, `CLAUDE.md`, and test fixtures.
4. WHEN `GetSecret()` in `api/vault.go` falls back to an environment variable, THE Audit_System SHALL verify that the fallback value is never logged at INFO level or above, to prevent credential leakage in container logs.
5. THE Audit_System SHALL verify that `ZOVARK_LLM_KEY` is treated as a `SecretStr` in `worker/settings.py` and is never serialized to a log line or JSON response body.

---

### Requirement 9: Security Issues — Sandbox and Code Execution

**User Story:** As a security engineer, I want all sandbox escape vectors and code execution risks identified in the v2 pipeline, so that I can confirm LLM-generated code cannot affect the host system.

#### Acceptance Criteria

1. THE Audit_System SHALL verify that `_run_fast_fill()` in `worker/stages/execute.py` is never called when `ZOVARK_EXECUTION_MODE=tools` (v3 default), and that it is only reachable when `FAST_FILL=true` AND `ZOVARK_EXECUTION_MODE=sandbox`, or flag any path where it runs without Docker isolation.
2. THE Audit_System SHALL verify that the `BLOCKED_PATTERNS` list in `worker/stages/execute.py` performs case-sensitive matching consistently — specifically that `import os` and `Import Os` are both blocked — or flag the inconsistency as an AST prefilter bypass.
3. THE Audit_System SHALL verify that the `MOCK_REQUESTS_SHIM` prepended to LLM-generated code in `worker/stages/analyze.py` does not introduce any callable that could be used to exfiltrate data or execute system commands within the sandbox.
4. THE Audit_System SHALL verify that the Docker sandbox command in `_run_in_sandbox()` includes `--user 65534:65534` (non-root), `--cap-drop=ALL`, `--network=none`, and `--read-only`, and that none of these flags can be overridden by the `sandbox_policy.yaml` configuration.
5. WHEN `SANDBOX_POLICY` is `None` (YAML load failure), THE Audit_System SHALL verify that `execute.py` falls back to the hardcoded safe defaults rather than running code without any prefilter, or flag the fallback as insufficient.

---

### Requirement 10: Cleanup — Dead Code and Unused Imports

**User Story:** As a platform engineer, I want all dead code and unused imports identified, so that I can reduce the codebase surface area and improve maintainability.

#### Acceptance Criteria

1. THE Audit_System SHALL identify all Python modules under `worker/` that are imported in `worker/main.py` but whose exported functions are never called by any registered workflow or activity in the primary investigation path.
2. THE Audit_System SHALL identify all Go source files in `api/` that define handler functions not referenced in `api/main.go`'s route registrations.
3. THE Audit_System SHALL verify that `worker/stages/analyze.py`'s `_TOOL_CALLING_SYSTEM` variable (marked "kept for backward compat") is not referenced anywhere other than its own assignment, and flag it as a dead alias if so.
4. THE Audit_System SHALL identify all `worker/skills/` Python files (e.g., `deobfuscation.py`, `lateral_movement.py`) and determine whether each is invoked from any registered Temporal activity or workflow, or is dead code.
5. THE Audit_System SHALL identify any `worker/stages/skills/` subdirectory contents and determine whether they are referenced from the primary pipeline stages or are orphaned.

---

### Requirement 11: Cleanup — Orphaned Migrations and Schema Drift

**User Story:** As a database engineer, I want all orphaned migrations and schema inconsistencies identified, so that I can ensure the migration sequence is clean and the schema matches the application's expectations.

#### Acceptance Criteria

1. THE Audit_System SHALL verify that the migration sequence in `migrations/` has no gaps other than the documented intentional gap at prefixes 056–058, and flag any undocumented gaps.
2. THE Audit_System SHALL verify that `migrations/049_sprint1e_hardening.sql` and `migrations/003_sprint1e_hardening.sql` do not apply conflicting or duplicate schema changes to the same tables, and flag any overlap.
3. THE Audit_System SHALL verify that `migrations/039_drop_legacy_tables.sql` does not drop any table that is still referenced by a query in `api/` or `worker/`, and flag any such reference as a schema drift bug.
4. THE Audit_System SHALL verify that every table referenced by a SQL query in `worker/stages/store.py` (`agent_tasks`, `investigations`, `investigation_memory`, `audit_events`, `llm_audit_log`) has a corresponding migration that creates it.
5. THE Audit_System SHALL verify that the `investigation_memory` table name used in `worker/stages/store.py` matches the table name created in the migrations (singular form, per `CLAUDE.md`), and flag any mismatch as a schema drift bug.

---

### Requirement 12: Cleanup — Configuration and Environment Variable Hygiene

**User Story:** As a platform engineer, I want all configuration inconsistencies and environment variable mismatches identified, so that I can ensure the system behaves predictably across dev, staging, and production deployments.

#### Acceptance Criteria

1. THE Audit_System SHALL verify that every environment variable read via `os.environ.get()` or `os.getenv()` in `worker/` has a corresponding entry in `worker/settings.py` (Pydantic Settings), or flag ungoverned env var reads.
2. THE Audit_System SHALL verify that the `DATABASE_URL` default in `api/main.go` (`postgresql://zovark:zovark_dev_2026@postgres:5432/zovark`) matches the password documented in `CLAUDE.md` (`hydra_dev_2026`), or flag the mismatch as a configuration bug.
3. THE Audit_System SHALL verify that `ZOVARK_MAX_CONCURRENT_ACTIVITIES` and `ZOVARK_MAX_CONCURRENT_WORKFLOWS` in `worker/main.py` match the values documented in `CLAUDE.md` (16 concurrent activities, 32 concurrent workflows), or flag the discrepancy.
4. THE Audit_System SHALL verify that the `REDIS_URL` default password used across `worker/stages/ingest.py`, `worker/stages/analyze.py`, and `worker/stages/store.py` is consistent, and flag any file that uses a different default password.
5. THE Audit_System SHALL verify that `api/main.go`'s `Config` struct reads `ZOVARK_LLM_KEY` (not a legacy key name) for the LLM API key, consistent with the `ZOVARK_` prefix convention documented in `CLAUDE.md`.
