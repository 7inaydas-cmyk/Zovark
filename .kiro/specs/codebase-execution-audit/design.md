# Design Document — Codebase Execution Audit

## Overview

This document describes how the execution audit of Zovark v3.2.1 will be conducted. The audit is a static analysis exercise: no code is modified, no services are started. All findings are produced by reading source files, tracing call graphs, and applying the acceptance criteria from the requirements document.

The primary runtime path under audit is:

```
SIEM alert → Go API (:8090) → NATS/Redpanda → worker/nats_consumer.py
  → Temporal InvestigationWorkflowV2 → 6-stage pipeline
  (ingest → analyze → execute → assess → govern → store)
```

The audit covers four concern areas: runtime path tracing, bug identification, security issues, and cleanup. Each concern maps to one or more requirements and produces a structured finding with file path, line reference, severity, and remediation guidance.

---

## Architecture

The audit is a read-only static analysis pass over two codebases:

- **Go API** (`api/`) — Gin HTTP server, 90+ routes, JWT auth, SIEM ingest, Temporal dispatch
- **Python Worker** (`worker/`) — Temporal worker, 6-stage investigation pipeline, 107 registered activities, 17 registered workflows

The audit methodology has four phases:

```
Phase 1: Call Graph Tracing
  ├── Go: enumerate routes in main.go → classify live/feature-gated/dead
  ├── Go: enumerate *Handler functions → diff against route registrations
  ├── Python: trace InvestigationWorkflowV2.run() → list invoked activities
  └── Python: diff registered activities (main.py) vs invoked activities

Phase 2: Bug Identification
  ├── Go: auth flows (refresh, logout, token confusion)
  ├── Go: DB context deadlines, RLS enforcement
  ├── Python: pool bypass, fragile imports, config mismatches
  └── Python: NATS consumer dispatch path

Phase 3: Security Review
  ├── Auth & tokens (JWT subject claim, cookie flags, OIDC state)
  ├── Input validation (HMAC, siem_event sanitization, boundary injection)
  ├── Secrets (hardcoded credentials, SecretStr coverage, Vault fallback logging)
  └── Sandbox (AST prefilter case sensitivity, Docker flags, fast_fill gating)

Phase 4: Cleanup
  ├── Dead code (unused imports, orphaned handlers, dead aliases)
  ├── Migration sequence (gaps, conflicts, dropped-table references)
  └── Config hygiene (env var governance, password consistency, concurrency defaults)
```

---

## Components and Interfaces

### Go API Call Graph

**Entry point:** `api/main.go` — all routes registered here.

**Route classification criteria:**
- `live` — handler is reachable from a documented production trigger (SIEM ingest, dashboard, CLI)
- `feature-gated` — reachable only when a specific env var or Docker profile is active (e.g., `ZOVARK_EXECUTION_MODE=sandbox`, `--profile tracing`)
- `dead` — no known trigger; handler defined but not reachable from any documented path

**Key finding — `workflowName` default:** `task_handlers.go:getWorkflowName()` defaults to `"ExecuteTaskWorkflow"` when `ZOVARK_WORKFLOW_VERSION` is not set. The V2 pipeline is `InvestigationWorkflowV2`. In a default deployment without the env var, all SIEM ingest routes dispatch to the legacy workflow, not the V2 pipeline. This is a critical misconfiguration risk.

**Key finding — `webhookAlertHandler` HMAC:** `siem.go` validates HMAC only when `webhook_secret` is present in `connection_config`. If a log source is created without a secret, the endpoint accepts unauthenticated payloads from any caller.

**Key finding — `siem_event` map unsanitized:** `splunkIngestHandler` and `elasticIngestHandler` sanitize the prompt string fields via `sanitizeSIEMField` but store the raw `payload.Event` map as `input["siem_event"]` without field-level sanitization. This map is later passed to the Python worker and used in LLM prompt construction.

### Python Worker Call Graph

**Entry point:** `worker/main.py` — registers 107 activities and 17 workflows.

**V2 pipeline activities** (registered via `get_v2_activities()`):
- `ingest_alert` (stages/ingest.py)
- `analyze_alert` (stages/analyze.py)
- `execute_investigation` (stages/execute.py)
- `assess_results` (stages/assess.py)
- `apply_governance` (stages/govern.py)
- `store_investigation` (stages/store.py)

**Activities invoked by `InvestigationWorkflowV2.run()`:**
1. `fetch_task` (legacy activity, string name reference)
2. `ingest_alert`
3. `analyze_alert`
4. `execute_investigation`
5. `assess_results`
6. `apply_governance`
7. `store_investigation`

**Activities registered but not invoked by InvestigationWorkflowV2** (partial list — full enumeration is a task):
- All bootstrap, intelligence, detection, response, fine-tuning, SRE, scheduler, correlation, SLA, embedding, integration, shadow, PII, stampede, token quota, network analysis, feedback, KEV, and cipher audit activities. These are invoked by their respective non-investigation workflows (e.g., `BootstrapCorpusWorkflow`, `ResponsePlaybookWorkflow`).

**Key finding — NATS consumer dispatch bug:** `create_nats_consumer()` calls `consumer.subscribe("ALERTS.>")` with no `handler` argument. This means `_process_message()` always falls through to `_default_handler()`, which only logs the alert at INFO level and does not start a Temporal workflow. `process_alert()` — the method that would start a workflow — is never called from the dispatch path. Every alert received via NATS is silently dropped.

**Key finding — `fetch_task` pool bypass:** `worker/stages/ingest.py:fetch_task()` calls `_get_db()` which calls `psycopg2.connect(DATABASE_URL)` directly, bypassing the `ThreadedConnectionPool` in `worker/database/pool_manager.py`. Under load, this creates a new DB connection per activity invocation.

### Legacy File Layout

Per `AGENTS.md`, the worker uses a split layout:
- `worker/_legacy_activities.py` — actual `@activity.defn` implementations
- `worker/activities/__init__.py` — re-exports a subset of those functions

The `__init__.py` exports: `fetch_task`, `update_task_status`, `log_audit`, `log_audit_event`, `record_usage`, `check_requires_approval`, `create_approval_request`, `update_approval_request`, `check_rate_limit_activity`, `decrement_active_activity`, `heartbeat_lease_activity`, `get_db_connection`.

All of these are defined with `@activity.defn` in `_legacy_activities.py`. The round-trip is consistent for the exported subset. However, `_legacy_activities.py` defines additional activities (`generate_code`, `validate_code`, `execute_code`, `save_investigation_pattern`, etc.) that are not re-exported through `__init__.py` and are not registered in `main.py` — these are dead registrations from the V2 sandbox path.

---

## Data Models

### Finding Record

Each audit finding is structured as:

```
Finding {
  id:           string          // e.g., "BUG-001"
  requirement:  string          // e.g., "Requirement 4.2"
  severity:     CRITICAL | HIGH | MEDIUM | LOW | INFO
  category:     BUG | SECURITY | DEAD_CODE | CONFIG | SCHEMA
  file:         string          // relative path
  line_range:   string          // e.g., "L220-L235"
  title:        string
  description:  string          // what the code does
  impact:       string          // what goes wrong
  remediation:  string          // how to fix it
}
```

### Confirmed Findings (from static analysis)

**BUG-001 — NATS Consumer Silent Alert Drop (CRITICAL)**
- File: `worker/nats_consumer.py:333-340` (`create_nats_consumer`)
- `subscribe("ALERTS.>")` called with no handler → `_default_handler` used → only logs, never starts Temporal workflow
- `process_alert()` is dead code — never called from dispatch path
- Impact: All alerts received via NATS are silently dropped. The system appears healthy but no investigations are started.
- Remediation: Pass `handler=consumer.process_alert` to `subscribe()`, and implement Temporal client dispatch inside `process_alert()`.

**BUG-002 — workflowName Defaults to Legacy Workflow (HIGH)**
- File: `api/task_handlers.go:24-30` (`getWorkflowName`)
- Default is `"ExecuteTaskWorkflow"` (V1 legacy), not `"InvestigationWorkflowV2"` (V2/V3 pipeline)
- Impact: Without `ZOVARK_WORKFLOW_VERSION=InvestigationWorkflowV2` set, all SIEM ingest dispatches to the legacy workflow.
- Remediation: Change default to `"InvestigationWorkflowV2"`.

**BUG-003 — refreshHandler No User Existence Check (HIGH)**
- File: `api/auth.go:220-265` (`refreshHandler`)
- Issues new access token from valid refresh JWT without querying DB to confirm user still exists and is active
- Impact: Deleted or deactivated users retain access until their refresh token expires (7 days).
- Remediation: Add `SELECT is_active FROM users WHERE id = $1` check before issuing new access token.

**BUG-004 — logoutHandler Cookie-Only, No Server-Side Revocation (MEDIUM)**
- File: `api/auth.go:267-280` (`logoutHandler`)
- Clears cookie but does not invalidate the refresh token in DB or Redis
- Impact: A captured refresh token remains valid for up to 7 days after logout.
- Remediation: Add a `revoked_tokens` table or Redis blocklist; check on every refresh.

**BUG-005 — fetch_task Bypasses Connection Pool (MEDIUM)**
- File: `worker/stages/ingest.py:52-55` (`_get_db`), `worker/stages/ingest.py:250-262` (`fetch_task`)
- Calls `psycopg2.connect()` directly instead of using `pool_manager.py`
- Impact: Under concurrent load, creates unbounded DB connections per activity invocation.
- Remediation: Use `get_db_connection()` from `worker/database/pool_manager.py`.

**BUG-006 — REDIS_URL Wrong Password in store.py (MEDIUM)**
- File: `worker/stages/store.py:22`
- Hardcoded default: `redis://:zovark-redis-dev-2026@redis:6379/0`
- Correct password (per CLAUDE.md and settings.py): `hydra-redis-dev-2026`
- Impact: Dedup entry updates silently fail when `REDIS_URL` env var is not set, causing investigation-aware dedup to not update Redis entries with verdict/risk data.
- Remediation: Change default to `redis://:hydra-redis-dev-2026@redis:6379/0` or use `settings.redis_url`.

**BUG-007 — DATABASE_URL Wrong Password in main.go (MEDIUM)**
- File: `api/main.go:43`
- Default: `postgresql://zovark:zovark_dev_2026@postgres:5432/zovark`
- Correct password (per CLAUDE.md): `hydra_dev_2026`
- Impact: API fails to connect to DB in default dev configuration without `DATABASE_URL` env var.
- Remediation: Change default password to `hydra_dev_2026`.

**BUG-008 — MAX_CONCURRENT_ACTIVITIES/WORKFLOWS Mismatch (LOW)**
- File: `worker/main.py:95-96`
- Defaults: `ZOVARK_MAX_CONCURRENT_ACTIVITIES=8`, `ZOVARK_MAX_CONCURRENT_WORKFLOWS=16`
- CLAUDE.md documents: 16 concurrent activities, 32 concurrent workflows
- Impact: Worker runs at half the documented concurrency in default configuration.
- Remediation: Change defaults to 16/32 or update CLAUDE.md to reflect actual defaults.

**SEC-001 — JWT Token Confusion: No Subject Claim Check (HIGH)**
- File: `api/middleware.go:55-95` (`authMiddleware`)
- Does not check `claims.Subject == "access"` — a refresh token (Subject="refresh") is accepted as an access token
- Impact: An attacker with a captured refresh token can use it directly as an access token for all protected endpoints.
- Remediation: Add `if claims.Subject != "access" { abort 401 }` in `authMiddleware`.

**SEC-002 — Refresh Token Cookie Secure Flag Conditional (MEDIUM)**
- File: `api/auth.go:175` (`loginHandler`)
- `Secure: c.Request.TLS != nil` — behind a TLS-terminating reverse proxy (Caddy), `c.Request.TLS` is nil, so `Secure=false`
- Impact: Refresh token cookie transmitted over HTTP in reverse-proxy deployments.
- Remediation: Set `Secure: true` unconditionally, or read from a `ZOVARK_COOKIE_SECURE=true` env var.

**SEC-003 — OIDC State Stored in Cookie (MEDIUM)**
- File: `api/oidc.go:185-188` (`ssoLoginHandler`)
- State stored in `oidc_state` cookie with `Secure: false` (same conditional issue as SEC-002)
- Impact: State cookie transmitted over HTTP; CSRF protection weakened in reverse-proxy deployments.
- Remediation: Store state server-side (Redis with short TTL) keyed by session ID, or enforce `Secure: true`.

**SEC-004 — HMAC Validation Optional on Webhook Endpoint (MEDIUM)**
- File: `api/siem.go:55-63` (`webhookAlertHandler`)
- HMAC validation only occurs when `webhook_secret` is present in `connection_config`
- Impact: Log sources created without a secret accept unauthenticated alert payloads from any caller.
- Remediation: Require `webhook_secret` for all log sources, or document the risk and enforce it in `createLogSourceHandler`.

**SEC-005 — siem_event Map Stored Unsanitized (MEDIUM)**
- File: `api/siem_ingest.go:299-302` (`splunkIngestHandler`), `api/siem_ingest.go:431-434` (`elasticIngestHandler`)
- Raw `payload.Event` map stored as `input["siem_event"]` without field-level sanitization
- Impact: Attacker-controlled SIEM fields (e.g., `raw_log`) reach the Python worker and LLM prompt construction without Go-side sanitization. Python-side sanitization in `input_sanitizer.py` is the only defense.
- Remediation: Apply `sanitizeSIEMField` to all string values in `payload.Event` before storing, or document that Python-side sanitization is the authoritative layer.

**SEC-006 — ZOVARK_LLM_KEY Not SecretStr in settings.py (MEDIUM)**
- File: `worker/settings.py:28`
- `llm_key: str = "sk-zovark-dev-2026"` — plain `str`, not `SecretStr`
- Impact: LLM API key can be accidentally logged via `str(settings)`, `settings.dict()`, or Pydantic model serialization.
- Remediation: Change to `llm_key: SecretStr = SecretStr("sk-zovark-dev-2026")`.

**SEC-007 — analyze.py Redis Import at Module Level (MEDIUM)**
- File: `worker/stages/analyze.py:55`
- `import redis as _redis` at module level without try/except
- Impact: If the `redis` package is unavailable at import time, the entire analyze stage fails to import, crashing the worker on startup.
- Remediation: Wrap in try/except ImportError, or move import inside the function that uses it.

**DEAD-001 — _TOOL_CALLING_SYSTEM Dead Alias (LOW)**
- File: `worker/stages/analyze.py:529`
- `_TOOL_CALLING_SYSTEM = _TOOL_CALLING_SYSTEM_PREFIX` — assigned but never referenced; only `_TOOL_CALLING_SYSTEM_PREFIX` is used
- Remediation: Remove the alias.

**DEAD-002 — process_alert() Dead Code in NATS Consumer (HIGH)**
- File: `worker/nats_consumer.py:170-185` (`process_alert`)
- Never called from `_process_message` or any registered handler
- Remediation: Wire into dispatch path (see BUG-001) or remove.

**CONFIG-001 — REDIS_URL Default Inconsistent Across Stage Files**
- `ingest.py`: `hydra-redis-dev-2026` ✓
- `analyze.py`: `hydra-redis-dev-2026` ✓
- `store.py`: `zovark-redis-dev-2026` ✗
- Remediation: Standardize all three to use `settings.redis_url` as the fallback.

**SCHEMA-001 — Migration Gap 056-058 (Documented/Intentional)**
- Confirmed intentional per AGENTS.md; allowlisted in `api/migrate.go:allowedMigrationGaps`.
- No action required.

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

This feature involves static analysis of source code rather than runtime data transformation. Most acceptance criteria are concrete example-based checks (read a file, verify a condition). However, several criteria express universal properties that hold across all instances of a pattern in the codebase — these are suitable for property-based testing using a tool like Hypothesis (Python) or `gopbt` (Go).

### Property 1: All *Handler Functions Are Registered Routes

*For any* Go source file in `api/`, every exported function whose name ends in `Handler` should appear as a handler argument in at least one route registration in `api/main.go`, or be explicitly documented as an internal helper.

**Validates: Requirements 1.2, 10.2**

---

### Property 2: requireRole Arguments Are Valid RBAC Roles

*For any* `requireRole(...)` call in `api/main.go`, every role string argument should be a member of the documented RBAC set `{"admin", "analyst", "viewer", "api_key"}`.

**Validates: Requirements 1.4**

---

### Property 3: Registered Activities Are Invoked by at Least One Workflow

*For any* activity function registered in `worker/main.py`'s activities list, it should be invoked (directly or transitively) by at least one registered workflow, or be explicitly documented as a utility activity with no workflow caller.

**Validates: Requirements 2.2**

---

### Property 4: activities/__init__.py Exports Have Matching @activity.defn in _legacy_activities.py

*For any* name exported from `worker/activities/__init__.py`, a function with that exact name decorated with `@activity.defn` should exist in `worker/_legacy_activities.py`.

**Validates: Requirements 2.4, 2.5**

---

### Property 5: NATS Messages Are Never Silently Discarded

*For any* message received by the NATS consumer, the dispatch path should either (a) start a Temporal workflow or (b) emit a structured error log containing the message subject and payload — it should never log at INFO level and return without either outcome.

**Validates: Requirements 3.2, 3.5**

---

### Property 6: SQL Queries Using task_type Use Parameterized Binding

*For any* SQL query in `api/*.go` that incorporates a `task_type` value, the value should be passed as a bound parameter (`$1`, `$2`, etc.) and never interpolated directly into the query string.

**Validates: Requirements 7.5**

---

### Property 7: Credential Strings Do Not Appear in Source Files Outside Allowed Locations

*For any* Python or Go source file that is not `.env.example`, `CLAUDE.md`, or a test fixture, no string literal should match the known credential patterns: `hydra_dev_2026`, `hydra-redis-dev-2026`, `sk-zovark-dev-2026`, `TestPass2026`.

**Validates: Requirements 8.1, 8.3**

---

### Property 8: Stage Files Use settings.py as Primary Credential Source

*For any* credential string read in `ingest.py`, `analyze.py`, `assess.py`, or `store.py`, the primary source should be `settings.py` (via the try/except import pattern), with `os.environ.get()` as the secondary fallback and a hardcoded default only as the tertiary fallback.

**Validates: Requirements 8.2**

---

### Property 9: REDIS_URL Default Password Is Consistent Across All Stage Files

*For any* stage file in `worker/stages/` that defines a `REDIS_URL` default value, the password component of that URL should be `hydra-redis-dev-2026`.

**Validates: Requirements 5.1, 12.4**

---

### Property 10: Migration Sequence Has No Undocumented Gaps

*For any* two consecutive migration file prefixes in `migrations/`, the numeric difference should be exactly 1, unless the gap falls within the allowlisted range `{056, 057, 058}`.

**Validates: Requirements 11.1**

---

### Property 11: Tables Referenced in store.py Have Creation Migrations

*For any* table name appearing in a SQL query in `worker/stages/store.py`, a `CREATE TABLE` statement for that table should exist in at least one file in `migrations/`.

**Validates: Requirements 11.4**

---

### Property 12: os.environ.get() Calls in worker/ Have settings.py Entries

*For any* `os.environ.get()` or `os.getenv()` call in `worker/` (excluding test files), the environment variable name should correspond to a field in `ZovarkSettings` (after stripping the `ZOVARK_` prefix).

**Validates: Requirements 12.1**

---

## Error Handling

The audit itself is a read-only analysis. Error handling applies to the findings it produces:

- **File not found:** If a file referenced in a requirement does not exist (e.g., `worker/stages/skills/`), the finding is recorded as "path does not exist — requirement not applicable."
- **Ambiguous findings:** If a pattern is present but context is unclear (e.g., a handler function that is internal by convention), the finding is recorded as INFO severity with a note.
- **False positives:** Credential strings in test fixtures are excluded from Property 7 by explicit allowlist.
- **Migration gap allowlist:** The 056-058 gap is documented and allowlisted; it does not generate a finding.

---

## Testing Strategy

This audit spec produces findings, not production code changes. The testing strategy applies to the audit tasks themselves.

### Unit Tests (Example-Based)

Each concrete finding (BUG-*, SEC-*, DEAD-*, CONFIG-*, SCHEMA-*) is verified by reading the specific file and line range cited. These are example-based checks:

- Read `api/auth.go:220-265` → confirm `refreshHandler` has no DB query for user existence
- Read `worker/nats_consumer.py:333-340` → confirm `subscribe()` called without handler argument
- Read `worker/stages/store.py:22` → confirm wrong Redis password in default
- Read `api/main.go:43` → confirm wrong DB password in default
- Read `worker/settings.py:28` → confirm `llm_key` is `str` not `SecretStr`
- Read `api/middleware.go:55-95` → confirm no `claims.Subject` check

### Property-Based Tests

The 12 correctness properties above are suitable for automated verification using:

- **Python:** `hypothesis` library for property-based testing
- **Go:** `testing/quick` or `gopbt` for Go-side properties

Each property test should run a minimum of 100 iterations over generated inputs (file lists, function name lists, SQL query strings, migration prefix sequences).

**Tag format:** `Feature: codebase-execution-audit, Property {N}: {property_text}`

**Property test configuration:**
- Properties 1, 2, 6, 7, 10: Can be implemented as deterministic enumeration tests (no randomization needed — the input set is finite and known)
- Properties 3, 4, 5, 8, 9, 11, 12: Enumeration over source files with assertion checks

### Integration Tests

Not applicable — this is a static analysis audit, not a runtime feature.

### Dual Testing Approach

- Unit/example tests: verify each specific finding with a direct file read
- Property tests: verify universal invariants hold across all instances of a pattern (all handlers, all activities, all stage files, all migrations)
- Together: example tests catch the specific bugs already found; property tests ensure no additional instances of the same pattern exist elsewhere in the codebase
