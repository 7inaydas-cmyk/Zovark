# Function Index: The 100 Most Important Functions

An alphabetical reference of the functions that make Zovark work. For each: where it lives, what it does in one sentence, who calls it, and what it calls.

---

## Functions by Concept

### Pipeline Stages (6 entry points)
- `ingest_alert` (worker/stages/ingest.py) — Stage 1: sanitize, dedup, skill match
- `analyze_alert` (worker/stages/analyze.py) — Stage 2: pick plan or ask LLM
- `execute_investigation` (worker/stages/execute.py) — Stage 3: run tools
- `assess_results` (worker/stages/assess.py) — Stage 4: verdict + IOCs
- `apply_governance` (worker/stages/govern.py) — Stage 4.5: autonomy check
- `store_investigation` (worker/stages/store.py) — Stage 5: persist everything

### Burst Protection (3 layers)
- `checkPreDedup` (api/alert_dedup.go) — Layer 1: Redis exact-hash dedup
- `tryBatchAlert` (api/batch_buffer.go) — Layer 2: Lua-atomic batch grouping
- `checkBackpressure` (api/backpressure.go) — Layer 3: workflow queue depth throttle
- `registerPreDedup` (api/alert_dedup.go) — Register hash after commit
- `clearDedupEntry` (api/alert_dedup.go) — Force reinvestigate bypass

### Tool Execution Engine
- `execute_plan` (worker/tools/runner.py) — Main tool dispatch loop
- `_run_single_step` (worker/tools/runner.py) — Execute one tool with timeout
- `_resolve_args` / `_resolve_ref` (worker/tools/runner.py) — $stepN variable resolution
- `_evaluate_condition` (worker/tools/runner.py) — Conditional branching (no eval)
- `_build_dependency_graph` (worker/tools/runner.py) — DAG for parallel execution
- `_topological_batches` (worker/tools/runner.py) — Parallel batch ordering

### Entity Graph
- `persist_entities` (worker/intelligence/entity_graph.py) — UPSERT IOC nodes
- `persist_edges` (worker/intelligence/entity_graph.py) — UPSERT relationships
- `persist_cross_tenant` (worker/intelligence/entity_graph.py) — Anonymous shared intelligence
- `infer_relationships` (worker/intelligence/entity_graph.py) — Derive edges from SIEM fields
- `listEntitiesHandler` / `getEntityHandler` / `entityGraphHandler` / `searchEntitiesHandler` / `entityStatsHandler` (api/entity_handlers.go) — 5 REST endpoints

### LLM / Inference
- `llm_call` (worker/stages/llm_gateway.py) — Central LLM dispatch with dual endpoints
- `llm_request` (worker/llm_client.py) — Singleton httpx client with semaphores
- `_scrub_code` (worker/stages/analyze.py) — Strip LLM prose and control tokens
- `_parse_tool_plan` (worker/stages/analyze.py) — Validate LLM tool selection output

### SIEM Connectors
- `createTaskHandler` (api/task_handlers.go) — POST /tasks direct submission
- `splunkIngestHandler` (api/siem_ingest.go) — Splunk HEC format
- `elasticIngestHandler` (api/siem_ingest.go) — Elastic SIEM webhook
- `createIngestTask` (api/siem_ingest.go) — Shared task creation logic
- `mapAlertToTaskType` (api/siem_ingest.go) — Regex-based alert classification

### Intelligence Layer
- `explain` / `suggest` / `correlate` / `brief` (worker/intelligence/copilot.py) — Analyst assistant
- `suggest_actions` (worker/intelligence/remediation.py) — Deterministic remediation rules
- `verify_license` (worker/bundles/license.py) — Ed25519 signature check

### Security / Input Validation
- `sanitize_siem_event` (worker/stages/input_sanitizer.py) — 25 injection patterns
- `_has_attack_indicators` (worker/stages/ingest.py) — 40 keyword attack check
- `_has_raw_log_attack_content` (worker/stages/ingest.py) — 70 regex content scanner
- `validate_investigation_output` (worker/stages/output_validator.py) — Pydantic schema check
- `_extract_iocs_from_signals` (worker/stages/assess.py) — Regex IOC extraction

### Scoring / Verdict
- `_derive_verdict` (worker/stages/assess.py) — Risk thresholds → verdict string
- `_severity_from_risk` (worker/stages/assess.py) — Risk → critical/high/medium/low
- `_generate_plain_english` (worker/stages/assess.py) — Template summary for analysts
- `_fp_confidence` (worker/stages/assess.py) — False positive probability

### Dashboard / SSE
- `handleForgeStart` / `handleForgeStream` (api/forge_handlers.go) — Alert forge
- `handlePipelineStatus` (api/zvadmin_handlers.go) — Real-time pipeline metrics
- `handleAnalyticsSummary` (api/analytics_handlers.go) — Verdict/risk aggregation
- `streamAllTaskUpdates` (api/sse.go) — SSE event stream

---

## Alphabetical Index

---

## Go API Functions (api/)

### beginTenantTx
**File:** `api/db.go`
**Purpose:** Starts a PostgreSQL transaction with the tenant context set for Row Level Security.
**Called by:** Any handler that writes tenant-scoped data (task handlers, entity handlers, promotion handlers).
**Calls:** `dbPool.BeginTx`, then executes `SET LOCAL app.current_tenant`.

### checkBackpressure
**File:** `api/backpressure.go`
**Purpose:** Layer 3 burst protection -- checks if the system has too many active workflows and either queues or rejects the alert.
**Called by:** `createTaskHandler`, `createIngestTask`.
**Calls:** Redis sorted set operations to count active workflows; returns a boolean (proceed or reject) and queue depth.

### checkPreDedup
**File:** `api/alert_dedup.go`
**Purpose:** Layer 1 burst protection -- computes a SHA-256 fingerprint of the alert and checks Redis for duplicates, with awareness of prior investigation status.
**Called by:** `createIngestTask`.
**Calls:** `computeAlertHash`, Redis GET; checks if prior investigation failed (allows retry) or if severity escalated (allows new investigation).

### computeAlertHash
**File:** `api/alert_dedup.go`
**Purpose:** Computes a SHA-256 hash of 6 canonical alert fields with timestamps normalized, producing the same hash as the Python worker's `_compute_alert_hash`.
**Called by:** `checkPreDedup`.
**Calls:** `normalizeRawLog`, `sha256.Sum256`.

### createIngestTask
**File:** `api/siem_ingest.go`
**Purpose:** Shared task-creation logic for all SIEM ingest endpoints -- runs all 3 burst protection layers, inserts the task record, and starts the Temporal workflow.
**Called by:** `splunkIngestHandler`, `elasticIngestHandler`.
**Calls:** `checkPreDedup`, `tryBatchAlert`, `checkBackpressure`, `dbPool.Exec` (INSERT), `temporalClient.ExecuteWorkflow`.

### createTaskHandler
**File:** `api/task_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/tasks -- the primary alert intake endpoint for analysts and automation.
**Called by:** Gin router (registered in `main.go`).
**Calls:** Playbook resolution query, fingerprint dedup (DB-level), `checkBackpressure`, `dbPool.Exec` (INSERT), `temporalClient.ExecuteWorkflow`.

### elasticIngestHandler
**File:** `api/siem_ingest.go`
**Purpose:** HTTP handler for POST /api/v1/ingest/elastic -- accepts Elastic SIEM webhook alerts and normalizes them to Zovark's format.
**Called by:** Gin router.
**Calls:** `mapAlertToTaskType`, `createIngestTask`.

### entityGraphHandler
**File:** `api/entity_handlers.go`
**Purpose:** Returns the subgraph of entities and edges connected to a specific entity, for visualization in the dashboard.
**Called by:** Gin router (GET /api/v1/entities/:id/graph).
**Calls:** PostgreSQL queries joining `entities` and `entity_edges` tables with tenant filtering.

### entityStatsHandler
**File:** `api/entity_handlers.go`
**Purpose:** Returns aggregate statistics about the entity graph -- total entities, top threat scores, type distribution.
**Called by:** Gin router (GET /api/v1/entities/stats).
**Calls:** PostgreSQL aggregate queries on the `entities` table.

### getEntityHandler
**File:** `api/entity_handlers.go`
**Purpose:** Returns full details for a single entity including all edges and investigation history.
**Called by:** Gin router (GET /api/v1/entities/:id).
**Calls:** PostgreSQL query on `entities` table with tenant filter.

### getTaskHandler
**File:** `api/task_handlers.go`
**Purpose:** HTTP handler for GET /api/v1/tasks/:id -- returns full task details including verdict, risk score, IOCs, and investigation output.
**Called by:** Gin router.
**Calls:** PostgreSQL query on `agent_tasks` table.

### handleAnalyticsSummary
**File:** `api/zvadmin_handlers.go`
**Purpose:** Returns aggregated pipeline analytics -- verdict distribution, average risk by attack type, throughput metrics, time series data.
**Called by:** Gin router (GET /api/v1/analytics/summary).
**Calls:** Multiple PostgreSQL aggregate queries on `agent_tasks`.

### handleCopilotBrief
**File:** `api/copilot_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/copilot/brief -- generates a shift handoff summary for a given time window.
**Called by:** Gin router.
**Calls:** Python worker's `copilot.brief()` via Temporal activity.

### handleCopilotCorrelate
**File:** `api/copilot_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/copilot/correlate -- finds related investigations by shared entities (no LLM).
**Called by:** Gin router.
**Calls:** Python worker's `copilot.correlate()` via Temporal activity.

### handleCopilotExplain
**File:** `api/copilot_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/copilot/explain -- generates a natural language explanation of an investigation verdict.
**Called by:** Gin router.
**Calls:** Python worker's `copilot.explain()` via Temporal activity.

### handleCopilotSuggest
**File:** `api/copilot_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/copilot/suggest -- returns remediation suggestions with optional LLM narrative.
**Called by:** Gin router.
**Calls:** Python worker's `copilot.suggest()` via Temporal activity.

### handleForgeStart
**File:** `api/forge_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/forge/start -- begins an Alert Forge session that generates synthetic alerts for testing.
**Called by:** Gin router.
**Calls:** Creates task records and starts Temporal workflows for each synthetic alert.

### handleForgeStream
**File:** `api/forge_handlers.go`
**Purpose:** HTTP handler for GET /api/v1/forge/stream -- SSE endpoint streaming real-time results from an active Alert Forge session.
**Called by:** Gin router.
**Calls:** PostgreSQL LISTEN on `task_completed`, streams events as SSE.

### handleLicenseInstall
**File:** `api/license_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/license/install -- accepts a signed license payload and stores it in system_configs.
**Called by:** Gin router.
**Calls:** PostgreSQL INSERT/UPDATE on `system_configs` table.

### handleLicenseStatus
**File:** `api/license_handlers.go`
**Purpose:** HTTP handler for GET /api/v1/license/status -- returns current license tier, expiry, features, and grace period status.
**Called by:** Gin router.
**Calls:** PostgreSQL query on `system_configs` for license payload and public key.

### handleLicenseVerify
**File:** `api/license_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/license/verify -- verifies a license payload against the stored public key without installing it.
**Called by:** Gin router.
**Calls:** Python worker's `verify_license()` via Temporal activity.

### handlePipelineStatus
**File:** `api/zvadmin_handlers.go`
**Purpose:** Returns real-time pipeline status -- active workflows, stage distribution, throughput, error rates, LLM circuit breaker state.
**Called by:** Gin router (GET /api/v1/pipeline/status).
**Calls:** Redis queries for workflow counts, PostgreSQL queries for stage metrics.

### listEntitiesHandler
**File:** `api/entity_handlers.go`
**Purpose:** HTTP handler for GET /api/v1/entities -- returns paginated list of entities with filtering by type, threat score, and date range.
**Called by:** Gin router.
**Calls:** PostgreSQL query on `entities` table with tenant filter and pagination.

### listTasksHandler
**File:** `api/task_handlers.go`
**Purpose:** HTTP handler for GET /api/v1/tasks -- returns paginated list of investigations with verdict, risk score, path taken, and execution mode.
**Called by:** Gin router.
**Calls:** PostgreSQL query on `agent_tasks` table with sorting and pagination.

### mapAlertToTaskType
**File:** `api/siem_ingest.go`
**Purpose:** Maps a SIEM alert signature/rule name to a Zovark task type using regex patterns (e.g., "brute.?force" maps to "brute_force").
**Called by:** `splunkIngestHandler`, `elasticIngestHandler`.
**Calls:** `regexp.MatchString` against 11 pattern groups.

### normalizeRawLog
**File:** `api/alert_dedup.go`
**Purpose:** Strips timestamps from raw log text so that two alerts differing only in timestamp produce the same dedup hash.
**Called by:** `computeAlertHash`.
**Calls:** Regex replace with 3 timestamp patterns.

### respondInternalError
**File:** `api/errors.go`
**Purpose:** Returns a generic 500 error to the client without exposing the actual Go error message -- prevents information leakage.
**Called by:** Every handler that catches an internal error.
**Calls:** `gin.Context.JSON` with a safe error message; logs the real error server-side.

### searchEntitiesHandler
**File:** `api/entity_handlers.go`
**Purpose:** Full-text search across entity values -- find all entities matching a partial IP, domain, or username.
**Called by:** Gin router (GET /api/v1/entities/search).
**Calls:** PostgreSQL LIKE query on `entities.value`.

### splunkIngestHandler
**File:** `api/siem_ingest.go`
**Purpose:** HTTP handler for POST /api/v1/ingest/splunk -- accepts Splunk HEC format alerts, extracts fields from the "event" object.
**Called by:** Gin router.
**Calls:** `mapAlertToTaskType`, `createIngestTask`.

### suggestRemediationHandler
**File:** `api/remediation_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/remediation/suggest -- returns deterministic remediation actions for an investigation.
**Called by:** Gin router.
**Calls:** Python worker's `suggest_actions()` via Temporal activity.

### tryBatchAlert
**File:** `api/batch_buffer.go`
**Purpose:** Layer 2 burst protection -- groups alerts by (task_type, source_ip) in a 5-second Redis window using an atomic Lua script, with severity promotion.
**Called by:** `createIngestTask`.
**Calls:** Redis EVAL (Lua script) for atomic batch check-and-set.

### verifyRemediationHandler
**File:** `api/remediation_handlers.go`
**Purpose:** HTTP handler for POST /api/v1/remediation/verify -- submits a synthetic alert to verify that a remediation action was effective.
**Called by:** Gin router.
**Calls:** Creates a synthetic task and checks if the pipeline produces a different verdict post-remediation.

---

## Python Worker Functions (worker/)

### analyze_alert
**File:** `worker/stages/analyze.py`
**Purpose:** Stage 2 entry point -- decides how to investigate by routing to Path A (saved plan), Path B (template), or Path C (LLM tool selection).
**Called by:** `InvestigationWorkflowV2.run` (via Temporal activity).
**Calls:** `_analyze_v3_tools` (V3 mode) or `_analyze_template`/`_analyze_llm` (V2 mode).

### _analyze_v3_tools
**File:** `worker/stages/analyze.py`
**Purpose:** V3 routing logic -- tries 5 plan lookups (skill plan, exact match, alias, substring, benign), falls back to LLM Path C if all fail.
**Called by:** `analyze_alert`.
**Calls:** DB queries for saved plans, `_load_institutional_knowledge`, `_load_correlation_context`, `llm_call`, `_parse_tool_plan`, `get_catalog_text`.

### _analyze_template
**File:** `worker/stages/analyze.py`
**Purpose:** Path B -- renders a skill template with parameters filled by LLM or fast-fill regex mapping.
**Called by:** `analyze_alert` (V2 mode when skill_template exists).
**Calls:** `_fill_parameters_fast` or `_fill_parameters_llm`, `_render_template`, `preflight_check`.

### _analyze_llm
**File:** `worker/stages/analyze.py`
**Purpose:** Path C (V2 mode) -- full LLM code generation for novel attacks when no template exists.
**Called by:** `analyze_alert` (V2 mode, no template).
**Calls:** `_wrap_siem`, `llm_call`, `_scrub_code`, `preflight_check`, `get_cached_code`/`set_cached_code`.

### apply_governance
**File:** `worker/stages/govern.py`
**Purpose:** Stage 4.5 entry point -- queries governance config and applies the autonomy level to determine if human review is needed.
**Called by:** `InvestigationWorkflowV2.run` (via Temporal activity).
**Calls:** `_get_governance_config` (DB query).

### assess_results
**File:** `worker/stages/assess.py`
**Purpose:** Stage 4 entry point -- validates tool output, extracts IOCs, applies signal boost and suppression detection, derives verdict, generates summary.
**Called by:** `InvestigationWorkflowV2.run` (via Temporal activity).
**Calls:** `validate_investigation_output`, `_extract_iocs_from_signals`, `_derive_verdict`, `_severity_from_risk`, `_fp_confidence`, `get_mitre_techniques`, `_generate_plain_english`, `_llm_summary`, `_has_attack_indicators`.

### brief
**File:** `worker/intelligence/copilot.py`
**Purpose:** Copilot operation -- generates a shift handoff summary for a given time window (hours), with LLM narrative and fallback template.
**Called by:** `handleCopilotBrief` (via Temporal).
**Calls:** `_query` (SQL aggregates), `_copilot_llm_call`, `_brief_fallback`.

### _build_dependency_graph
**File:** `worker/tools/runner.py`
**Purpose:** Parses $stepN references in a plan to build a dependency DAG for parallel tool execution.
**Called by:** `execute_plan` (when parallel execution is enabled).
**Calls:** Regex matching on `$step(\d+)` patterns.

### calculate_entropy
**File:** `worker/tools/analysis.py`
**Purpose:** Calculates Shannon entropy of a string -- higher entropy means more randomness, which can indicate DGA domains or encoded payloads.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Standard library math.log2.

### check_base64
**File:** `worker/tools/analysis.py`
**Purpose:** Finds and decodes base64-encoded strings in text, returning the decoded content.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** `base64.b64decode`.

### _check_tenant_tier
**File:** `worker/stages/analyze.py`
**Purpose:** Checks whether the tenant has a premium license tier by querying installed_bundles -- fail-closed (DB error = deny premium).
**Called by:** `_analyze_v3_tools` (when a plan requires premium tier).
**Calls:** PostgreSQL query on `installed_bundles` table.

### _compute_alert_hash
**File:** `worker/stages/ingest.py`
**Purpose:** Computes SHA-256 of 6 canonical alert fields with timestamps normalized -- must match the Go API's `computeAlertHash` exactly.
**Called by:** `_check_exact_dedup`, `_register_dedup`.
**Calls:** `_normalize_raw_log`, `hashlib.sha256`.

### _copilot_llm_call
**File:** `worker/intelligence/copilot.py`
**Purpose:** Makes an LLM call with the copilot's dedicated Semaphore(1) -- ensures copilot never uses more than 1 concurrent LLM call.
**Called by:** `explain`, `suggest`, `brief`.
**Calls:** `llm_request` (from `llm_client.py`) with the CODE model.

### correlate
**File:** `worker/intelligence/copilot.py`
**Purpose:** Copilot operation -- finds related investigations by shared source_ip, username, or task_type in the last 7 days. No LLM needed.
**Called by:** `handleCopilotCorrelate` (via Temporal).
**Calls:** `_query` (SQL joins on `agent_tasks` and `attack_paths`).

### correlate_with_history
**File:** `worker/tools/enrichment.py`
**Purpose:** Checks if IOC values appeared in recent investigations by querying the entity graph, returning risk modifiers and prior verdicts.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Searches `history_context` dict pre-loaded by `_load_correlation_context`.

### count_pattern
**File:** `worker/tools/analysis.py`
**Purpose:** Counts regex pattern matches in text -- for example, counting "Failed password" occurrences to quantify brute force intensity.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** `re.findall`.

### _create_investigation
**File:** `worker/stages/store.py`
**Purpose:** Inserts a row into the investigations table with verdict, risk score, confidence, and summary -- uses synchronous_commit for durability.
**Called by:** `store_investigation`.
**Calls:** PostgreSQL INSERT with synchronous_commit.

### _derive_verdict (assess)
**File:** `worker/stages/assess.py`
**Purpose:** Maps risk score, IOC count, and finding count to a verdict string -- the authoritative verdict derivation that considers execution mode.
**Called by:** `assess_results`.
**Calls:** Pure logic (no external calls).

### _derive_verdict (runner)
**File:** `worker/tools/runner.py`
**Purpose:** Preliminary verdict derivation within the tool runner -- provides an initial verdict before the assess stage refines it.
**Called by:** `execute_plan`.
**Calls:** Pure logic.

### detect_appcert_dlls
**File:** `worker/tools/detection.py`
**Purpose:** Detects AppCert DLLs persistence (T1546.009) by scanning for registry modifications to the AppCertDlls key.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex and keyword scanning on siem_event fields.

### detect_c2
**File:** `worker/tools/detection.py`
**Purpose:** Detects C2 communication by analyzing beacon intervals, DGA domain entropy, and encoded payloads.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** `calculate_entropy` (internally), regex pattern matching.

### detect_com_hijacking
**File:** `worker/tools/detection.py`
**Purpose:** Detects COM object hijacking (T1546.015) via suspicious registry modifications to CLSID/InprocServer32 keys.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex scanning on registry path patterns.

### detect_data_exfil
**File:** `worker/tools/detection.py`
**Purpose:** Detects data exfiltration by checking transfer volumes, off-hours activity, cloud storage destinations, and encoding usage.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Field extraction and threshold checks on siem_event.

### detect_dns_exfiltration
**File:** `worker/tools/detection.py`
**Purpose:** Detects DNS exfiltration by measuring subdomain entropy, TXT record abuse, and query volume anomalies.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Shannon entropy calculation, regex on DNS query patterns.

### detect_encoded_service
**File:** `worker/tools/detection.py`
**Purpose:** Detects malicious Windows services with base64-encoded PowerShell commands in their service paths (T1543.003).
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Base64 detection and command-line pattern matching.

### detect_golden_ticket
**File:** `worker/tools/detection.py`
**Purpose:** Detects Golden Ticket attacks by checking for forged TGTs with abnormal lifetimes and RC4 encryption on krbtgt.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Kerberos ticket attribute analysis.

### detect_kerberoasting
**File:** `worker/tools/detection.py`
**Purpose:** Detects Kerberoasting (T1558.003) by identifying RC4-encrypted TGS requests for non-krbtgt service principal names.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Encryption type and SPN analysis on siem_event.

### detect_lolbin_abuse
**File:** `worker/tools/detection.py`
**Purpose:** Detects Living Off the Land Binary abuse -- certutil downloading files, mshta running scripts, bitsadmin transferring payloads.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Command-line pattern matching against known LOLBin signatures.

### detect_phishing
**File:** `worker/tools/detection.py`
**Purpose:** Detects phishing by analyzing suspicious URLs, credential harvesting forms, urgency language, and typosquatted domains.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** URL and domain analysis, keyword matching.

### detect_ransomware
**File:** `worker/tools/detection.py`
**Purpose:** Detects ransomware by checking for shadow copy deletion (vssadmin), mass file encryption patterns, and ransom note indicators.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Process command-line and file extension analysis.

### detect_token_impersonation
**File:** `worker/tools/detection.py`
**Purpose:** Detects token impersonation (T1134.001) by identifying RunAs with saved credentials and privilege elevation patterns.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Authentication event pattern matching.

### _evaluate_condition
**File:** `worker/tools/runner.py`
**Purpose:** Evaluates conditional branching expressions (like "$step2.count > 100") without using eval() -- supports numeric comparisons and boolean checks.
**Called by:** `_run_single_step` (when a plan step has a "condition" field).
**Calls:** `_resolve_ref`.

### execute_plan
**File:** `worker/tools/runner.py`
**Purpose:** The engine room -- runs an investigation plan step by step, resolving variables, dispatching tools, aggregating results, with optional parallel execution.
**Called by:** `execute_investigation` (worker/stages/execute.py).
**Calls:** `_run_single_step` for each step, `_build_dependency_graph` and `_topological_batches` (parallel mode), `_derive_verdict`.

### explain
**File:** `worker/intelligence/copilot.py`
**Purpose:** Copilot operation -- generates a natural language explanation of why an investigation received its verdict, with LLM and template fallback.
**Called by:** `handleCopilotExplain` (via Temporal).
**Calls:** `_get_investigation`, `_copilot_llm_call`, `_explain_fallback`.

### extract_cves
**File:** `worker/tools/extraction.py`
**Purpose:** Extracts CVE identifiers (CVE-YYYY-NNNNN) from text with evidence_refs.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex matching.

### extract_domains
**File:** `worker/tools/extraction.py`
**Purpose:** Extracts domain names from text with TLD validation to avoid false positives.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex matching with TLD whitelist.

### extract_emails
**File:** `worker/tools/extraction.py`
**Purpose:** Extracts email addresses from text with evidence_refs.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex matching.

### extract_hashes
**File:** `worker/tools/extraction.py`
**Purpose:** Extracts MD5 (32-char), SHA1 (40-char), and SHA256 (64-char) file hashes from text.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex matching with length validation.

### extract_ipv4
**File:** `worker/tools/extraction.py`
**Purpose:** Extracts IPv4 addresses from text with evidence_refs (log snippets showing where each IP was found).
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex matching, IP validation (excludes loopback, broadcast).

### extract_ipv6
**File:** `worker/tools/extraction.py`
**Purpose:** Extracts IPv6 addresses from text.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex matching.

### _extract_iocs_from_signals
**File:** `worker/stages/assess.py`
**Purpose:** Comprehensive IOC extraction from SIEM data and tool output -- pulls IPs, URLs, emails, hashes, domains, CVEs with evidence_refs.
**Called by:** `assess_results`.
**Calls:** Regex matching, `_is_valid_ioc_ip`, `_snippet_around`, `_raw_text_evidence`.

### extract_urls
**File:** `worker/tools/extraction.py`
**Purpose:** Extracts full URLs (http/https/ftp) from text.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex matching.

### extract_usernames
**File:** `worker/tools/extraction.py`
**Purpose:** Extracts usernames from SIEM log patterns like "Failed password for root" or "User=admin".
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Regex matching against common log username patterns.

### fetch_task
**File:** `worker/stages/ingest.py`
**Purpose:** Loads the full task record from the agent_tasks table -- the workflow needs this because Temporal only passes the task ID.
**Called by:** `InvestigationWorkflowV2.run` (as a Temporal activity).
**Calls:** PostgreSQL SELECT on `agent_tasks`.

### _fill_parameters_fast
**File:** `worker/stages/analyze.py`
**Purpose:** Path B fast-fill -- maps SIEM event fields directly to template parameters without calling the LLM.
**Called by:** `_analyze_template` (when FAST_FILL=true or as fallback).
**Calls:** Direct dict lookups on siem_event.

### _fill_parameters_llm
**File:** `worker/stages/analyze.py`
**Purpose:** Path B LLM fill -- asks the FAST model to extract parameter values from the alert text and SIEM event.
**Called by:** `_analyze_template`.
**Calls:** `llm_call` with TIER_FILL config, `_wrap_siem`.

### _fp_confidence
**File:** `worker/stages/assess.py`
**Purpose:** Rule-based false positive confidence score -- higher means more likely false positive, used for analyst prioritization.
**Called by:** `assess_results`.
**Calls:** Pure logic based on risk_score and ioc_count.

### _generate_plain_english
**File:** `worker/stages/assess.py`
**Purpose:** Writes a deterministic bullet-point summary for L1 analysts -- no LLM needed, covers verdict, findings, IOCs, risk, MITRE, and affected user.
**Called by:** `assess_results`.
**Calls:** Pure string formatting.

### get_catalog_text
**File:** `worker/tools/catalog.py`
**Purpose:** Formats the full 40-tool catalog as text for injection into the LLM prompt during Path C tool selection.
**Called by:** `_analyze_v3_tools`.
**Calls:** Iterates TOOL_CATALOG dict.

### _has_attack_indicators
**File:** `worker/stages/ingest.py`
**Purpose:** Checks if a task_type, rule_name, or title contains any of 40 attack-related keywords -- used for inverted benign routing and risk floor logic.
**Called by:** `ingest_alert` (benign routing decision), `assess_results` (risk floor).
**Calls:** String matching against ATTACK_INDICATORS list.

### _has_raw_log_attack_content
**File:** `worker/stages/ingest.py`
**Purpose:** Scans raw log text against 70 high-confidence attack patterns -- overrides benign routing when real attacks hide behind benign metadata.
**Called by:** `ingest_alert` (classification override check).
**Calls:** Regex matching against RAW_LOG_ATTACK_PATTERNS, including caret-deobfuscated version.

### infer_relationships
**File:** `worker/intelligence/entity_graph.py`
**Purpose:** Deterministically creates entity relationship edges from SIEM event context -- source_ip communicates_with dest_ip, source_ip logged_into username.
**Called by:** `store_investigation`.
**Calls:** SIEM event field extraction, IOC value matching.

### ingest_alert
**File:** `worker/stages/ingest.py`
**Purpose:** Stage 1 entry point -- sanitizes, normalizes, deduplicates, masks PII, retrieves skill template, and applies content-based routing override.
**Called by:** `InvestigationWorkflowV2.run` (via Temporal activity).
**Calls:** `sanitize_siem_event`, `normalize_siem_event`, `_check_exact_dedup`, `_register_dedup`, `_mask_pii`, `_retrieve_skill`, `_has_raw_log_attack_content`.

### _insert_audit_event
**File:** `worker/stages/store.py`
**Purpose:** Inserts a row into the audit_events table -- required for compliance (CMMC, HIPAA) with trace_id for request tracing.
**Called by:** `store_investigation` (twice: investigation_started and investigation_completed).
**Calls:** PostgreSQL INSERT.

### llm_call
**File:** `worker/stages/llm_gateway.py`
**Purpose:** The single gateway for all pipeline LLM calls -- routes to the correct endpoint (FAST/CODE), logs audit metadata, supports GBNF grammar constraints.
**Called by:** `_fill_parameters_llm`, `_analyze_llm`, `_llm_summary`, `_analyze_v3_tools` (Path C).
**Calls:** `httpx.AsyncClient.post` to llama-server, audit logging to `llm_audit_log` table.

### _llm_summary
**File:** `worker/stages/assess.py`
**Purpose:** Optional LLM-generated 2-3 sentence investigation summary using the CODE model with prefix-cached system prompt.
**Called by:** `assess_results`.
**Calls:** `llm_call` with CODE model config.

### _load_correlation_context
**File:** `worker/stages/analyze.py`
**Purpose:** Queries recent investigations (last 24h) with overlapping IOCs to provide correlation context for tool selection.
**Called by:** `_analyze_v3_tools`.
**Calls:** PostgreSQL query on `agent_tasks` matching source_ip and username.

### _load_institutional_knowledge
**File:** `worker/stages/analyze.py`
**Purpose:** Loads analyst-provided baselines for entities in the alert (e.g., "10.0.0.5 is the dev server, expect SSH from it during business hours").
**Called by:** `_analyze_v3_tools`.
**Calls:** PostgreSQL query on `institutional_knowledge` table.

### lookup_institutional_knowledge
**File:** `worker/tools/enrichment.py`
**Purpose:** Tool-level function that checks entities against the analyst-provided knowledge base during plan execution.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Dict lookup on pre-loaded knowledge_base.

### lookup_known_bad
**File:** `worker/tools/enrichment.py`
**Purpose:** Checks an IOC value against the local known-bad list (threat intel feeds, prior confirmed attacks).
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Dict/set lookup.

### map_mitre
**File:** `worker/tools/enrichment.py`
**Purpose:** Maps MITRE ATT&CK technique IDs (like T1110) to human-readable names and tactic categories.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Lookup in MITRE technique dictionary.

### normalize_siem_event
**File:** `worker/stages/normalizer.py`
**Purpose:** Maps vendor-specific field names to Zovark standard names across 70+ field mappings (Splunk, Elastic, firewall formats).
**Called by:** `ingest_alert`.
**Calls:** Dict-based field remapping.

### parse_auth_log
**File:** `worker/tools/parsing.py`
**Purpose:** Parses Linux auth/syslog lines into structured fields: action (success/failure), username, source_ip, authentication method.
**Called by:** Tool runner during brute_force, privilege_escalation, credential_access plans.
**Calls:** Regex pattern matching on auth log format.

### parse_dns_query
**File:** `worker/tools/parsing.py`
**Purpose:** Parses DNS query logs into structured fields: query_name, query_type, source_ip, response_code.
**Called by:** Tool runner during dns_exfiltration, network_beaconing plans.
**Calls:** Regex pattern matching on DNS log format.

### parse_http_request
**File:** `worker/tools/parsing.py`
**Purpose:** Parses HTTP access logs into structured fields: method, path, status_code, source_ip, user_agent.
**Called by:** Tool runner during api_key_abuse plan.
**Calls:** Regex pattern matching on HTTP log format.

### parse_syslog
**File:** `worker/tools/parsing.py`
**Purpose:** Parses standard syslog format into structured fields: timestamp, hostname, facility, severity, message.
**Called by:** Tool runner when raw_log is in syslog format.
**Calls:** Regex pattern matching on RFC 3164/5424 syslog format.

### parse_windows_event
**File:** `worker/tools/parsing.py`
**Purpose:** Parses Windows Event Log key=value pairs into a structured dict. Includes 4KB parse guard to prevent ReDoS on large payloads.
**Called by:** Tool runner during ransomware, kerberoasting, golden_ticket, lateral_movement, and other Windows-focused plans.
**Calls:** Regex key=value extraction with size guard.

### detect_encoding
**File:** `worker/tools/analysis.py`
**Purpose:** Detects base64, hex, or URL encoding in text. Used to find obfuscated payloads in logs.
**Called by:** Tool runner during data_exfiltration_detection plan.
**Calls:** Regex pattern matching for encoding signatures.

### _parse_tool_plan
**File:** `worker/stages/analyze.py`
**Purpose:** Validates the LLM's JSON response for Path C -- checks tool names against TOOL_CATALOG, removes duplicates, caps at 10 tools.
**Called by:** `_analyze_v3_tools`.
**Calls:** `json.loads`, TOOL_CATALOG lookup.

### persist_cross_tenant
**File:** `worker/intelligence/entity_graph.py`
**Purpose:** UPSERTs privacy-preserving cross-tenant entity sightings -- only hashes are shared, with running averages of risk scores.
**Called by:** `store_investigation`.
**Calls:** PostgreSQL UPSERT on `cross_tenant_entities` with incremental statistics.

### persist_edges
**File:** `worker/intelligence/entity_graph.py`
**Purpose:** Writes relationship edges between entities (communicates_with, logged_into, executed) with investigation provenance.
**Called by:** `store_investigation`.
**Calls:** PostgreSQL INSERT on `entity_edges`.

### persist_entities
**File:** `worker/intelligence/entity_graph.py`
**Purpose:** UPSERTs IOCs as entity nodes in the knowledge graph -- increments observation_count and updates threat_score on conflict.
**Called by:** `store_investigation`.
**Calls:** PostgreSQL UPSERT on `entities` with ON CONFLICT DO UPDATE.

### _resolve_args
**File:** `worker/tools/runner.py`
**Purpose:** Resolves all variable references in a tool's arguments -- converts $raw_log, $siem_event.field, $stepN to actual values.
**Called by:** `_run_single_step`.
**Calls:** `_resolve_ref` for each argument value.

### _resolve_ref
**File:** `worker/tools/runner.py`
**Purpose:** Resolves a single variable reference like $raw_log, $siem_event.source_ip, $step2, or $step2.count to its actual value.
**Called by:** `_resolve_args`, `_evaluate_condition`.
**Calls:** Dict lookups on step_results, siem_event, or special variables.

### _run_single_step
**File:** `worker/tools/runner.py`
**Purpose:** Executes one step of an investigation plan -- handles conditional branching, argument resolution, tool dispatch, timeout enforcement, and result aggregation.
**Called by:** `execute_plan`.
**Calls:** `_evaluate_condition` (if conditional), `_resolve_args`, tool function from TOOL_CATALOG, `emit_event` (for SSE streaming).

### sanitize_siem_event
**File:** `worker/stages/input_sanitizer.py`
**Purpose:** Scrubs SIEM data for 25 injection patterns (template injection, code injection, SSTI), normalizes Unicode, strips zero-width characters, truncates at 10K chars.
**Called by:** `ingest_alert`.
**Calls:** Regex matching, Unicode normalization, Shannon entropy analysis.

### _save_pattern
**File:** `worker/stages/store.py`
**Purpose:** Saves the investigation pattern to investigation_memory -- what we found when investigating this task_type with this rule_name.
**Called by:** `store_investigation`.
**Calls:** PostgreSQL INSERT on `investigation_memory`.

### score_brute_force
**File:** `worker/tools/scoring.py`
**Purpose:** Calculates risk score for brute force attacks based on failed_count, unique_sources, and timespan_minutes.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Threshold-based scoring formula.

### score_c2_beacon
**File:** `worker/tools/scoring.py`
**Purpose:** Calculates risk score for C2 beaconing based on interval standard deviation, average interval, connection count, and domain entropy.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Statistical calculations.

### score_exfiltration
**File:** `worker/tools/scoring.py`
**Purpose:** Calculates risk score for data exfiltration based on bytes transferred, external destination, off-hours timing, and encryption usage.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Threshold-based scoring.

### score_generic
**File:** `worker/tools/scoring.py`
**Purpose:** Generic risk score based on indicator counts -- used when no attack-specific scoring tool applies.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Weighted sum of indicator counts.

### score_lateral_movement
**File:** `worker/tools/scoring.py`
**Purpose:** Calculates risk score for lateral movement based on method (PsExec/WMI), admin share access, remote execution, and pass-the-hash usage.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Binary signal aggregation.

### score_phishing
**File:** `worker/tools/scoring.py`
**Purpose:** Calculates risk score for phishing based on URL count, suspicious domain count, credential form presence, and urgency language.
**Called by:** `execute_plan` (via TOOL_CATALOG dispatch).
**Calls:** Weighted indicator aggregation.

### _scrub_code
**File:** `worker/stages/analyze.py`
**Purpose:** Post-generation cleanup of LLM output -- strips markdown fences, special tokens, prose wrapping, fixes common hallucinations, prepends mock requests shim.
**Called by:** `_analyze_llm`.
**Calls:** Regex replacements, line-by-line code boundary detection.

### store_investigation
**File:** `worker/stages/store.py`
**Purpose:** Stage 5 entry point -- persists all investigation artifacts to PostgreSQL, entity graph, and Redis dedup; fires NOTIFY for SSE.
**Called by:** `InvestigationWorkflowV2.run` (via Temporal activity).
**Calls:** `_update_task_status`, `_save_pattern`, `_create_investigation`, `_insert_audit_event` (x2), `persist_entities`, `infer_relationships`, `persist_edges`, `persist_cross_tenant`, NOTIFY task_completed, `_update_dedup_entry`.

### suggest
**File:** `worker/intelligence/copilot.py`
**Purpose:** Copilot operation -- returns remediation suggestions from the deterministic engine with optional LLM narrative context.
**Called by:** `handleCopilotSuggest` (via Temporal).
**Calls:** `_get_investigation`, `suggest_actions` (remediation engine), `_copilot_llm_call`.

### suggest_actions
**File:** `worker/intelligence/remediation.py`
**Purpose:** Returns deterministic remediation actions for 22 attack types -- circuit breaker limits (3/type/24h), rate limiter (10/hr), kill switch.
**Called by:** `copilot.suggest`, `suggestRemediationHandler`.
**Calls:** REMEDIATION_RULES dict lookup, circuit breaker and rate limiter checks.

### _update_dedup_entry
**File:** `worker/stages/store.py`
**Purpose:** Updates the Redis dedup entry with the final verdict and risk_score so the dedup layer knows whether the prior investigation succeeded.
**Called by:** `store_investigation`.
**Calls:** Redis GET/SETEX with recomputed alert hash.

### _update_task_status
**File:** `worker/stages/store.py`
**Purpose:** Updates agent_tasks with final status, output JSON, verdict, risk_score, path_taken, execution_mode -- uses synchronous_commit for durability.
**Called by:** `store_investigation`.
**Calls:** PostgreSQL UPDATE with synchronous_commit.

### verify_license
**File:** `worker/bundles/license.py`
**Purpose:** Verifies an Ed25519 signature on a license payload -- fail-closed (any error returns DENIED), checks expiry, grace period, and tier.
**Called by:** `handleLicenseVerify`, `handleLicenseStatus`.
**Calls:** `Ed25519PublicKey.verify` (cryptography library), JSON parsing, datetime comparison.
