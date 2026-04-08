# Zovark v3.3 — Complete Data Flow

> Traced from actual source code on 2026-04-07. Every field name, function, and file path is real.

## Typed Contracts (from `worker/stages/__init__.py`)

```python
@dataclass
class IngestOutput:
    task_id: str
    tenant_id: str
    task_type: str
    siem_event: Dict                    # sanitized + normalized
    prompt: str
    is_duplicate: bool
    duplicate_of: Optional[str]
    pii_masked: bool
    skill_id: Optional[str]             # UUID from agent_skills
    skill_template: Optional[str]       # code_template from agent_skills
    skill_params: List[Dict]            # template parameters
    skill_methodology: str

@dataclass
class AnalyzeOutput:
    code: str                           # v2: Python code
    plan: List[Dict]                    # v3: [{tool, args}, ...]
    source: "template"|"llm"|"saved_plan"|"llm_tool_call"|"fast_fill"
    path_taken: "A"|"B"|"C"|"benign"
    execution_mode: "sandbox"|"tools"
    skill_id: Optional[str]
    preflight_passed: bool
    tokens_in: int
    tokens_out: int
    generation_ms: int

@dataclass
class ExecuteOutput:
    stdout: str                         # JSON string of tool results
    stderr: str
    exit_code: int
    status: "completed"|"failed"|"timeout"
    iocs: List[Dict]
    findings: List[Dict]
    risk_score: int
    recommendations: List[str]
    execution_ms: int
    execution_mode: str

@dataclass
class AssessOutput:
    verdict: "true_positive"|"suspicious"|"benign"|"inconclusive"|...
    risk_score: int                     # 0-100
    severity: "critical"|"high"|"medium"|"low"|"informational"
    confidence: float
    entities: List[Dict]
    edges: List[Dict]
    recommendations: List[str]
    memory_summary: str

@dataclass
class StoreOutput:
    task_id: str
    status: "completed"|"failed"
    investigation_id: Optional[str]
    entities_stored: int
    edges_stored: int
    memory_saved: bool
    pattern_saved: bool
```

---

## Step-by-Step Data Flow

### SIEM Alert Ingestion

```
SIEM VENDOR ALERT (Splunk HEC / Elastic / Direct POST)
│
│ Splunk HEC format:                    Direct POST format:
│ {                                     {
│   "time": 1234567890,                   "task_type": "brute_force",
│   "event": {                            "input": {
│     "signature": "BruteForce",            "prompt": "SSH brute force",
│     "src_ip": "185.220.101.45",           "severity": "high",
│     "dest_ip": "10.0.1.50",              "siem_event": {
│     "user": "root",                         "title": "SSH BF",
│     "raw": "Failed password..."             "source_ip": "185.220.101.45",
│   },                                        "username": "root",
│   "sourcetype": "linux:syslog",             "rule_name": "BruteForce",
│   "host": "web01"                           "raw_log": "Failed password..."
│ }                                         }
│                                         }
│                                       }
▼
```

### Go API Layer (`api/task_handlers.go:39`, `api/siem_ingest.go:219`)

```
┌─────────────────────────────────────────────────────────┐
│ GO API: createTaskHandler / splunkIngestHandler          │
│                                                         │
│ 1. mapAlertToTaskType(signature) → task_type             │
│    (11 regex patterns, fallback: sanitized signature)    │
│                                                         │
│ 2. SHA-256 dedup fingerprint:                            │
│    hash(tenant_id|task_type|sorted(prompt,source_ip,     │
│         dest_ip))                                        │
│                                                         │
│ 3. Layer 1: checkPreDedup() → Redis exact hash           │
│    Layer 2: tryBatchAlert(task_type, source_ip, severity) │
│    Layer 3: checkBackpressure() → Temporal queue depth   │
│                                                         │
│ 4. INSERT INTO agent_tasks:                              │
│    (id, tenant_id, task_type, input, status='pending',   │
│     created_at, trace_id)                                │
│                                                         │
│ 5. tc.ExecuteWorkflow(workflowName, TaskRequest{         │
│       TaskType: task_type,                               │
│       Input: map[string]interface{} })                   │
└─────────────────────────────────┬───────────────────────┘
                                  │
                                  ▼ Temporal Queue
```

### Workflow Orchestrator (`worker/stages/investigation_workflow.py:27`)

```
┌─────────────────────────────────────────────────────────┐
│ WORKFLOW: InvestigationWorkflowV2                        │
│                                                         │
│ 1. fetch_task(task_id) → full_task dict from DB          │
│ 2. ingest_alert(full_task) → ingested                    │
│ 3. analyze_alert(ingested) → analyzed                    │
│ 4. execute_investigation({plan, siem_event, ...})        │
│        → executed                                       │
│ 5. assess_results({**executed, task_id, tenant_id,       │
│        task_type, siem_event, path_taken})               │
│        → assessed                                       │
│ 6. apply_governance({**assessed, tenant_id, task_type})  │
│        → governed                                       │
│ 7. store_investigation({**executed, **governed,           │
│        task_id, tenant_id, task_type, siem_event,        │
│        code, tokens_in/out, path_taken, trace_id,        │
│        execution_mode, plan_executed})                   │
│        → stored                                         │
└─────────────────────────────────────────────────────────┘
```

### Stage 1: INGEST (`worker/stages/ingest.py`)

```
INPUT: full_task dict from DB (agent_tasks row)
  {task_id, tenant_id, task_type, input: {prompt, severity, siem_event: {...}}}

TRANSFORMS:
  1. sanitize_siem_event() — 25 injection patterns, Unicode normalization,
     field truncation at 10K chars, Shannon entropy check
  2. normalize_siem_event() — 70+ field mappings (src_ip→source_ip, etc.)
  3. Redis dedup check (SHA-256 of 6 canonical fields, severity-based TTL)
  4. _has_attack_indicators() — checks 40 ATTACK_INDICATORS keywords
  5. _has_raw_log_attack_content() — scans 66 RAW_LOG_ATTACK_PATTERNS regexes
     with caret deobfuscation
  6. Skill retrieval from agent_skills table (by task_type match)

OUTPUT → IngestOutput:
  {task_id, tenant_id, task_type, siem_event: {sanitized+normalized},
   prompt, is_duplicate, skill_id, skill_template, skill_params,
   skill_methodology, pii_masked}
```

### Stage 2: ANALYZE (`worker/stages/analyze.py`)

```
INPUT: IngestOutput

DECISION TREE (ZOVARK_EXECUTION_MODE="tools"):
  1. Has skill_id with investigation_plan in agent_skills?
       → YES: Load plan from DB → Path A (saved_plan, ~5ms, 0 tokens)
  2. Match task_type in investigation_plans.json?
     (exact → alias via _PLAN_ALIASES → substring → benign fallback)
       → YES: Load file plan → Path A (saved_plan, ~5ms, 0 tokens)
  3. Tier enforcement: plan.tier == "premium"?
       → _check_tenant_tier(tenant_id, "premium")
         queries installed_bundles for non-rolled-back premium bundle
  4. ZOVARK_MODE == "templates-only"?
       → Return empty plan, path="error_no_plan"
  5. No saved plan found → LLM tool selection (Path C):
     a. Load pruned tool catalog (get_subset_catalog_text)
     b. Load institutional knowledge (DB: institutional_knowledge table)
     c. Load correlation context (DB: agent_tasks with overlapping IOCs)
     d. Build system prompt: _TOOL_CALLING_SYSTEM_PREFIX + catalog_text
     e. Build user prompt: institutional_knowledge + siem_event JSON
     f. llm_call(TIER_FILL=FAST model, grammar="tool_selection",
                 timeout=120s)
     g. _parse_tool_plan(): validate against TOOL_CATALOG,
        dedup, cap at 10 tools

OUTPUT → AnalyzeOutput:
  Path A: {plan: [{tool, args}, ...], source: "saved_plan",
           path_taken: "A", execution_mode: "tools", generation_ms: <5}
  Path C: {plan: [{tool, args}, ...], source: "llm_tool_call",
           path_taken: "C", execution_mode: "tools",
           tokens_in, tokens_out, generation_ms}
```

### Stage 3: EXECUTE (`worker/tools/runner.py`)

```
INPUT: {plan: [{tool, args}, ...], siem_event, task_type,
        tenant_id, execution_mode: "tools"}

TRANSFORMS:
  1. Load history_context = _load_correlation_context(tenant_id, siem_event)
  2. Load institutional_knowledge = _load_institutional_knowledge(...)
  3. Extract raw_log = siem_event.get("raw_log", "")
  4. For each step in plan:
     a. _resolve_args(args, step_results, siem_event, raw_log, ...)
        Variable resolution:
          $raw_log         → raw_log string
          $siem_event      → full dict
          $siem_event.field → siem_event["field"]
          $stepN           → result of step N
          $stepN.count     → len(step N result)
          $stepN.field     → step N result["field"]
          $correlation_context     → history_context dict
          $institutional_knowledge → institutional_knowledge dict
     b. Conditional branching:
        {"condition": "$step4 > 50",
         "if_true": {tool, args}, "if_false": {tool, args}}
        _evaluate_condition() — no eval(), regex-based comparison
     c. TOOL_CATALOG[tool_name](**resolved_args)
        Per-tool 5s timeout (signal.alarm), error isolation
     d. step_results[step_idx] = tool_output
  5. Aggregate: merge iocs, findings, risk_score from all tool outputs

OUTPUT (dict, serialized for Temporal):
  {stdout: JSON string of {findings, iocs, risk_score, verdict,
   tools_executed: int, tool_names: [...],
   tool_results: {1: ..., 2: ..., ...}, errors: []},
   iocs: [...], findings: [...], risk_score: int,
   execution_mode: "tools", status: "completed"}
```

### Stage 4: ASSESS (`worker/stages/assess.py`)

```
INPUT: {**executed, task_id, tenant_id, task_type, siem_event,
        path_taken, execution_mode}

TRANSFORMS:
  1. Parse stdout JSON (tool results)
  2. validate_investigation_output() — Pydantic: VerdictOutput,
     IOCItem validation. Invalid → safe_default_output(risk=50)
  3. _extract_iocs_from_signals(raw_log, siem_event):
     - Regex: IPv4, domains, hashes, emails, usernames, CVEs
     - _is_valid_ioc_ip() filter (no loopback/broadcast)
     - _snippet_around() for evidence context
     - Dedup by value
  4. Signal boost: 8 attack patterns (SQLi, XSS, path_traversal, etc.)
     → adds finding + boosts risk_score
  5. Suppression detection: 9 phrases ("scheduled test",
     "do not escalate") + attack indicator → risk boost to 75+
  6. IOC provenance validation: IOCs without raw_log backing →
     confidence=low
  7. _derive_verdict(risk_score, ioc_count, finding_count):
     risk <= 35 → benign
     risk >= 70 → true_positive
     risk >= 50 → suspicious
     risk >= 25 + findings → suspicious
     no iocs + no findings → benign
     else → inconclusive
  8. MITRE mapping: get_mitre_techniques(task_type, tool_results)
  9. Plain-English summary:
     - attack: "CONFIRMED ATTACK from {ip}, {finding}, {ioc_count} IOCs,
       risk {score}/100, MITRE: {techniques}, user: {username}"
     - benign: "Routine activity -- no threat detected"
  10. Optional LLM summary (CODE model, 200 tokens, 45s timeout)

OUTPUT → dict (flattened AssessOutput):
  {verdict, risk_score, severity, confidence,
   iocs: [{type, value, context, confidence, evidence_refs}],
   findings: [{title, details}],
   mitre_attack: [{id, name, tactic}],
   plain_english_summary, recommendations,
   memory_summary, model_used}
```

### Stage 4.5: GOVERN (`worker/stages/govern.py`)

```
INPUT: {**assessed, tenant_id, task_type}

TRANSFORMS:
  1. _get_governance_config(tenant_id, task_type)
     → DB: governance_config (specific task_type → wildcard '*' fallback)
  2. Apply autonomy level:
     observe    → needs_human_review = True (always)
     assist     → needs_human_review = (verdict != "benign")
     autonomous → needs_human_review = (verdict in
                    ["inconclusive", "needs_manual_review", "error"])

OUTPUT: same dict +
  {needs_human_review: bool, review_reason: str,
   autonomy_level: "observe"|"assist"|"autonomous"}
```

### Stage 5: STORE (`worker/stages/store.py`)

```
INPUT: {**executed, **governed, task_id, tenant_id, task_type,
        siem_event, code, tokens_in/out, path_taken, trace_id,
        execution_mode, plan_executed}

WRITES (in order):
  1. agent_tasks UPDATE: status, output (JSONB), error_message,
     tokens_used_input/output, execution_ms, severity,
     needs_human_review, review_reason, model_name,
     path_taken, generated_code, completed_at
     [synchronous_commit = on]

  2. investigation_memory INSERT: task_type, alert_signature,
     code_template, iocs_found (JSON), findings_found (JSON),
     risk_score, success

  3. investigations INSERT: tenant_id, task_id, verdict,
     risk_score, confidence, summary, source="production",
     model_name → RETURNING id

  4. audit_events INSERT x2:
     - investigation_started {task_type, severity, model}
     - investigation_completed {verdict, risk_score,
       execution_ms, ioc_count, finding_count}

  5. entities UPSERT: per IOC → entity_graph.persist_entities()
     (entity_hash, entity_type, value, tenant_id, threat_score,
      observation_count, confidence, source_investigation_id)

  6. entity_edges UPSERT: inferred relationships →
     entity_graph.persist_edges()
     (source_entity_id, target_entity_id, edge_type,
      investigation_id, tenant_id, confidence)

  7. cross_tenant_entities UPSERT:
     (entity_hash, entity_type, sighting_count, malicious_count,
      benign_count, avg_risk_score)

  8. NOTIFY task_completed {task_id, tenant_id, verdict,
     risk_score, task_type}

  9. NOTIFY attack_path_correlate {same payload}

  10. Redis dedup entry UPDATE: status, verdict, risk_score

OUTPUT → StoreOutput:
  {task_id, status, investigation_id, memory_saved, pattern_saved}
```

---

## Post-Pipeline Intelligence (On-Demand API)

```
POST /api/v1/remediation/suggest {investigation_id}
  → copilot.suggest(investigation_id, tenant_id)
    → remediation._get_rules(attack_type)
      e.g. brute_force → [
        {action_type: "block", desc: "Block source IP", priority: 90},
        {action_type: "access_revoke", desc: "Reset credentials", priority: 85},
        {action_type: "rule_update", desc: "Lower lockout threshold", priority: 60}
      ]
    → optional LLM narrative (CODE model, Semaphore(1))

POST /api/v1/copilot/explain {investigation_id}
  → copilot.explain(investigation_id, tenant_id)
    → DB: agent_tasks WHERE id=$1 AND tenant_id=$2
      → {task_type, verdict, risk_score, iocs, findings,
         mitre_attack, raw_log, source_ip, username}
    → LLM system: "Explain investigation in 3-5 sentences"
    → fallback: _explain_fallback() template
    → {explanation, investigation_id, task_type, verdict,
       risk_score, latency_ms}

POST /api/v1/copilot/correlate {investigation_id}
  → DB: agent_tasks with matching source_ip/username (7d lookback)
  → attack_paths with matching entity_value
  → {related_investigations, attack_paths, source_ip, username}

POST /api/v1/copilot/brief {hours}
  → DB: aggregate verdicts, top attack types, alert volume
  → LLM: shift summary narrative
  → {brief, period_hours, stats}
```

---

## Complete Field Lineage

```
SIEM Alert
  | {event.src_ip, event.signature, event.raw, sourcetype, host}
  |
  +-> mapAlertToTaskType(signature) -> task_type
  +-> normalize: src_ip->source_ip, dest_ip->destination_ip
  |
  v
agent_tasks row
  | {id, tenant_id, task_type, input.siem_event.*, status=pending, trace_id}
  |
  v [Temporal]
  |
INGEST -> sanitize(25 patterns) + normalize(70 mappings) + dedup(Redis)
  |        + attack_scan(66 patterns) + skill_match(agent_skills)
  |
  v
  | IngestOutput.siem_event = {source_ip, username, hostname, dest_ip,
  |                            raw_log, rule_name, title, severity, ...}
  | IngestOutput.skill_id = UUID or null
  |
ANALYZE -> Path A: investigation_plans.json[task_type].plan
  |         Path C: LLM(FAST) -> {steps: [{tool, args}]}
  |
  v
  | AnalyzeOutput.plan = [{tool: "parse_auth_log", args: {text: "$raw_log"}},
  |                        {tool: "extract_ipv4", args: {text: "$raw_log"}},
  |                        {tool: "score_brute_force", args: {count: "$step4"}},
  |                        {tool: "correlate_with_history", args: {ioc_values: "$step2"}},
  |                        {tool: "map_mitre", args: {technique_ids: ["T1110"]}}]
  |
EXECUTE -> runner.execute_plan(): $stepN resolution, tool dispatch
  |
  v
  | stdout = {findings: [{title, details}],
  |           iocs: [{type, value, evidence_refs}],
  |           risk_score: 95, tools_executed: 7,
  |           tool_results: {1: ..., 2: [...], ...}}
  |
ASSESS -> IOC extraction + signal boost + verdict derivation + MITRE
  |
  v
  | {verdict: "true_positive", risk_score: 95, severity: "critical",
  |  iocs: [{type: "ipv4", value: "185.220.101.45", confidence: "high",
  |          evidence_refs: [{source: "siem_event.source_ip"}]}],
  |  findings: [{title: "Attack Signal: ...", details: "..."}],
  |  mitre_attack: [{id: "T1110", name: "Brute Force", tactic: "Credential Access"}],
  |  plain_english_summary: "CONFIRMED ATTACK from 185.220.101.45..."}
  |
GOVERN -> autonomy check
  |
  v
  |  + {needs_human_review: true, review_reason: "Observe mode: ...",
  |     autonomy_level: "observe"}
  |
STORE -> agent_tasks UPDATE + investigations INSERT + audit_events x2
  |       + entities UPSERT + entity_edges UPSERT + cross_tenant UPSERT
  |       + NOTIFY task_completed + Redis dedup update
  |
  v
  | {task_id, status: "completed", investigation_id: UUID}
  |
  +-->  SSE stream -> Dashboard real-time feed
  +-->  SIEM push-back (if configured): POST verdict to Splunk/Elastic
  +-->  On-demand: /copilot/explain, /remediation/suggest
```

---

## Key Decision Points

| Decision | Location | Logic |
|----------|----------|-------|
| Attack vs Benign routing | `ingest.py:_has_attack_indicators()` | 40 keyword match on task_type+rule_name+title |
| Content override | `ingest.py:_has_raw_log_attack_content()` | 66 regex patterns on raw_log with caret deobfuscation |
| Path A vs Path C | `analyze.py:_analyze_v3_tools()` | Saved plan exists? → A. Else LLM tool selection → C |
| Tier gating | `analyze.py:_check_tenant_tier()` | Premium plans blocked for community tier |
| Verdict derivation | `assess.py:_derive_verdict()` | risk<=35→benign, >=70→true_positive, >=50→suspicious |
| Signal boost | `assess.py` | 8 regex patterns add risk for SQLi/XSS/traversal |
| Suppression detection | `assess.py` | 9 phrases + attack indicator → risk boost to 75+ |
| Governance | `govern.py:apply_governance()` | observe/assist/autonomous from governance_config table |
| Fail-closed LLM | `analyze.py` + `assess.py` | LLM down → needs_manual_review, never benign |

## Database Tables Written Per Investigation

| Table | Write Type | Condition |
|-------|-----------|-----------|
| `agent_tasks` | UPDATE | Always |
| `investigation_memory` | INSERT | status=completed |
| `investigations` | INSERT | status=completed, not FAST_FILL |
| `audit_events` | INSERT x2 | tenant_id present |
| `entities` | UPSERT | status=completed, iocs present |
| `entity_edges` | UPSERT | entities created, relationships inferred |
| `cross_tenant_entities` | UPSERT | iocs present |
| Redis `dedup:exact:*` | UPDATE | Always |
