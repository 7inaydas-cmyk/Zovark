# Glossary: Every Term Used in Zovark

Every domain-specific term, grouped by category. For each: a plain English definition and where it appears in the codebase.

---

## Pipeline Stages

**Ingest** -- The front door. Cleans the alert, checks for duplicates, masks secrets, and figures out which investigation template to use. Think of it as the hospital triage nurse: quick assessment, no treatment yet. File: `worker/stages/ingest.py`.

**Analyze** -- The planning stage. Decides HOW to investigate. Either loads a pre-built plan (Path A), asks the AI to pick tools (Path C), or renders a template (Path B). This is the doctor deciding which tests to order. File: `worker/stages/analyze.py`.

**Execute** -- Runs the actual investigation tools. Parses logs, extracts IP addresses, counts failed logins, calculates risk scores. This is the lab running the blood tests. File: `worker/tools/runner.py` (dispatched from `worker/stages/execute.py`).

**Assess** -- Quality control. Validates tool outputs, extracts IOCs, checks for adversarial manipulation, assigns a final verdict and risk score, writes a plain-English summary. This is the doctor reading the lab results and writing a diagnosis. File: `worker/stages/assess.py`.

**Govern** -- The human oversight checkpoint between assess and store. Applies the tenant's autonomy level to decide whether an analyst must review the verdict before it becomes final. File: `worker/stages/govern.py`.

**Store** -- Writes everything to the database. Updates the task record, saves to investigation memory, creates audit events, persists to the entity graph, and fires a real-time notification to the dashboard. File: `worker/stages/store.py`.

---

## Investigation Paths

**Path A (Saved Plan)** -- The fast path. Zovark has a pre-built investigation plan for this attack type (e.g., brute_force has 7 tools in sequence). No AI needed. Takes about 5 milliseconds to load the plan. The plan lives in `investigation_plans.json` or the agent_skills table. File: `worker/stages/analyze.py`, function `_analyze_v3_tools`.

**Path B (Template + LLM Param Fill)** -- The medium path. There is a code template but it has blank parameters. The AI fills in the blanks (like "what is the source IP?") and the template runs with those values. Takes about 30 seconds. File: `worker/stages/analyze.py`, function `_analyze_template`.

**Path C (LLM Tool Selection)** -- The slow path for novel attacks. No saved plan and no template. The AI reads the full 40-tool catalog and selects 3-8 tools to run. Takes 5-30 seconds. A GBNF grammar constrains the AI output to valid JSON. The resulting verdict is flagged for analyst review (the "learning gate"). File: `worker/stages/analyze.py`, function `_analyze_v3_tools` (bottom half).

**Benign Path** -- For routine events like password changes, Windows updates, or scheduled backups. Matches one of 31 registered benign task types. Returns risk=15 and verdict=benign with no AI involvement. Identified by inverted logic: if the alert does NOT match any of the 40 attack indicator terms, it is benign. File: `worker/stages/ingest.py`, list `ATTACK_INDICATORS`.

---

## Tool Types

**Extraction Tools** (8) -- Pull structured data out of unstructured text. "Find all IP addresses in this log." Returns lists of values with evidence_refs (the exact log snippet where each value was found). File: `worker/tools/extraction.py`.

**Analysis Tools** (4) -- Perform calculations on data. Count how many times a pattern appears, measure Shannon entropy (randomness), detect encoding types. File: `worker/tools/analysis.py`.

**Parsing Tools** (5) -- Convert raw log lines into structured key-value pairs. Turn "Failed password for root from 185.220.101.45" into {action: "failed", username: "root", source_ip: "185.220.101.45"}. File: `worker/tools/parsing.py`.

**Scoring Tools** (6) -- Calculate risk scores based on quantitative inputs. "500 failed logins from 1 IP in 5 minutes = risk 95." Each tool is calibrated for a specific attack type. File: `worker/tools/scoring.py`.

**Detection Tools** (12) -- Composite detectors for specific attacks. Combine multiple signals: kerberoasting detection checks for RC4 encryption type, TGS request type, and non-krbtgt SPN. Return structured verdicts with findings and IOCs. File: `worker/tools/detection.py`.

**Enrichment Tools** (4) -- Add context from outside the alert. Map to MITRE ATT&CK techniques, check against known-bad lists, correlate with previous investigations via the entity graph, look up institutional knowledge. File: `worker/tools/enrichment.py`.

---

## Architecture

**Burst Protection** -- The 3-layer defense that prevents alert floods from overwhelming the system. Layer 1: dedup (reject duplicates). Layer 2: batch buffer (group similar alerts). Layer 3: backpressure (queue or reject when overloaded). All three layers run in the Go API before Temporal. Files: `api/alert_dedup.go`, `api/batch_buffer.go`, `api/backpressure.go`.

**Backpressure** -- Specifically Layer 3 of burst protection. Tracks how many workflows are currently running. Soft limit (200): alerts are queued for a drain goroutine. Hard limit (1000): returns HTTP 503 "try later." Prevents the system from accepting more work than it can handle. File: `api/backpressure.go`.

**Dedup (Deduplication)** -- Preventing the same alert from being investigated twice. Exists at two levels: the Go API checks Redis before creating a Temporal workflow, and the Python worker checks Redis again during ingest. Uses SHA-256 hashing of canonical fields with timestamps stripped. Files: `api/alert_dedup.go`, `worker/stages/ingest.py`.

**Batch Buffer** -- Groups identical alert types from the same source IP into a single investigation. If 100 brute force alerts arrive from 10.0.0.1 in 5 seconds, one investigation covers them all. Uses a Redis Lua script for atomic grouping. Severity promotion: if a "critical" alert arrives for the same group, the batch representative is upgraded. File: `api/batch_buffer.go`.

**Signal Boost** -- Risk score adjustment in the assess stage. If the raw log contains obvious attack patterns (SQL injection syntax, XSS tags, C2 beacon intervals), the risk score is boosted by 45 points per pattern type. Scans SIEM-provided data only, not tool output. File: `worker/stages/assess.py`, list `attack_signals`.

**Risk Floor** -- A minimum risk score applied when the alert matched a known attack template. If the task_type matches an attack indicator (like "brute_force") but the tools under-scored it (risk 40), the assess stage boosts it to at least 70. Prevents obviously malicious alerts from getting low scores. File: `worker/stages/assess.py`.

**Content Scanner** -- 70 regex patterns that detect attack commands in raw log text. Even if the alert metadata says "scheduled_task" (benign), the content scanner will find "mimikatz" or "certutil -urlcache" in the log and force a full investigation. The red-team-proof safety net. File: `worker/stages/ingest.py`, list `RAW_LOG_ATTACK_PATTERNS`.

**Suppression Detection** -- 9 patterns that detect adversarial manipulation of risk scores. Phrases like "scheduled test," "do not escalate," or "false positive confirmed" are red flags when they appear alongside actual attack indicators. When found together, risk is BOOSTED to 75+ instead of lowered. File: `worker/stages/assess.py`, list `SUPPRESSION_PATTERNS`.

**IOC Provenance** -- Validation that every IOC (indicator of compromise) actually exists in the raw log data. If an IP address appears in a structured SIEM field but not in the raw log text, it gets downgraded to confidence=low. Prevents the AI from inventing fake evidence. File: `worker/stages/assess.py`.

---

## Verdicts

**true_positive** -- Confirmed attack. Risk score 50+ with supporting evidence. Requires analyst review in observe mode. The most common verdict for genuine attacks.

**suspicious** -- Something looks wrong but the evidence is not conclusive. Risk 25-49 with at least one finding. Requires analyst review.

**benign** -- Routine activity, no threat. Risk 35 or below. In assist mode, this can be auto-closed without analyst review.

**inconclusive** -- Not enough data to decide. Very rare -- usually means tools produced no findings and no IOCs but risk is above zero.

**needs_manual_review** -- The system explicitly cannot decide. Used when the LLM was unavailable during investigation (fail-closed behavior) or when a validation error occurred. Always requires analyst review.

**needs_analyst_review** -- Specific to Path C (LLM-selected tools). The investigation completed, but because the tool plan was AI-generated (not pre-validated), an analyst must confirm before the plan can be promoted to a saved template. This is the learning gate.

All verdicts are defined in: `worker/stages/assess.py` function `_derive_verdict` and `worker/tools/runner.py` function `_derive_verdict`.

---

## Infrastructure

**Temporal** -- An open-source workflow engine. Think of it as a job manager that guarantees every investigation either completes or is explicitly retried. If the worker crashes mid-investigation, Temporal will restart it from the last completed stage. Zovark uses it to orchestrate the 6-stage pipeline. Container: `zovark-temporal`.

**Activity** -- Temporal's name for a single unit of work. Each pipeline stage (ingest, analyze, execute, assess, govern, store) is registered as a Temporal activity. Activities have individual timeouts and retry policies.

**llama-server** -- The inference engine that runs the AI model. Built from llama.cpp source code. Runs inside the `zovark-inference` container. Exposes an OpenAI-compatible chat completions API on port 8080. No external dependencies.

**GGUF** -- The file format for quantized AI models. Short for "GPT-Generated Unified Format." Zovark uses Q4_K_M quantization (4-bit, medium quality) which compresses a model from ~16GB to ~5GB while keeping most of its accuracy.

**Inference** -- The process of asking the AI model a question and getting an answer. Each inference call consumes GPU memory and takes time. Zovark limits concurrent inference to 2 calls (via semaphore) to prevent GPU memory exhaustion.

**pgvector** -- A PostgreSQL extension that stores vector embeddings (lists of numbers that represent meaning). Used for similarity search in the entity graph and investigation memory. Container: `zovark-postgres`.

**Valkey** -- A BSD-licensed fork of Redis (the in-memory key-value store). Used for dedup, batching, code cache, and backpressure tracking. Zovark switched from Redis to Valkey for license compliance. Container: `zovark-redis`.

---

## Security Terms

**IOC (Indicator of Compromise)** -- A piece of evidence that an attack occurred. An IP address, a domain name, a file hash, a username, an email, a URL, or a CVE identifier. Zovark extracts IOCs from SIEM data and attaches evidence_refs (proof of where each IOC was found).

**MITRE ATT&CK** -- A public catalog of known attack techniques, maintained by the MITRE Corporation. Each technique has an ID like T1110 (Brute Force) or T1558.003 (Kerberoasting). Zovark maps every investigation to MITRE techniques so analysts can see what category of attack they are dealing with.

**TTP (Tactics, Techniques, and Procedures)** -- The "how" of an attack. Tactics are the goals (initial access, persistence, lateral movement). Techniques are the specific methods (brute force, DLL sideloading). Procedures are the exact implementation.

**C2 (Command and Control)** -- The communication channel between an attacker and a compromised machine. The attacker sends commands; the malware sends back data. Zovark detects C2 by looking for regular beacon intervals, high-entropy domains, and encoded payloads.

**Lateral Movement** -- An attacker moving from one machine to another inside a network after the initial compromise. Methods include PsExec, WMI, pass-the-hash. Zovark detects this by looking for remote execution patterns and admin share access.

**Exfiltration** -- Stealing data by sending it outside the network. Can be via large file transfers, cloud storage uploads, or even DNS queries (encoding data in DNS subdomain names). Zovark measures transfer volumes, checks for off-hours activity, and detects encoding.

**Kerberoasting** -- An attack against Windows Active Directory. The attacker requests service tickets encrypted with RC4 (a weak encryption), then cracks them offline to get service account passwords. Zovark detects RC4 TGS requests for non-krbtgt SPNs.

**Golden Ticket** -- A forged Kerberos ticket that gives an attacker unlimited access to a Windows domain. Created by stealing the krbtgt account hash. Zovark detects abnormal ticket lifetimes and RC4 encryption on TGTs.

**LOLBin (Living Off the Land Binary)** -- A legitimate Windows program used for malicious purposes. Examples: certutil (downloading malware), mshta (running scripts), bitsadmin (transferring files). The attacker avoids deploying custom malware by abusing tools already on the system.

**DGA (Domain Generation Algorithm)** -- Malware that generates random-looking domain names (like "x8fjk2.xyz") to contact its C2 server. Zovark detects DGA domains by measuring Shannon entropy (randomness) of DNS queries.

---

## Zovark-Specific Terms

**zvadmin** -- A command-line tool for operators. Runs on the host machine (not in Docker). Commands: diagnose (health checks), alerts (pipeline stats), model check (risk calibration), dedup health, troubleshoot, update. File: `cmd/zvadmin/`.

**Autonomy Slider** -- The governance setting that controls how much human oversight Zovark requires. Three levels: observe (review everything), assist (review non-benign only), autonomous (review only edge cases). Configurable per tenant and per attack type. File: `worker/stages/govern.py`, table: `governance_config`.

**Copilot** -- An analyst-facing AI assistant. Four operations: explain (why was this verdict given?), suggest (what should I do next?), correlate (what other investigations involve the same entities?), brief (shift handoff summary). Uses its own semaphore to avoid starving the pipeline of LLM capacity. File: `worker/intelligence/copilot.py`.

**Breakglass Login** -- An emergency admin login for when the normal authentication system is down. Uses a system tenant (UUID 00000000-0000-0000-0000-000000000001) that bypasses normal tenant isolation. File: `api/admin_breakglass.go`.

**OOB Watchdog** -- "Out of Band" monitoring. A separate HTTP listener on a different port that provides health diagnostics without going through the main API. Used by zvadmin and the healer for health checks that must work even when the main API is degraded. File: `api/oob.go`.

**AutoResearch** -- An autonomous experimentation system. Two modes: Red Team (finds bypasses in the detection pipeline -- 152 experiments, 144 bypasses found) and Template Engineer (builds and validates investigation templates -- 10/10 approved). Everything is lab-only; nothing enters production without human review. Files: `autoresearch/redteam/`, `autoresearch/templates/`.

**Template Promotion Flywheel** -- The process of converting a Path C investigation (AI-selected tools, slow) into a Path A template (pre-built plan, fast). When an analyst confirms a Path C verdict, the tool plan can be extracted and saved. Requires 2-person approval (quorum). Files: `api/promotion_handlers.go`, `worker/stages/template_promoter.py`.

**Learning Gate** -- The safety valve on Path C investigations. Because the AI selected the tools (not a human-validated plan), the verdict is automatically downgraded to needs_analyst_review. The analyst either confirms or corrects. This is how Zovark learns. File: `worker/stages/assess.py`.

**Investigation Plan** -- A JSON document listing 2-8 tool steps in sequence, with variable references and optional conditional branching. Example: step 1 runs parse_auth_log, step 2 runs extract_ipv4 with $raw_log, step 3 runs count_pattern with $step1.username. File: `worker/tools/investigation_plans.json`.

**Skill Template** -- A record in the agent_skills database table. Contains a skill name, slug, threat types it handles, an investigation plan (for V3) or a code template (for V2), and parameters. Zovark has 25 active skill templates.

---

## Entity Graph

**Entity** -- A node in the knowledge graph. Represents a single IOC value: an IP address, a domain, a user, a file hash. Each entity tracks observation_count (how many times seen), threat_score, confidence, and first/last seen timestamps. Table: `entities`.

**Edge** -- A relationship between two entities. Types include: communicates_with (IP to IP), logged_into (IP to user), executed (user to process), resolved_to (domain to IP). Table: `entity_edges`.

**Sighting** -- Each time an entity appears in an investigation, its observation_count increments and last_seen updates. More sightings generally mean higher confidence in the entity's classification.

**Cross-Tenant Intelligence** -- Privacy-preserving shared intelligence. Entity hashes (not raw values) are stored in a table visible to all tenants. A tenant can see "this entity hash has 5 sightings across the platform, 4 malicious" without knowing which other tenants reported it. Table: `cross_tenant_entities`.

**entity_hash** -- A SHA-256 hash of "entity_type:value" (e.g., "ip:185.220.101.45"). Used for deduplication within a tenant and for cross-tenant sharing without revealing the raw value.

**observation_count** -- How many separate investigations have involved this entity. An IP with observation_count=10 is much more significant than one with observation_count=1.

**threat_score** -- The highest risk_score from any investigation involving this entity. Ranges 0-100. Updated on each new sighting via GREATEST (keeps the higher value).

---

## LLM Terms

**FAST Model** -- The AI model used for quick tasks: tool selection (Path C) and parameter extraction (Path B). Currently Gemma 4 E4B. Optimized for speed over quality. Env var: `ZOVARK_MODEL_FAST`.

**CODE Model** -- The AI model used for quality-sensitive tasks: verdict assessment and investigation summaries (Stage 4). Same model as FAST in dev; bigger model in customer deployments. Env var: `ZOVARK_MODEL_CODE`.

**GBNF Grammar** -- A formal grammar that constrains what the AI model can output. For tool selection, the grammar forces the output to be valid JSON with tool names from the catalog. This eliminates hallucinated tool names and malformed JSON. Used by llama-server's native grammar support.

**Prefix Caching** -- A llama-server optimization. If the system prompt (the static part) is the same across multiple requests, the server caches the computed representation and only processes the dynamic part (the alert data). Saves 30-50% of inference time. Zovark keeps all static content in the system message and all dynamic content in the user message to maximize cache hits.

**Semaphore** -- A concurrency limiter. Zovark uses Semaphore(2) for pipeline LLM calls (max 2 concurrent) and Semaphore(1) for copilot calls (max 1 concurrent). This prevents GPU memory exhaustion when multiple investigations arrive simultaneously. File: `worker/llm_client.py`.

**Circuit Breaker** -- A failure detection pattern with three states. GREEN: everything works normally. YELLOW: some failures detected, reduced capacity. RED: too many failures, stop sending requests. When the LLM is down, the circuit breaker goes RED and investigations fail-closed (verdict = needs_manual_review, never benign). File: `worker/stages/circuit_breaker.py`.
