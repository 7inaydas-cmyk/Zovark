# Swami FAQ — Plain English Answers

Questions a non-technical cofounder would ask, answered without jargon.

---

## 1. "How does an alert become a verdict?"

A SIEM system (like Splunk or Elastic) detects something unusual and sends an alert to Zovark's front door (the Go API on port 8090). The alert goes through three bouncers (dedup, batching, backpressure) to prevent flooding. If it passes, it gets put in a queue (Temporal).

A Python worker picks it up and runs it through 6 stages: clean the data (Ingest), pick an investigation plan (Analyze), run the investigation tools (Execute), judge the results (Assess), decide if a human needs to review it (Govern), and save everything to the database (Store).

The whole process takes about 2.6 seconds on average. The verdict — true_positive, suspicious, benign, or inconclusive — along with a risk score (0-100), IOCs (the bad IPs/domains/hashes found), and MITRE ATT&CK technique mapping appears on the dashboard in real time via a live streaming connection.

---

## 2. "What does the AI actually do? What doesn't it do?"

**What the AI does:**
- Picks investigation tools for unknown/novel attack types (Path C — about 5% of alerts)
- Generates a brief investigation summary in plain English for analysts
- Optionally explains verdicts when analysts ask via the Copilot feature

**What the AI does NOT do:**
- It does NOT pick tools for known attack types (95% of alerts use pre-built plans — zero AI)
- It does NOT execute the investigation (deterministic Python tools do that)
- It does NOT decide the verdict (rule-based logic with thresholds: risk >= 70 = true_positive)
- It does NOT extract IOCs (regex pattern matching does that)
- It does NOT access the internet (runs 100% air-gapped on local hardware)

The AI is a convenience, not a dependency. Remove the AI entirely and Zovark still investigates 95% of alerts at full speed using saved plans.

---

## 3. "Can we run without GPU?"

Yes, with caveats. Path A (saved plans) and benign routing need zero GPU — they're pure Python logic. That covers 95%+ of alerts. Path C (novel attack types) and the verdict summary feature need LLM inference, which is very slow on CPU (minutes instead of seconds).

For a customer with only known attack types and no need for AI summaries, Zovark runs entirely on CPU. Set `ZOVARK_MODE=templates-only` and the LLM is never called.

For full functionality, a 4GB+ GPU is recommended. The current model (Gemma 4 E4B Q4_K_M) fits in 4GB VRAM with reduced context size.

---

## 4. "What happens if the LLM goes down?"

The system is designed for this. When the LLM becomes unavailable:

- **Known attacks (Path A):** Continue normally. Zero impact. No LLM needed.
- **Benign alerts:** Continue normally. Zero impact.
- **Novel attacks (Path C):** Get verdict `needs_manual_review` — they're flagged for an analyst but never marked as "benign." This is called "fail-closed" — we'd rather send a human a false alarm than miss a real attack.
- **Investigation summaries:** Fall back to a template-based summary instead of AI-generated prose.
- **Circuit breaker:** Goes RED, alerting operators that the LLM is down.

The pipeline never crashes due to LLM failure.

---

## 5. "How do we add a new type of attack detection?"

Three ways, from easiest to hardest:

1. **Automatic (Path C → Template Promotion):** If a novel attack comes in, Zovark's AI selects tools and investigates it. If an analyst confirms the verdict, the tool selection becomes a saved plan. Next time, it's Path A — instant, no AI.

2. **Manual plan:** Add an entry to `investigation_plans.json` with the tool sequence. Takes 5 minutes for someone who understands the tool catalog.

3. **New detection tool:** Write a Python function in `worker/tools/detection.py`, register it in `catalog.py`, add it to relevant investigation plans. Takes a few hours.

No retraining, no model fine-tuning, no data labeling. Detection is code, not AI.

---

## 6. "How do we connect to a customer's Splunk/Elastic?"

Two built-in connectors:

- **Splunk:** Customer configures a Splunk HTTP Event Collector (HEC) output to POST alerts to `https://zovark:8090/api/v1/ingest/splunk`. Zovark maps Splunk field names (src_ip, dest_ip, signature) to internal format automatically.

- **Elastic:** Customer configures an Elastic SIEM webhook to POST to `https://zovark:8090/api/v1/ingest/elastic`. Same automatic field mapping.

- **Generic webhook:** Any system can POST JSON to `https://zovark:8090/api/v1/tasks` with a task_type and siem_event object.

Setup takes about 15 minutes on the customer side. The bootstrap wizard in the admin dashboard walks through it step by step.

---

## 7. "What's the entity graph and why does it matter?"

Think of it as Zovark's long-term memory. Without the entity graph, every investigation starts from scratch. With it, Zovark remembers: "This IP address was involved in a brute force attack last Tuesday."

Every time an investigation completes, the IOCs (bad IPs, domains, file hashes, usernames) are saved as "entities" in a graph database. Relationships between them (this IP logged into this hostname) are saved as "edges."

On future investigations, the `correlate_with_history` tool queries this graph. If it finds the same IP, domain, or username from a prior attack, the risk score gets boosted. An IP seen in 5 prior attacks is more suspicious than one seen for the first time.

Cross-tenant intelligence goes further: anonymized entity hashes (no raw values) are shared across all tenants. If Tenant A sees a malicious IP, Tenant B's risk score for the same IP gets a boost — without either tenant seeing the other's data.

---

## 8. "How does multi-tenancy work?"

Each customer organization is a "tenant" with a unique ID. Every database query includes the tenant ID, so Tenant A's data is invisible to Tenant B. PostgreSQL Row-Level Security (RLS) enforces this at the database level — even a bug in the application code can't leak cross-tenant data.

API authentication returns a JWT token containing the tenant ID. Every request is scoped to that tenant automatically.

The one exception: cross-tenant entity intelligence uses SHA-256 hashes, not raw values. Tenants share anonymous threat statistics without exposing their actual data.

---

## 9. "What's the difference between Path A and Path C?"

**Path A (95% of alerts):** The alert type (e.g., "brute_force") matches a pre-built investigation plan. The plan is loaded from a JSON file — a sequence of 5-8 tools to run. No AI involved. Takes ~5 milliseconds.

**Path C (5% of alerts):** The alert type is unknown (no matching plan). The AI model reads the alert and the tool catalog, then selects which tools to run. Takes ~30 seconds. After the investigation, an analyst can confirm it, and the AI's tool selection becomes a new saved plan — turning future occurrences into Path A.

Path A is fast, deterministic, and GPU-free. Path C is slower but handles novel attacks. Over time, Path C investigations get promoted to Path A, so the system gets faster as it sees more attack types.

---

## 10. "How fast is an investigation and why?"

- **Average:** 2.6 seconds
- **Path A (saved plan):** ~350 milliseconds (no AI, just tool execution)
- **Path C (AI tool selection):** ~30 seconds (AI inference + tool execution)
- **Benign alerts:** ~200 milliseconds (minimal processing)

Why so fast? Three reasons:
1. Saved plans skip the AI entirely (the biggest bottleneck)
2. Tools are pure Python functions running in-process (no Docker containers, no network calls)
3. The 3-layer burst protection prevents duplicate work

At ~40 investigations per minute on a single worker, Zovark is 60-250x faster than Dropzone AI and ~1,600x faster than a human analyst.

---

## 11. "What do we demo to customers?"

The demo flow:
1. Open the admin dashboard (port 3100)
2. Go to Alert Forge tab
3. Set 100 alerts, 80% attack ratio, 5/sec rate
4. Click Start and watch the Pipeline Monitor in real time
5. Show: verdicts appearing every ~0.5 seconds, risk scores, MITRE mapping, zero false positives on benign alerts
6. Open the Analytics tab — show verdict distribution, attack type breakdown, throughput charts
7. Open a specific investigation — show the plain-English summary, IOCs with evidence, MITRE techniques
8. Show the Entity Graph page — interconnected threat intelligence building up from investigations
9. Key talking points: "2.6 second average," "100% detection on known attacks," "0% false positives on benign," "runs air-gapped — your data never leaves your network"

---

## 12. "What are our 3 biggest technical advantages over competitors?"

1. **Air-gapped by design:** Competitors (Dropzone AI, Torq HyperSOC) are cloud-only SaaS. Zovark runs entirely on-premise. For defense, healthcare, and government customers, this isn't a feature — it's a requirement. No security telemetry ever leaves the network.

2. **Speed without AI dependency:** 95% of investigations use saved plans (no AI). Average 2.6 seconds vs. competitors' 3-10 minutes. The AI is optional, not core. This means we can run on minimal hardware ($40K Essentials tier with CPU-only).

3. **Self-improving flywheel:** When the AI investigates a novel attack (Path C), analysts confirm the result, and it becomes a saved plan (Path A). The system literally gets faster and more accurate with every confirmed investigation. Competitors don't have this — their AI cost stays constant.

---

## 13. "If I hire a new developer, what do they read first?"

1. `HANDOVER.md` — How to work in this codebase (20 min read)
2. `docs/DATA_FLOW.md` — Complete pipeline trace with actual code (30 min read)
3. `COMPONENT_REGISTRY.md` — Living inventory of every module (10 min scan)
4. `docs/KNOWLEDGE_BASE/00_HOW_ZOVARK_WORKS.md` — The narrative walkthrough (15 min)
5. Run `bash autoresearch/cycle10/verify_all.sh` — See the pipeline work (5 min)

After that, they pick a specific area (tools, API, dashboard) and read the relevant code. The knowledge base directory has deep dives on every topic.

---

## 14. "What's the most fragile part of the system?"

The LLM inference container. It's a single point of failure for Path C investigations and verdict summaries. If it crashes or runs out of memory:
- Path A investigations continue fine (no LLM needed)
- Path C investigations fail-closed to manual review
- The healer container auto-restarts it, but there's a 30-60 second gap

Mitigations in place: circuit breaker (detects LLM failures within 3 seconds), fail-closed logic (never returns benign on LLM failure), healer auto-restart, 512MB memory limit on the healer itself (it has its own memory leak on Windows).

The second most fragile: PostgreSQL. If the database goes down, everything stops. Mitigated by PgBouncer connection pooling, synchronous_commit on critical writes, and daily backups.

---

## 15. "What would break if we 10x the alert volume?"

Going from ~40/minute to ~400/minute:

**What would handle it fine:**
- Burst protection layers (designed for exactly this — dedup and batching absorb the flood)
- Go API (handles thousands of concurrent requests natively)
- PostgreSQL (with PgBouncer, 400 client connections are fine)

**What would need scaling:**
- **Worker:** Currently 1 worker with 16 concurrent activities. At 400/min, you'd need 4-8 workers. Temporal supports multi-worker out of the box — just `docker compose scale worker=4`.
- **LLM inference:** If many alerts are Path C (novel), the single GPU becomes the bottleneck. Solution: dual-container setup (FAST + CODE on separate GPUs) or reducing Path C rate by promoting more templates.
- **Valkey/Redis:** Dedup and batch buffer keys grow linearly. At 400/min, Redis memory usage increases ~10x. A 1GB Valkey instance handles this easily.

The architecture was designed for horizontal scaling. The hard limit is GPU inference for Path C — but since 95% of alerts use Path A (no GPU), the real bottleneck is further out than you'd expect.
