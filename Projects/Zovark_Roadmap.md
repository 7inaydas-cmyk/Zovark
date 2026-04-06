---
kanban-plugin: basic
---

## Done

- [x] Migration 066 — template sync engine + intelligence layer (11 tables, RLS, partitioned) — completed 2026-04-06
- [x] Bundle schema — Pydantic models, Ed25519 verification, size limits, diff/preview — completed 2026-04-06
- [x] Security gates — 3-phase deterministic SAST (AST + patterns + runtime) + DAST — completed 2026-04-06
- [x] Bundle importer — atomic import, semver conflict resolution, generation pinning, rollback — completed 2026-04-06
- [x] Bundle system unit tests — 25 tests (schema, SAST bypass, diff, semver) — completed 2026-04-06
- [x] Dynamic plan loading — DB plans first, tier enforcement, generation pinning in analyze.py — completed 2026-04-06
- [x] Attack path correlator — 5 deterministic rules, confidence scoring, DLQ — completed 2026-04-06
- [x] Contextual risk scoring — conservative multipliers (0.72x-1.87x), auto-discovery — completed 2026-04-06
- [x] Store NOTIFY trigger — attack_path_correlate after Stage 5 — completed 2026-04-06
- [x] Risk calibration anchors — DB loading with 5-min cache in assess.py — completed 2026-04-06
- [x] Zvadmin web panel — 5 command buttons, structured output, terminal-style UI — completed 2026-04-06
- [x] Alert Forge — mass generator with sliders, SSE progress, verdict charts — completed 2026-04-06
- [x] Analytics dashboard — verdicts, risk by type, separation gap, latency — completed 2026-04-06
- [x] Investigation detail view — verdict, tools, IOCs, MITRE, raw SIEM — completed 2026-04-06
- [x] Go API: zvadmin handlers (diagnose, alerts, model-check, dedup-health, system-stats) — completed 2026-04-06
- [x] Go API: forge handlers (start, status, stream SSE, stop, history) — completed 2026-04-06
- [x] Go API: forge scenarios (10 attacks, 5 benign, 3 campaigns, mutation engine) — completed 2026-04-06
- [x] Path C regression coverage — 16/16 (added unusual_network_traffic) — completed 2026-04-05
- [x] Dedup batch severity promotion fix — test was reading wrong Redis key, Lua correct — completed 2026-04-05
- [x] Web-admin served via nginx — port 3100, nginx:alpine, SPA fallback — completed 2026-04-05
- [x] PRD addendum saved — Intelligence Layer + Multi-Model Architecture (Phases 10-15) — completed 2026-04-05
- [x] Gemma 4 E4B model swap — from Nemotron-Mini-4B, --ctx-size 4096 --jinja --reasoning off — completed 2026-04-04
- [x] Path C fix — str.format() braces escaped to {{ }} — completed 2026-04-05
- [x] MITRE ATT&CK propagation — 12 entries, 100% coverage — completed 2026-04-05
- [x] Parallel tool execution — DAG builder + ThreadPoolExecutor (flag-gated, default OFF) — completed 2026-04-05
- [x] Engineering discipline framework — 7 slash commands — completed 2026-04-05
- [x] Component registry — COMPONENT_REGISTRY.md — completed 2026-04-05
- [x] RLS migration 065 — zovark_app user, FORCE ROW LEVEL SECURITY on 10 tables — completed 2026-04-05
- [x] Healer memory leak mitigated — 512MB container limit — completed 2026-04-05

## In Progress

- [ ] C1: Remediation engine — circuit breakers (MAX_ATTEMPTS=3/24h), rate limiter (10 synthetic/hr), kill switch, regression check logic
- [ ] C2: Copilot API MVP — explain, suggest, correlate, brief. Semaphore(1) priority=LOW. Tenant-scoped.
- [ ] C3: License enforcement — Ed25519, fail-closed on error, 30-day grace period in signed payload

## Blocked

- [ ] E1: Model validation benchmark — BLOCKED: need 48h stable pipeline before swapping models
- [ ] E3: Fine-tuning pilot — BLOCKED: need 200+ DPO pairs from analyst feedback (no analysts yet)

## Sprint D: Delivery

- [ ] D1: zvadmin bundle CLI commands — list, inspect, apply, rollback, revoke, impact, approve-tool
- [ ] D2: OTA sync service — api/bundle_sync.go, background goroutine, state machine (idle/downloading/staged/applying)
- [ ] D3: Bundle publisher — autoresearch/bundle_publisher/, HQ-side generation
- [ ] D4: Signing key distribution — Ed25519 public key in worker binary, rotation via certificate chain

## Backlog

- [ ] Asset TTL cleanup job — healer daily, 90-day partitioned asset_occurrences
- [ ] Attack path analyst feedback — POST /api/v1/attack-paths/{id}/feedback, auto-disable >20% FP rate
- [ ] Remediation ticket integration — Jira, ServiceNow, generic webhook
- [ ] Delta bundle compression — only ship diffs between bundle versions
- [ ] Model canary deployment — A/B test new model on subset of alerts
- [ ] RunPod deployment scripts — REASON model testing on A100
- [ ] Healthcare template pack — 30 industry-specific templates (HIPAA, infrastructure, compliance)
- [ ] PgBouncer zovark_app switch — migration 065 applied, config + credential switch pending
- [ ] Healer memory leak root cause — mitigated (512MB limit), not fixed (Python async/GIL)
- [ ] Merge v3.3-dev to master — when Sprint C complete and regression stable
- [ ] Blue/green deployment — zero-downtime updates with auto-rollback
- [ ] A100 benchmark — rerun with parallel workers on GPU hardware

## Constraints

- [ ] DO NOT modify investigation_workflow.py
- [ ] DO NOT break two-model FAST/CODE architecture
- [ ] All bundle code through AST prefilter + runtime SAST
- [ ] verify_all.sh 16/16 after EVERY change
- [ ] Additive-only migrations (safe rollback to v3.2.1)
- [ ] License check errors -> DENY access (fail-closed)
- [ ] Detection tools activate ONLY after worker restart
- [ ] Plans instance-scoped, tier enforcement at query time
- [ ] No LLM on SAST path — deterministic only
- [ ] No customer data in telemetry without explicit opt-in
- [ ] Copilot LLM calls deprioritized below pipeline calls
- [ ] Attack path failures -> DLQ + metric + SSE alert

## Decision Log

- [x] 2026-04-05: Gemma 4 E4B kept as dev model. Only swap if specific benchmark metric fails.
- [x] 2026-04-05: REASON model (LLaMA 70B) = testing-only on RunPod. Not production path.
- [x] 2026-04-05: 2 models (FAST/CODE), not 5. Prove need before adding REASON/CODESEC/EDGE.
- [x] 2026-04-05: Plans are instance-scoped, NOT tenant-scoped. Tier enforcement at query time.
- [x] 2026-04-05: No LLM on SAST path. Deterministic AST + regex + runtime validation only.
- [x] 2026-04-05: StarCoder2 (CODESEC role) cut. AST prefilter + pattern analysis sufficient.
- [x] 2026-04-05: Copilot rule generation (patch command) DEFERRED to post-MVP.
- [x] 2026-04-06: Dedup "Go Lua bug" was actually a test bug. Lua severity promotion correct.
- [x] 2026-04-06: Auto-verification = regression check (pipeline still detects), NOT remediation verification.
- [x] 2026-04-06: Conservative contextual risk multipliers (0.72x-1.87x range) to avoid over-adjustment.
- [x] 2026-04-06: Attack path MIN_CONFIDENCE = 0.75 to reduce false correlations.
