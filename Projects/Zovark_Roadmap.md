---
kanban-plugin: basic
---

## Doing

- [ ] D1: zvadmin bundle CLI
- [ ] D2: OTA sync service

## Up Next

- [ ] D1: zvadmin bundle CLI
- [ ] D2: OTA sync service
- [ ] D3: Bundle publisher
- [ ] D4: Signing key distribution

## Blocked

- [ ] E1: Model benchmark — needs 48h stable pipeline
- [ ] E3: Fine-tuning pilot — needs 200 DPO pairs

## Done (Post-Sprint C)

- [x] Entity graph: migration 069, entity persistence, 5 API endpoints, cross-tenant
- [x] Dashboard revamp: sidebar nav (web-admin), auto-templates field fix (port 3000)
- [x] Security: curl|bash + reverse shell patterns (scanner 87, boost 11)
- [x] Data flow doc: docs/DATA_FLOW.md
- [x] Codebase manifest: scripts/generate_manifest.sh → docs/MANIFEST.json
- [x] Knowledge base v1.1: 16 files, ~38k words, 132 functions indexed — completed 2026-04-08
- [x] Overnight 2026-04-09: 6 unit test fixes, detect_credential_access + detect_supply_chain (42 tools), dual-endpoint FAST/CODE, 7 scanner bypasses fixed, 534/534 tests

## Backlog

- [ ] Clean stale Ollama refs (airgap, test, dpo)
- [x] C1: Remediation engine (4 endpoints, 22 attack types, migration 067)
- [x] C2: Copilot API (explain, suggest, correlate, brief — 4 endpoints, LLM fallback)
- [x] C3: License enforcement (Ed25519, fail-closed, grace period, 3 API endpoints)
- [x] Dashboard v2 (pipeline monitor, time series, attack breakdown, error panel)
- [x] Bundle test fixes (conftest.py, 6 failures → 0)
- [x] Detection calibration (golden_ticket, kerberoasting, ransomware, data_exfil, phishing BEC)
- [x] Dashboard v1 (PipelineMonitor, AnalyticsPanel fixes, SSE reconnect)
- [x] Security audit fixes (ReDoS, JSON injection, info disclosure)
- [x] Red team patches (7 E2E bypasses, 66 content scanner patterns)
- [ ] Fix remaining test failures (4 egress, rest pre-existing)
- [ ] Asset TTL cleanup
- [ ] Attack path analyst feedback
- [ ] Ticket integration (Jira/ServiceNow)
- [ ] Delta bundle compression
- [ ] Model canary deployment
- [ ] RunPod REASON testing
- [ ] Healthcare template pack
- [ ] PgBouncer credential switch
- [ ] Healer memory leak root cause
- [ ] Blue/green deployment
- [ ] Merge v3.3-dev to master
