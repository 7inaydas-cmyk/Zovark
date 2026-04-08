# HOT CACHE
# Updated: 2026-04-09 (commit 134a045)
# Read this FIRST. Skip CLAUDE.md unless you need deep detail.

## Current State
- Branch: v3.3-dev
- Regression: 16/16 (Path C included)
- Dedup: 14/14
- Unit tests: 534/534 (0 failures — was 528/534 before overnight)
- Services: 17 containers running
- Last commit: 134a045 security: red team round 2
- Content scanner: 87 patterns (was 76)
- Signal boost: 11 patterns
- Tools: 42 (was 40, added detect_credential_access + detect_supply_chain)
- Sprint C: COMPLETE (C1+C2+C3 all shipped)
- Entity graph: LIVE (213 entities, 243 edges from investigations)
- Dual-endpoint: CONFIGURED (health check, graceful degradation, ROG extra_hosts)
- Scoring: avg 1.84s latency, 0% benign FP, credential_access now 100 (was 50)

## Overnight Session (2026-04-08/09) — 5 commits
- 4dfa592: fix 6 unit test failures (detection thresholds + egress controller)
- 28a6494: add detect_credential_access + detect_supply_chain (42 tools)
- 35a48d0: dual-endpoint FAST/CODE with health check + graceful degradation
- 134a045: red team round 2 — 7 bypasses fixed (87 scanner patterns)
- [pending]: state files + morning report

## Sprint C — COMPLETE
- C1: Remediation engine — DONE (e83440b)
- C2: Copilot API — DONE (d14f88a)
- C3: License enforcement — DONE (846ec54)

## Dual-Endpoint (Ready for 31B)
- FAST: http://zovark-inference:8080 (Gemma 4 E4B, local)
- CODE: configurable (currently same as FAST)
- Health check: check_endpoint_health() on startup
- Degradation: after 3 CODE failures, falls back to FAST
- ROG: extra_hosts rog-inference:100.100.79.83 in docker-compose.yml
- To activate: set ZOVARK_LLM_ENDPOINT_CODE + ZOVARK_MODEL_CODE in .env, restart worker

## 100-Alert Scoring (post-overnight)
| Type | Avg Risk | Min | Max |
|------|----------|-----|-----|
| credential_access | 100 | 100 | 100 |
| c2/c2_communication | 100 | 100 | 100 |
| brute_force | 95 | 95 | 95 |
| kerberoasting | 95 | 80 | 100 |
| golden_ticket | 87.5 | 75 | 100 |
| phishing | 86.7 | 70 | 100 |
| lolbin_abuse | 81.3 | 70 | 100 |
| dns_exfiltration | 77.5 | 70 | 100 |
| ransomware | 74.3 | 70 | 85 |
| All benign (27) | 0 | 0 | 0 |

## Next Sprint: D — Bundle Distribution
- D1: zvadmin bundle CLI
- D2: OTA sync service
- D3: Bundle publisher
- D4: Signing key distribution

## Blocked
- E1: Model benchmark — needs 48h stable pipeline (ready to unblock)
- E3: Fine-tuning pilot — needs 200 DPO pairs

## Anti-Patterns
- Don't use .* in regex (ReDoS) — split into independent re.search() calls
- Don't use fmt.Sprintf for JSON — use json.Marshal
- Don't return specific error messages (IDOR) — use generic "not found"
- Don't rely on structured parse fields alone — add raw_log keyword fallback
- License check errors → DENY (fail-closed, Invariant #6)
- Copilot LLM calls → deprioritized below pipeline (Invariant #11)

## Files You'll Probably Touch
- worker/bundles/ (Sprint D bundle CLI)
- api/main.go (route registration)
- web-admin/src/components/ (dashboard enhancements)
