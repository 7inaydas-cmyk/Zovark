# HOT CACHE
# Updated: 2026-04-07 (commit 81932fc)
# Read this FIRST. Skip CLAUDE.md unless you need deep detail.

## Current State
- Branch: v3.3-dev
- Regression: 16/16 (Path C included)
- Dedup: 14/14
- Services: 17 containers running (11 defined, 6 from profiles)
- Tests: 48 bundle+remediation pass, rest pre-existing
- Last commit: fc5bb1a security: patch 7 red team E2E bypasses in content scanner
- Content scanner: 66 patterns (was 54), caret deobfuscation added
- Healer: memory limited to 512MB, leak active

## Active Sprint: C — Pipeline Integration
- C1: Remediation engine — DONE (4 API endpoints, 22 attack types, 17 tests)
- C2: Copilot API — NOT STARTED
- C3: License enforcement — NOT STARTED

## Session Work (2026-04-06/07)
- C1 remediation engine (suggest/verify/list/patch, migration 067)
- Bundle test fixes (conftest.py, SyntaxError, SAST, expiry — 31/31 pass)
- Detection patches (golden_ticket, kerberoasting, ransomware, data_exfil, phishing BEC)
- 100-alert benchmark: 88% detection, all types avg risk ≥65, 0% benign FP
- Dashboard v1: PipelineMonitor, AnalyticsPanel fixes, AlertForge SSE reconnect
- Security audit: ReDoS fix (3.4s→0.22s), JSON injection, info disclosure
- Red team: 7 E2E bypasses patched (registry, caret, WMI, DNS tunnel, staging, renamed binary, process hollowing)
- Session protocol: smoke test added as Step 2
- Competitive benchmark doc

## Blocked
- E1: Model benchmark — needs 48h stable pipeline
- E3: Fine-tuning pilot — needs 200 DPO pairs

## Anti-Patterns (Top 5 Recent)
- Don't use .* in regex (ReDoS) — split into independent re.search() calls
- Don't use fmt.Sprintf for JSON — use json.Marshal
- Don't return specific error messages (IDOR) — use generic "not found"
- Don't pass comma-joined IDs to UUID columns
- Don't use double backslash in regex for single-backslash Windows paths

## Files You'll Probably Touch
- worker/intelligence/copilot.py (Sprint C2)
- worker/bundles/license.py (Sprint C3)
- api/zvadmin_handlers.go (pipeline status v2)
- web-admin/src/components/ (dashboard v2)
