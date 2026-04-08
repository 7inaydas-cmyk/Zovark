# HOT CACHE
# Updated: 2026-04-08 (commit a0b2b61)
# Read this FIRST. Skip CLAUDE.md unless you need deep detail.

## Current State
- Branch: v3.3-dev
- Regression: 16/16 (Path C included)
- Dedup: 14/14
- Services: 17 containers running (11 defined, 6 from profiles)
- Tests: 72 pass (31 bundle + 17 remediation + 13 copilot + 11 license)
- Last commit: a0b2b61 security: curl|bash patterns
- Content scanner: 70 patterns (was 66), caret deobfuscation
- Signal boost: 11 patterns (was 8)
- Sprint C: COMPLETE (C1+C2+C3 all shipped)
- Entity graph: LIVE (37 entities, 13 edges from investigations)
- Dashboard revamp: sidebar nav on web-admin, auto-templates field fix on port 3000
- Codebase manifest: docs/MANIFEST.json (162 routes, 40 tools, 70 migrations)

## Sprint C — COMPLETE
- C1: Remediation engine — DONE (e83440b)
- C2: Copilot API — DONE (d14f88a)
- C3: License enforcement — DONE (846ec54)

## Post-Sprint C (2026-04-07/08)
- Entity graph: migration 069, entity persistence in store.py, 5 API endpoints, cross-tenant entities
- Dashboard revamp: sidebar nav (web-admin), auto-templates field fix (port 3000)
- Security: curl|bash + reverse shell patterns (content scanner + signal boost)
- Data flow: docs/DATA_FLOW.md — complete field-level pipeline trace
- Manifest: scripts/generate_manifest.sh — auto-inventory of codebase

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
