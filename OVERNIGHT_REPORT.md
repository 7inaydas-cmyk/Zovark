# OVERNIGHT BATCH REPORT
Date: 2026-04-05
Branch: v3.3-dev

## Fixes Attempted

| Fix | Status | Detail |
|-----|--------|--------|
| Path C parse failure | **FIXED** | Root cause: Python str.format() KeyError on literal JSON braces in system prompt. Fix: escaped `{{` `}}`. Also increased timeout 30→120s, improved parse resilience. |
| Dedup 13/14 → 14/14 | DIAGNOSED | Batch severity promotion: Go Lua script string comparison issue in batch_buffer.go. Not fixed (Go change, higher risk). |
| PgBouncer zovark_app | SKIPPED | PgBouncer uses env-based auth from docker-compose. Needs custom userlist.txt mount. Deferred. |
| Web-admin serving | SKIPPED | Build exists (web-admin/dist/). Needs nginx service or API static mount. Deferred (no pipeline impact). |

## Critical Fix Detail: Path C

The Path C (LLM tool selection) has been broken since the system prompt was written.
The `_TOOL_CALLING_SYSTEM_PREFIX` string contained `{"steps": [{"tool": "name"}]}`
which Python's `.format(catalog_text=...)` interpreted as format placeholders, causing
`KeyError: '"steps"'`. Every Path C investigation (unknown task types that don't match
saved plans) failed with this error and triggered the circuit breaker to RED.

**Impact:** Any alert type not in investigation_plans.json (e.g., unusual_network_traffic,
log_analysis, custom SIEM rules) was silently failing. The 15/15 regression never caught
this because all 15 test types have saved plans (Path A).

**Fix:** Escaped literal braces as `{{` and `}}` in the JSON example. Verified with
`unusual_network_traffic` task → completed successfully (risk=30, benign verdict appropriate).

## Stress Test Results

| Test | Result | Notes |
|------|--------|-------|
| Pipeline 50 alerts | 20 completed, 30 deduped/batched | Burst protection working correctly |
| Dedup stress suite | 13/14 | Same batch severity promotion failure |
| Memory post-stress | Stable | Inference 4.4→4.8GB (KV cache), healer 209MB/204 PIDs |

## Diagnostics Comparison

| Metric | Baseline | Post-Stress |
|--------|----------|-------------|
| Regression | 15/15 | 15/15 |
| Healer memory | 97MB / 82 PIDs | 209MB / 204 PIDs |
| Worker memory | 76MB | 72MB |
| Inference memory | 4.4GB | 4.8GB |
| Pipeline errors | 0 | 0 |
| Path C working | NO | **YES** |

## Commits Made

1. `3f91516` — fix(analyze): Path C tool selection — escape JSON braces in system prompt

## Action Items for Operator

1. **Path C is now functional** — previously all unknown task types silently failed.
   Consider adding more investigation plans for common Path C task types to avoid
   LLM call overhead (each Path C call costs ~60-120s on CPU).

2. **Dedup batch severity promotion** (13/14) — needs Go code fix in
   `api/batch_buffer.go` Lua script. The severity comparison is string-based,
   not ordinal. Low priority (doesn't affect pipeline verdicts).

3. **Healer memory leak** — 97→209MB in this session (204 PIDs). Will hit 512MB
   limit within ~12 hours. Consider adding a Docker restart policy with
   `--restart-condition on-failure` or a cron restart.

## Risks Found

None critical. Pipeline is stable at 15/15. Path C fix is the significant improvement —
it unblocks all novel/unknown alert types from silently failing.
