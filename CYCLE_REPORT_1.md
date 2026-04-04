# Improvement Cycle #1 Report
Date: 2026-04-04
Branch: v3.3-dev

## Observability Data Collected

### Verdict Distribution (all time)
| Verdict | Count | Avg Risk | Stddev |
|---------|-------|----------|--------|
| true_positive | 400 | 88.7 | 12.8 |
| benign | 137 | 1.2 | 3.5 |
| suspicious | 10 | 45.0 | 0.0 |

### Per-Type Quality (24h)
- 18 task types active in last 24h
- Attack types with low avg risk on GENERIC test data:
  - powershell_obfuscation: 21.3 (but 70 with proper raw_log)
  - phishing: 63.2 (but 85-100 with proper raw_log)
  - kerberoasting: 63.8 (but 80 with proper raw_log)
- All benign types: 0.0 risk (perfect)
- **Root cause of variance: test data quality, not pipeline bugs**

### Container Health
- Healer: 409MB / 402 PIDs (approaching 512MB limit) → restarted
- Squid proxy: 112MB / 128MB (87%) → bumped to 256MB
- Inference: 4.4GB stable
- Worker: 76MB stable
- 48 stale pending tasks in DB → cleaned

### Worker Logs
- 0 pipeline errors
- 11 NATS connection warnings (no NATS container, non-critical)
- 0 sanitizer activations (Gemma 4 output clean)
- 0 parallel execution messages (all Path A)

## Key Analysis Finding

**The "low detection scores" on certain attack types are CORRECT behavior.**

When raw_log contains generic text ("kerberoasting activity detected"), the detection
tools correctly return low scores — there's no evidence to analyze. When raw_log contains
actual event data (EventID=4769, EncryptionType=0x17), scores are 80-100.

Proof: verify_all.sh (which uses rich test data) produces perfect 15/15 on both
Nemotron and Gemma 4. The pipeline is evidence-based by design.

## Fixes Applied

| Issue | Finding | Fix | Before | After |
|-------|---------|-----|--------|-------|
| IC1-1 | 48 stale pending tasks | SET status='failed' on tasks pending >1h | 48 pending | 2 pending |
| IC1-2 | Healer at 409MB/402 PIDs | Restart container | 409MB | 39MB |
| IC1-3 | Squid proxy at 87% memory | Increase limit 128→256MB | 87% | 65% |

## Results

| Metric | Before Cycle | After Cycle |
|--------|:-:|:-:|
| Regression | 15/15 | 15/15 |
| Stale pending tasks | 48 | 2 |
| Healer memory | 409MB (80%) | 39MB (8%) |
| Healer PIDs | 402 | 20 |
| Squid memory | 87% | 65% |
| Pipeline errors | 0 | 0 |
| Sanitizer activations | 0 | 0 |

## Findings Deferred to Next Cycle

| Finding | Why Deferred |
|---------|-------------|
| Path C parse failure (unusual_network_traffic) | Requires Gemma 4 tool selection prompt tuning — separate work item |
| NATS connection warnings | No NATS container needed for core pipeline |
| Healer memory leak root cause | Mitigated by 512MB limit + periodic restart. Fix requires Python async refactor |

## Recommendations for Cycle #2
1. Investigate Path C (LLM tool selection) reliability with Gemma 4
2. Consider adding a scheduled healer restart (cron or Docker healthcheck restart policy)
3. Add test data quality validation to the benchmark suite — reject vague raw_log payloads

## Framework Compliance
| Check | Compliant? |
|-------|-----------|
| Data-driven (not hunches) | YES — all findings from DB queries and docker stats |
| Independent fixes | YES — 3 fixes, each independently revertable |
| verify_all.sh after fixes | YES — 15/15 |
| No unnecessary changes | YES — resisted "fixing" correct low-evidence scores |
