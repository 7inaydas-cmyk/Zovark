# HOT CACHE
# Updated: 2026-04-10 (hydra purge complete, 26B connected)
# Read this FIRST. Skip CLAUDE.md unless you need deep detail.

## Current State
- Branch: v3.3-dev
- Regression: 16/16 (with 26B connected)
- Unit tests: 534/534
- Tools: 42 (detect_credential_access + detect_supply_chain)
- Content scanner: 87 patterns, signal boost: 11
- FAST: Gemma 4 E4B (local, llama-server, ~30 tok/s)
- CODE: Gemma 4 26B-A4B (ROG 100.100.79.83, llama-server, 77 tok/s)
- Path C: WORKING with REAL verdicts — risk=100 completed (was: risk=0 timeout)
- Benign: 0-2s, 0% FP (skips LLM entirely)
- Entity graph: 213 entities, 243 edges

## Dual-Endpoint (LIVE)
- FAST: http://zovark-inference:8080 (Gemma 4 E4B, local)
- CODE: http://100.100.79.83:8080 (Gemma 4 26B-A4B, ROG via Tailscale)
- Health check: check_endpoint_health() on startup
- Degradation: 3 CODE failures → fall back to FAST
- Ollama: BANNED (supply chain risk, GBNF incompatible)
- Gemma 4 thinking: reasoning_effort=none for prose, thinking enabled for GBNF grammar

## Known Issues
- Store stage: rare race where Temporal workflow completes but DB row stays pending
- Path C novel types: occasional 500 from ROG 26B tool selection (fail-closed OK)
- FIXED 2026-04-09: GBNF + thinking tokens — sanitizer strips <channel|>...<channel|>
- FIXED 2026-04-09: Forge dedup collision — unique source_ip per alert via index
- FIXED 2026-04-09: CODE cascade timeout — semaphore(2), non-blocking summary with wait_for(30)
- FIXED 2026-04-09: Validator too strict — tools_executed populated in ExecuteOutput

## 100-Alert Stress Results (post-fix)
- 100 unique tasks created (was ~10)
- 98/100 completed in 130s
- Attacks: avg 85s P95 122s (was avg 176s P95 403s)
- Benign: avg 67s P95 104s (was avg 173s P95 413s)
- 0 validation failures, 0 benign FP, 0 cascade timeouts
- 2 pending: Path C 500 from ROG (fail-closed edge case)

## 1000-Alert Results (4 bugs fixed)
- 1000 submitted, 999 unique (dedup_count=1), 0 HTTP errors
- 197 completed before backpressure hard limit kicked in
- Verdicts (197): 135 TP avg 95.4, 61 benign avg 0.0, 1 Path C needs_review
- 0% benign FP (0/61), 100% attack classification accuracy
- Path C unusual_network_traffic: risk=100, completed (was timeout)
- See docs/BENCHMARK_1000_ALERT_v2.md
- Bug 4 discovered: rate limiter + silent Forge 429s → `X-Zovark-Internal: forge` bypass

## 1000-Alert Results FULL (2/sec, campaign mode)
- 1000 submitted, 873 completed, 127 backpressure orphans
- 0 dedup, 0 HTTP errors, 0 validation failures
- Detection rate: 91.0% (559/614 attacks → true_positive)
- Benign FP rate: 0.0% (0/259 clean benign)
- Separation gap: 88.3 points
- All 6 high-confidence attacks (c2, lateral, exfil, kerberos, ransom, golden): 100% at risk 100
- brute_force: 100% at risk 95, phishing: 100% at avg 78
- lolbin_abuse: 48% (55 novel PowerShell -enc variants scored 15 → calibration gap)
- Latency queue-dominated: avg 391s P50 428s P95 667s
- Entity graph: +1708 entities, +1076 edges during this run
- Worker throughput: ~42/min (16 activities × 27s per assess)
- Next run: submission ≤0.7/sec to avoid backpressure orphans
- See docs/BENCHMARK_1000_ALERT_FULL.md

## Sprint C — COMPLETE
- C1: Remediation engine — DONE
- C2: Copilot API — DONE
- C3: License enforcement — DONE

## Next Sprint: D — Bundle Distribution
- D1: zvadmin bundle CLI
- D2: OTA sync service

## Hydra Purge (2026-04-10)
- Compose service: `redis:` → `valkey:` (was already running valkey/valkey:7-alpine, just hadn't been renamed)
- Container: `zovark-redis` → `zovark-valkey`
- Volume: `redis_data` → `valkey_data`
- Compose project: `hydra-mvp` → `zovark` (set via .env COMPOSE_PROJECT_NAME). All new container/network/volume names get the `zovark_*` prefix.
- Passwords renamed: `hydra_dev_2026` → `zovark_dev_2026`, `hydra-redis-dev-2026` → `zovark_valkey_dev_2026`, `hydra-nats-dev-2026` → `zovark_nats_dev_2026`
- Env vars: `REDIS_URL/REDIS_PASSWORD` → `VALKEY_URL/VALKEY_PASSWORD` (legacy REDIS_* kept as fallback)
- Python `import redis` library KEPT — Valkey is wire-compatible and no `valkey-py` library exists
- Old `hydra-mvp_*` Docker volumes are now orphaned (intentional — fresh data start)

## Anti-Patterns
- Don't use .* in regex (ReDoS) — split into independent re.search() calls
- Don't use fmt.Sprintf for JSON — use json.Marshal
- Don't use Ollama — llama-server only
- reasoning_effort=none for prose, thinking enabled for GBNF grammar
- License check errors → DENY (fail-closed, Invariant #6)
- Don't only test sequentially — run 100-alert Forge before benchmarking
- Forge must produce unique source_ip per alert (dedup collision)
- LLM summary MUST be non-blocking (asyncio.wait_for + template fallback)
- CODE semaphore = 2, not 3 (ROG 26B returns 500 at 3 concurrent)
- Don't ship hydra-* references in new code — full purge done 2026-04-10
