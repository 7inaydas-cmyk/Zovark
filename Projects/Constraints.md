# Constraints & Decisions

## Invariants (Never Violate)

1. DO NOT modify investigation_workflow.py
2. DO NOT break two-model FAST/CODE architecture
3. All bundle code through AST prefilter + runtime SAST
4. verify_all.sh 16/16 after EVERY change
5. Additive-only migrations (safe rollback)
6. License check errors -> DENY (fail-closed)
7. Detection tools activate ONLY after worker restart
8. Plans instance-scoped, tier enforced at query time
9. No LLM on SAST path
10. No customer data in telemetry without opt-in
11. Copilot LLM calls deprioritized below pipeline
12. Attack path failures -> DLQ + alert

## Decisions Made

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-05 | Keep Gemma 4 E4B | Swap only if benchmark fails |
| 2026-04-05 | REASON = testing only | Not production dependency |
| 2026-04-05 | 2 models, not 5 | Prove need first |
| 2026-04-05 | Plans instance-scoped | Tier check at query time |
| 2026-04-05 | No LLM for SAST | Deterministic only |
| 2026-04-05 | Cut StarCoder2 | AST + patterns sufficient |
| 2026-04-05 | Defer copilot patch | Post-MVP |
| 2026-04-06 | Dedup Lua correct | Test bug, not code bug |
| 2026-04-06 | Auto-verify = regression | Not remediation check |
| 2026-04-06 | Conservative multipliers | 0.72x-1.87x range |
| 2026-04-06 | Confidence threshold 0.75 | Reduce false correlations |
| 2026-04-06 | DB-direct for forge | HTTP self-calls hit rate limiter |
| 2026-04-06 | Hot cache + linter | Faster sessions, catch drift |
| 2026-04-06 | Board split (active/completed/constraints) | Roadmap was unreadable |
| 2026-04-06 | Healer needs periodic restart | 509MB/512MB after ~3hrs, leak unfixed |
| 2026-04-07 | Copilot semaphore(1) from CODE budget | Pipeline priority preserved (Invariant #11) |
| 2026-04-07 | License fail-closed on all errors | Invariant #6 enforcement |
| 2026-04-07 | Copilot Go-side deterministic first | LLM via Temporal activity for production |
| 2026-04-07 | Sprint C complete | All 3 tasks shipped, regression 16/16 |
| 2026-04-08 | Knowledge base v1.1 created | 16 files, 38k words, 132 functions — full system docs for non-technical readers |
| 2026-04-08 | Entity graph fire-and-forget | Non-fatal persistence, pipeline never crashes on graph errors |
| 2026-04-08 | Content scanner broadened | curl|bash patterns now match flags before http (was a gap) |
| 2026-04-09 | detect_data_exfil floor requires 2+ findings | Single cloud storage mention = benign. Multiple indicators needed. |
| 2026-04-09 | detect_golden_ticket boost gated on keywords | Only tool/technique names (mimikatz, forged) trigger 75 floor, not structural matches |
| 2026-04-09 | detect_kerberoasting caps krbtgt risk | krbtgt TGS + RC4 = min(risk, 35), not max — it's a TGT renewal, not kerberoasting |
| 2026-04-09 | CODE endpoint graceful degradation | After 3 consecutive failures, fall back to FAST. Resets on success. |
| 2026-04-09 | Ollama banned | Supply chain risk, incompatible with GBNF grammar, reasoning_content field issues. Use llama-server only. |
| 2026-04-09 | Gemma 4 26B-A4B over 31B dense | MoE activates 4B/token from 26B total. 5-7x faster (77 vs ~15 tok/s). Path C 7s vs timeout. |
| 2026-04-09 | reasoning_effort=none for prose only | GBNF grammar needs thinking for quality tool selection. Prose (summaries) disables thinking. |
| 2026-04-09 | 1000-alert test exposed 3 bugs | Semaphore(1) cascade timeout, Forge dedup collision, validator too strict. Root cause: all prior tests were sequential (16/16) or tiny (smoke). Added anti-pattern: always test concurrent load against remote endpoints before benchmarking. |
| 2026-04-09 | CODE semaphore = 2 (not 3) | ROG 26B returns 500 errors at 3 concurrent (KV pressure). 2 is the sweet spot — GPU stays busy, no OOM. |
| 2026-04-09 | LLM summary only for high-risk true_positives | Summary is cosmetic. Reserving the 26B for (verdict=true_positive AND risk>=70) cuts queue depth by ~50% and keeps benign alerts fast. |
| 2026-04-09 | Summary is non-blocking with 30s ceiling | Pipeline sets template summary first, tries LLM with asyncio.wait_for(30). If it hits the ceiling, template stays. Verdict/risk are never delayed by LLM. |
| 2026-04-10 | Full hydra purge | All `hydra_*` and `hydra-redis-*` passwords renamed to `zovark_*_dev_2026`. Compose service `redis:` → `valkey:`, container `zovark-redis` → `zovark-valkey`, volume `redis_data` → `valkey_data`. Env vars promoted to `VALKEY_*` with `REDIS_*` legacy aliases. `COMPOSE_PROJECT_NAME=zovark` (was implicit `hydra-mvp` from directory name). Python `import redis` library KEPT — Valkey is wire-compatible and no `valkey-py` library exists. Triggered by fresh-data migration to new Ubuntu machine. |
