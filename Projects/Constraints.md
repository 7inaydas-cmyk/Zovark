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
