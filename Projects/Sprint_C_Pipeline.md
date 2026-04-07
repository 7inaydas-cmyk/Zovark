---
kanban-plugin: basic
---

## Acceptance Criteria

- [ ] verify_all.sh 16/16 after each task
- [ ] Remediation circuit breaker prevents infinite verification loops (max 3 per type per 24h)
- [ ] Copilot explain returns explanation in <5s (on Gemma 4 E4B)
- [ ] License expiry deactivates premium tier, community plans continue working
- [ ] All new endpoints require JWT auth (existing authMiddleware)
- [ ] Copilot LLM calls never starve pipeline verdicts (Semaphore(1) carved from CODE budget)
- [ ] No modifications to investigation_workflow.py
- [ ] All DB queries include tenant_id (WHERE tenant_id = $1)

## C1: Remediation Engine

- [x] Create worker/intelligence/remediation.py
- [x] RemediationEngine class with suggest_action() deterministic rules
- [x] Circuit breaker: MAX_VERIFICATION_ATTEMPTS = 3 per attack_type per 24h
- [x] Rate limiter: MAX_SYNTHETIC_PER_HOUR = 10 per tenant
- [x] Kill switch: system_configs `remediation.auto_verify_enabled` (default false)
- [x] Regression check logic: submit test alert of same type, compare verdict, NOT actual remediation check
- [x] Suggestion engine: deterministic rules based on attack_type + historical success rates
- [x] API: POST /api/v1/remediation/suggest {investigation_id}
- [x] API: POST /api/v1/remediation/verify {remediation_id}
- [x] API: GET /api/v1/remediation/actions {tenant_id, status filter}
- [x] Go handlers: api/remediation_handlers.go
- [x] Route registration in main.go
- [x] Unit tests: circuit breaker opens after 3, rate limiter blocks at 10, kill switch disables
- [x] verify_all.sh 16/16

## C2: Copilot API

- [x] Create worker/intelligence/copilot.py
- [x] explain(investigation_id) — CODE model with deterministic fallback
- [x] suggest(investigation_id) — deterministic rules + optional LLM narrative
- [x] correlate(investigation_id) — DB query by source_ip, username, task_type
- [x] brief(hours) — aggregate stats + optional LLM narrative
- [x] Copilot semaphore: asyncio.Semaphore(1) carved from CODE budget
- [x] Priority: copilot calls get role=summary (CODE semaphore), pipeline priority preserved
- [x] All queries WHERE tenant_id = $1
- [x] Go handlers: api/copilot_handlers.go
- [x] API: POST /api/v1/copilot/explain {investigation_id}
- [x] API: POST /api/v1/copilot/suggest {investigation_id}
- [x] API: POST /api/v1/copilot/correlate {investigation_id}
- [x] API: POST /api/v1/copilot/brief {hours}
- [x] Route registration in main.go (accessible to admin + analyst)
- [x] 13 unit tests (explain/brief fallbacks, suggest, semaphore, hour limits)
- [x] verify_all.sh 16/16

## C3: License Enforcement

- [x] Create worker/bundles/license.py
- [x] Ed25519 signature verification on license payload (cryptography lib)
- [x] Fail-closed: any error → DENY premium access (Invariant #6)
- [x] Grace period: 30 days (encoded in signed payload, NOT configurable)
- [x] License payload: {tenant_id, tier, features, expires_at, grace_days, signature}
- [x] System_configs: license.public_key, license.payload
- [x] API: GET /api/v1/admin/license/status
- [x] API: GET /api/v1/admin/license/verify
- [x] API: POST /api/v1/admin/license/install
- [x] Migration 068: license system_configs entries
- [x] scripts/generate_test_license.py (dev keypair + install)
- [x] 11 unit tests (valid/expired/grace/tampered/missing/denied/cache)
- [x] verify_all.sh 16/16

## Done (Sprint A + B)

- [x] A1: Migration 066 — 11 tables, RLS, partitioned asset_occurrences
- [x] A2: Bundle schema — Pydantic models, Ed25519, size limits
- [x] A3: Security gates — 3-phase SAST + DAST
- [x] A4: Bundle importer — atomic, semver, generation pinning, rollback
- [x] A5: Unit tests — 25 tests for bundle system
- [x] B1: Dynamic plan loading — DB first, tier enforcement
- [x] B2: Attack path correlator — 5 rules, confidence, DLQ
- [x] B3: Contextual risk scoring — conservative multipliers
- [x] B4: Store NOTIFY — attack_path_correlate trigger

## Risks

- [ ] RISK: Copilot Semaphore(1) may not be enough during peak. MITIGATION: Monitor queue wait time. If >10s avg, consider Semaphore(2) with explicit pipeline priority.
- [ ] RISK: Regression check could create infinite loops if remediation repeatedly fails. MITIGATION: Circuit breaker (3 attempts max per 24h) + kill switch in system_configs.
- [ ] RISK: License enforcement could lock out customers if Ed25519 key rotates mid-grace. MITIGATION: Accept signatures from current OR previous key (30-day window).
