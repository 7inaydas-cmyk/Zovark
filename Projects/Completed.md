# Completed Work -- v3.3-dev

## Sprint A: Bundle Foundation (2026-04-06)
- Migration 066 (11 tables, RLS, partitioned)
- Bundle schema (Pydantic, Ed25519, size limits)
- Security gates (3-phase SAST + DAST)
- Bundle importer (atomic, semver, rollback)
- Unit tests (25 tests)

## Sprint B: Intelligence Layer (2026-04-06)
- Dynamic plan loading in analyze.py
- Attack path correlator (5 rules, DLQ)
- Contextual risk scoring (0.72x-1.87x)
- Store NOTIFY trigger
- Risk calibration anchor loading

## Operator GUI (2026-04-06)
- Zvadmin web panel (5 commands)
- Alert Forge (mass generator, SSE, charts)
- Analytics dashboard
- Investigation detail view
- Go API handlers (zvadmin + forge + scenarios)
- Dashboard fixes (CORS, proxy, config fields, OOB transform, error boundary)
- Forge collector: DB-direct queries (HTTP self-call hit rate limiter)

## Quick Wins (2026-04-05)
- Path C regression: 15/15 -> 16/16
- Dedup fix: test bug, Lua was correct
- Web-admin nginx on :3100
- Gemma 4 E4B model swap
- Path C str.format() fix
- MITRE propagation (100% coverage)
- Parallel tool execution (flag-gated)
- RLS migration 065
- Healer memory limit (512MB)

## Sprint C1: Remediation Engine (2026-04-06)
- worker/intelligence/remediation.py (22 attack types, circuit breaker, rate limiter)
- api/remediation_handlers.go (suggest, verify, list, patch)
- migration 067 (audit event types + kill switch config)
- 17 unit tests (rules, circuit breaker, rate limiter, stats)

## Detection Calibration (2026-04-06)
- golden_ticket: 10→91.7 avg (keyword scanning + abnormal lifetime)
- kerberoasting: 58→94 avg (EncryptionType alias + keyword fallback)
- ransomware: 60.7→77.5 avg (family name keywords)
- data_exfil: 51→70 avg (exfil shorthand + DNS tunnel patterns)
- phishing BEC: 20→90 (executive impersonation + wire transfer)

## Dashboard v1 (2026-04-06)
- PipelineMonitor.tsx (status bar, metrics, stages, charts, activity log)
- AnalyticsPanel fixes (top_attacks, computed total, risk_buckets)
- AlertForge SSE reconnect with backoff + ?token= auth
- GET /api/v1/admin/pipeline/status endpoint

## Security Hardening (2026-04-06/07)
- ReDoS: split compound .* regex into independent searches (3.4s→0.22s)
- ReDoS: 4KB parse guard in parse_windows_event
- JSON injection: json.Marshal instead of fmt.Sprintf in remediation
- Info disclosure: generic "not found" errors
- Red team: 7 E2E bypasses patched (66 content scanner patterns, caret deobfuscation)
- Bundle test fixes: conftest.py, SyntaxError, SAST allowlist, expiry check

## Benchmark (2026-04-06)
- 100-alert test: 88% detection, 0% FP, P50=1.98s, P95=8.6s
- Competitive benchmark doc vs Dropzone AI / Torq HyperSOC

## Process (2026-04-06)
- Kanban boards + engineering process
- Hot cache (Projects/hot.md)
- Architecture linter (12 checks)
- Board restructure (active/completed/constraints split)
