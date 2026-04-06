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

## Process (2026-04-06)
- Kanban boards + engineering process
- Hot cache (Projects/hot.md)
- Architecture linter (12 checks)
- Board restructure (active/completed/constraints split)
