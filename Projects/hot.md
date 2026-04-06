# HOT CACHE
# Updated: 2026-04-06 (commit 5dfa89c)
# Read this FIRST. Skip CLAUDE.md unless you need deep detail.

## Current State
- Branch: v3.3-dev
- Regression: 16/16 (Path C included)
- Dedup: 14/14
- Services: 17 containers running (11 defined, 6 from profiles)
- Tests: 458 pass, 35 fail (3 bundle import path, 4 known, rest pre-existing)
- Last commit: 5dfa89c refactor(project): split Kanban into active/completed/constraints
- Healer: restarted (was at 509MB/512MB, now 41MB — leak active)

## Active Sprint: C — Pipeline Integration
- C1: Remediation engine — NOT STARTED
- C2: Copilot API — NOT STARTED
- C3: License enforcement — NOT STARTED

## Blocked
- E1: Model benchmark — needs 48h stable pipeline
- E3: Fine-tuning pilot — needs 200 DPO pairs

## Critical Context
- Full invariants + decisions: Projects/Constraints.md
- Migration 066 applied. All 11 tables exist, but attack_paths/remediation/bundles have 0 rows.
- 145 API routes registered. Forge + zvadmin + analytics all functional.
- Stale Ollama refs remain in docker-compose.airgap.yml, docker-compose.test.yml, dpo/ (profile-gated, non-critical)

## Anti-Patterns (Top 5 Recent)
- Don't HTTP self-call from Go API (hits own rate limiter)
- Don't call Python functions directly (test through API)
- Don't scan tool stdout in signal boost (scan SIEM data only)
- Don't use str.format() with JSON (use .replace() or {{ }})
- Don't hardcode model names (use env vars — fixed nemotron refs in healer + error_context.go)

## Files You'll Probably Touch
- worker/intelligence/remediation.py (Sprint C1)
- worker/intelligence/copilot.py (Sprint C2)
- worker/bundles/license.py (Sprint C3)
- api/main.go (route registration)
- web-admin/src/ (dashboard updates)
