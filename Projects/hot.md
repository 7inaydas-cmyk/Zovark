# HOT CACHE
# Updated: 2026-04-06 (commit 147157e)
# Read this FIRST. Skip CLAUDE.md unless you need deep detail.

## Current State
- Branch: v3.3-dev
- Regression: 16/16 (Path C included)
- Dedup: 14/14
- Services: 17 containers running
- Last commit: 147157e fix(forge): use DB-direct queries instead of HTTP self-calls

## Active Sprint: C — Pipeline Integration
- C1: Remediation engine — NOT STARTED
- C2: Copilot API — NOT STARTED
- C3: License enforcement — NOT STARTED

## Blocked
- E1: Model validation benchmark — need 48h stable pipeline
- E3: Fine-tuning pilot — need 200+ DPO pairs (no analysts yet)

## Critical Context (Don't Forget)
- Migration 066 creates 11 tables. Already applied.
- Detection tools activate ONLY after worker restart.
- Plans are instance-scoped, NOT tenant-scoped.
- Fail-closed on license check errors.
- The "Go Lua dedup bug" was a test bug. Lua is correct.
- Path C timeout on CPU is expected — fail-closed to needs_manual_review.
- Forge collector must query DB directly (not HTTP self-call — hits rate limiter).

## Anti-Patterns (Top 5 Recent)
- Don't HTTP self-call from Go API (hits own rate limiter) — fixed in 147157e
- Don't call Python functions directly (test through API)
- Don't scan tool stdout in signal boost (scan SIEM data only)
- Don't use str.format() with JSON (use .replace() or {{ }})
- Don't test only Path A types (include Path C unusual_network_traffic)

## Files You'll Probably Touch
- worker/intelligence/remediation.py (Sprint C1)
- worker/intelligence/copilot.py (Sprint C2)
- worker/bundles/license.py (Sprint C3)
- api/main.go (route registration for new endpoints)
- web-admin/src/ (dashboard updates)
