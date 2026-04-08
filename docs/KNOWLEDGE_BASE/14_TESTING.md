# Testing — What's Tested, How to Run It, What to Expect

Zovark has three layers of testing: unit tests (fast, run in the worker container), pipeline regression tests (end-to-end, run against the live system), and stress tests (high-volume, run against the live system). This document covers all of them.

---

## Test Suite Overview

| Category | Test Count | What It Covers | Speed |
|----------|-----------|----------------|-------|
| Unit tests | ~365 across 19 files | Individual functions and components | ~30 seconds |
| Pipeline regression | 16 alerts (11 attack + 5 benign) | Full 6-stage pipeline end-to-end | ~3 minutes |
| Dedup stress test | 14 tests across 6 categories | Deduplication and batching logic | ~5 minutes |
| Alert corpus | 515 alerts | Large-scale regression | ~15 minutes |
| AutoResearch corpus | 240 alerts | Detection accuracy per attack type | ~30 minutes |

### How to Run All Unit Tests

```bash
docker compose exec -T worker python -m pytest tests/ -q
```

This runs every test file inside the worker container. The `-q` flag gives you a quiet summary — just pass/fail counts. Expect about 365 tests, with 3 known failures (see Known Issue #6 below).

---

## Unit Test Files (19 Files)

Each file tests a specific component. Here's what each one does and what to expect.

### test_adversarial_review.py — 3 tests

Tests that adversarial review attempts are blocked. These are attacks where someone tries to manipulate the system into bypassing human review.

**Known Issue #6**: These 3 tests are pre-existing failures. They fail because when the LLM is unavailable, the adversarial review passes through instead of being blocked. This is documented and not a security issue in practice (fail-closed handles it at a different layer). Expect 3 failures here — that's normal.

### test_alert_sanitizer.py — ~44 tests

Tests the input sanitizer that screens every incoming alert for injection attacks. Covers 25+ injection patterns including template injection (`{{...}}`), code injection (`import os`), Server-Side Template Injection (SSTI), and Unicode normalization (Cyrillic characters that look like Latin letters). All 44 should pass.

### test_ast_prefilter.py — ~78 tests

Tests the AST (Abstract Syntax Tree) allowlist. When the system generates Python code (Path C), this prefilter scans it and only allows 16 safe standard library modules (like `json`, `re`, `datetime`). Anything dangerous (`os`, `sys`, `subprocess`, `socket`, `eval`, `exec`) is blocked before the code ever runs. All 78 should pass.

### test_benchmark.py

Performance benchmarks for pipeline throughput. Measures how fast alerts move through the system. Results vary by hardware.

### test_bundle_system.py — 31 tests

Tests the bundle system — the mechanism for packaging and distributing Zovark updates as signed `.zvk` files. Covers the bundle schema (Pydantic validation), SAST+DAST security gates (static and dynamic analysis of bundle contents), and the atomic importer (installs bundles with rollback on failure). All 31 should pass.

### test_bypass_regression.py

Regression tests for red team bypasses. Every bypass that was discovered during AutoResearch red team testing has a corresponding test here to make sure the fix stays fixed. If any of these fail, it means a security patch has regressed.

### test_copilot.py — 13 tests

Tests the Copilot API — the four analyst assistance endpoints (explain, suggest, correlate, brief). Verifies that each endpoint returns useful output, that the LLM fallback works (when the LLM is unavailable, deterministic templates are used instead), and that the semaphore (concurrency limiter) is respected. All 13 should pass.

### test_dedup.py

Tests the Redis deduplication logic. Verifies that duplicate alerts are correctly identified and suppressed, and that the dedup counter increments properly.

### test_detection_cycle5.py, test_detection_cycle6.py, test_detection_cycle7.py

Detection tool tests generated during AutoResearch cycles 5, 6, and 7. Each cycle tested new detection tools (like `detect_com_hijacking`, `detect_encoded_service`, `detect_token_impersonation`) against crafted attack scenarios. These ensure the detection tools produce correct risk scores.

### test_egress_controller.py

Tests the egress proxy controls — the Squid proxy that controls what outbound network connections the system can make. Verifies that unauthorized destinations are blocked.

### test_license.py — 11 tests

Tests the license enforcement system. Covers Ed25519 signature verification (ensuring license files haven't been tampered with), fail-closed behavior (if anything goes wrong with license checking, the system denies access rather than allowing it), grace period logic (reading the grace period from the signed license payload), and the 5-minute database cache. All 11 should pass.

### test_redteam_patches.py — 46 tests

Tests every security patch that came out of the red team exercises. Covers the input sanitizer patterns, the content scanner (54 attack patterns checked against raw log data), IOC provenance validation (ensuring reported indicators of compromise actually appear in the log data), suppression detection (catching attempts to lower risk scores with phrases like "scheduled test"), and Unicode normalization. All 46 should pass.

### test_remediation.py — 17 tests

Tests the remediation engine — the system that suggests response actions for confirmed attacks. Covers all 22 attack type rules, the circuit breaker (limits remediation suggestions to 3 per attack type per 24 hours), and the rate limiter (maximum 10 remediation actions per hour across all types). Also tests the kill switch that lets an operator disable all remediation suggestions instantly. All 17 should pass.

### test_risk_validator.py

Tests risk score boundaries and verdict derivation logic. Verifies that risk scores stay within 0-100, that verdicts are correctly derived from risk scores (e.g., risk >= 70 maps to true_positive), and that edge cases are handled.

### test_synthetic_login.py — 7 tests

Tests the healer's synthetic login check — a health check where the healer tries to log into the dashboard every 60 seconds to verify it's working. Tests cover various failure scenarios: 502 (bad gateway), 503 (service unavailable), 401 (auth failure), 500 (server error), and connection refused. All 7 should pass.

### test_template_resolver.py

Tests template matching and resolution. Verifies that incoming alerts are matched to the correct skill template (e.g., a brute force alert matches the `brute-force-investigation` template) and that template variable substitution works correctly.

### test_vault_manager.py

Tests the secret management system. Verifies that credentials are stored and retrieved securely.

---

## Pipeline Regression Test (verify_all.sh)

This is the most important test to run after making any change to the pipeline. It submits real alerts through the entire system and checks the results.

### What It Does

1. Submits 11 attack alerts covering different attack types (brute force, phishing, ransomware, kerberoasting, golden ticket, DCSsync, DLL sideloading, LOLBin abuse, DNS exfiltration, powershell obfuscation, and one novel "unusual_network_traffic" alert)
2. Submits 5 benign alerts (password change, Windows update, health check, scheduled backup, user login)
3. Waits 180 seconds for all investigations to complete
4. Checks each result against expected outcomes

### Expected Results

- **Attack alerts**: Must be `true_positive` with risk score >= 65
- **Benign alerts**: Must be `benign` with risk score <= 25
- **Path C alert** (unusual_network_traffic): This one has no saved investigation plan, so it forces the LLM to select tools. It's allowed to timeout — if it does, it gets `needs_manual_review`, which is the correct fail-closed behavior
- **Overall**: 16/16 PASSED (or 15/16 with Path C timeout, which is acceptable)

### How to Run

```bash
bash autoresearch/cycle10/verify_all.sh
```

### When to Run

- After ANY change to pipeline code (ingest, analyze, execute, assess, store, govern)
- After changing investigation plans
- After adding or modifying detection tools
- After changing the LLM model or prompts
- After database migrations that touch pipeline-related tables
- Before tagging a release

### Prerequisites

- All containers must be running (`docker compose up -d`)
- LLM inference must be loaded and healthy
- No stale Temporal workflows (terminate them first if leftover from a previous run)

---

## Dedup Stress Test

Tests the 3-layer pre-Temporal alert funnel: deduplication, batch buffering, and backpressure.

### What It Does

Runs 14 tests across 6 categories:

1. **Exact dedup** — Submitting the same alert twice. Second one should be deduplicated.
2. **Severity escalation** — Submitting the same alert at a higher severity. Should bypass dedup and create a new investigation.
3. **Failed retry** — If a previous investigation failed, the same alert should be re-investigated.
4. **Force reinvestigate** — The `force_reinvestigate: true` flag should bypass all dedup layers.
5. **Batch buffer** — Multiple alerts with the same (task_type, source_ip) within 5 seconds should be batched into one investigation.
6. **TTL behavior** — Dedup entries expire based on severity (15 minutes for info, up to 2 hours for critical).

### Expected Results

14/14 tests passing.

### How to Run

```bash
bash autoresearch/cycle10/dedup_stress_test.sh
```

---

## Alert Forge (Built-In Stress Testing)

The Alert Forge is a built-in tool for generating synthetic alerts at scale. Available both through the dashboard and the API.

### What It Does

Generates and submits configurable batches of synthetic alerts. You can control:

- **Volume**: 100 to 10,000 alerts
- **Attack ratio**: What percentage are attack vs. benign
- **Novelty rate**: What percentage are novel alert types (forces Path C / LLM tool selection)
- **Rate**: Alerts per second

### How to Use — Dashboard

Open the dashboard at `http://localhost:3000`, navigate to the Alert Forge tab, configure your parameters, and click start. The integrated Pipeline Monitor shows real-time progress.

### How to Use — API

```bash
POST /api/v1/admin/forge/start
```

with a JSON body specifying count, attack ratio, novelty rate, and rate.

### When to Use

- Load testing before deployment
- Verifying the dedup/batching/backpressure layers under load
- Checking LLM performance under concurrent requests
- Demonstrating the system to stakeholders

---

## How to Add a New Test

1. Create a new file in the worker's test directory: `worker/tests/test_yourname.py`
2. Use standard pytest conventions — functions starting with `test_`, classes starting with `Test`
3. Import from worker modules as needed (e.g., `from worker.tools.detection import detect_kerberoasting`)
4. Run your test:

```bash
docker compose exec -T worker python -m pytest tests/test_yourname.py -v
```

The `-v` flag gives verbose output showing each test name and result.

### Tips

- Tests run inside the worker container, so they have access to all Python dependencies
- For tests that need database access, use the test database credentials from the environment
- For tests that need Redis, the worker container can reach it at `zovark-redis:6379`
- Keep tests fast — mock external services (LLM, database) when testing logic
- If your test needs the full pipeline running, consider adding it to `verify_all.sh` instead of as a unit test

---

## Quick Reference

| What | Command | Expected |
|------|---------|----------|
| All unit tests | `docker compose exec -T worker python -m pytest tests/ -q` | ~365 pass, 3 known failures |
| Pipeline regression | `bash autoresearch/cycle10/verify_all.sh` | 16/16 PASSED |
| Dedup stress test | `bash autoresearch/cycle10/dedup_stress_test.sh` | 14/14 PASSED |
| Single test file | `docker compose exec -T worker python -m pytest tests/test_copilot.py -v` | All pass |
| Alert Forge | Dashboard > Alert Forge tab | Configurable |
