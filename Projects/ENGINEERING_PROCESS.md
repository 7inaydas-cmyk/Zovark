# Zovark Engineering Process

How we ship. Every session, every commit, every change.

---

## 1. THE RULE

**Plan -> Implement -> Verify -> Document -> Commit.**

No commit without 16/16 on verify_all.sh.
No implementation without reading affected files first.
No "I'll fix it later."

---

## 2. SESSION START

1. Read: HANDOVER.md, CLAUDE.md, COMPONENT_REGISTRY.md, Projects/Zovark_Roadmap.md
2. Run: `cmd/zvadmin/zvadmin.exe diagnose` — all checks must pass
3. Check: "In Progress" column on Kanban board — pick up where we left off
4. Run: `bash autoresearch/cycle10/verify_all.sh` — must be 16/16 before writing any code

If diagnose fails: fix the infrastructure first, then proceed.
If verify_all.sh fails: investigate and fix the regression before any new work.

---

## 3. TASK EXECUTION

### Before Writing Code
- Check COMPONENT_REGISTRY.md — which files are affected?
- Check anti-patterns table below — am I about to make a known mistake?
- Read the files you're about to modify (never guess behavior)
- State: which pipeline stages affected, which LLM role (FAST/CODE/none)

### During Implementation
- Test through API only: `POST /api/v1/tasks` with real SIEM data
- One logical change per commit (not one file, one *change*)
- Rebuild after Python changes: `docker compose build worker && docker compose up -d worker && sleep 30`
- Rebuild after Go changes: `docker compose build api && docker compose up -d api`

### After Implementation
- Run: `bash autoresearch/cycle10/verify_all.sh` — 16/16
- Run: `docker compose exec -T worker python -m pytest tests/ -q --tb=short`
- Check: `cmd/zvadmin/zvadmin.exe diagnose`
- If any verification fails: revert and try again

---

## 4. COMMIT FORMAT

```
type(scope): description

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

Types:
| Type | When |
|------|------|
| feat | New feature or capability |
| fix | Bug fix |
| test | Adding or fixing tests |
| refactor | Code restructuring without behavior change |
| docs | Documentation only |
| chore | Build, config, project management |
| perf | Performance improvement |

Scope: the subsystem (analyze, assess, forge, bundles, dashboard, etc.)

---

## 5. WHAT TO UPDATE WHEN

| Event | Update These Files |
|-------|--------------------|
| New Python file | COMPONENT_REGISTRY.md |
| New Go file | COMPONENT_REGISTRY.md |
| New DB table | CLAUDE.md (Database section), COMPONENT_REGISTRY.md |
| New API endpoint | CLAUDE.md (API Routes section) |
| New env var | CLAUDE.md (Environment Variables), worker/settings.py |
| New Docker service | CLAUDE.md (Docker Services), docker-compose.yml, COMPONENT_REGISTRY.md |
| Pipeline stage change | CLAUDE.md (Architecture), HANDOVER.md (Key File Map) |
| New investigation plan | worker/tools/investigation_plans.json, catalog.py, tool_subsets.py |
| New detection tool | worker/tools/catalog.py, tool_subsets.py, investigation_plans.json |
| Risk scoring change | Run `zvadmin model check` before and after |
| Model swap | CLAUDE.md, HANDOVER.md, docker-compose.distroless.yml, flush code cache |
| Sprint completed | Projects/Zovark_Roadmap.md, HANDOVER.md (Current State) |
| Decision made | Projects/Zovark_Roadmap.md (Decision Log) |

---

## 6. ANTI-PATTERNS

Real mistakes from this project. Do not repeat.

| # | Anti-Pattern | Why It's Wrong | What To Do |
|---|-------------|----------------|------------|
| 1 | Calling detect_phishing() directly | Bypasses 6-stage pipeline (sanitizer, signal boost, provenance) | Submit via POST /api/v1/tasks |
| 2 | Scanning tool stdout in signal boost | JSON keys trigger false positive regex matches | Signal boost scans raw_log + title + rule_name only |
| 3 | Empty findings -> safe_default(risk=50) | In v3 tools mode, empty findings is valid (nothing suspicious) | Check tools_executed/plan_executed before rejecting |
| 4 | Hardcoding model names | Breaks tier-agnostic pipeline | Read from env vars via settings.py |
| 5 | Modifying investigation_workflow.py | Breaks Temporal state machine | Modify stages, not the orchestrator |
| 6 | Running 100 tests with 100 logins | Triggers rate limiter (10/15min) | Login once, reuse token |
| 7 | Using python3 on Windows host | No Python on this machine | docker compose exec -T worker python |
| 8 | Self-verifying your own output | Confirmation bias masks errors | Use verify_all.sh, multi-agent review |
| 9 | Using str.format() with JSON templates | Literal {} braces are format placeholders | Use .replace() or {{ }} escaping |
| 10 | Testing only Path A types in regression | Path C was broken for months, regression never caught it | verify_all.sh includes Path C (alert #11) |
| 11 | Fixing correct low-evidence scores | Pipeline correctly scores low when raw_log has no evidence | Use realistic SIEM event data in tests |
| 12 | Assuming model fits in Docker memory | Gemma 4 E4B needed 7GB, VM had 5.8GB | Check docker stats + docker info before swaps |
| 13 | KEYS "pattern" | head -1 in Redis tests | Returns wrong key if multiple exist | Compute exact key or flush stale keys first |

---

## 7. QUALITY GATES

| Gate | Command | Pass Criteria | When |
|------|---------|---------------|------|
| Pipeline regression | `bash autoresearch/cycle10/verify_all.sh` | 16/16 (11 attacks + 5 benign) | After ANY change |
| Dedup stress test | `bash autoresearch/cycle10/dedup_stress_test.sh` | 14/14 passed, 0 failed | After dedup changes |
| Unit tests | `docker compose exec -T worker python -m pytest tests/ -q` | All pass (3 known failures excluded) | After Python changes |
| System health | `cmd/zvadmin/zvadmin.exe diagnose` | All checks green | Session start, after infra changes |
| Model calibration | `cmd/zvadmin/zvadmin.exe model check` | Separation gap > 50 points | After scoring changes |
| AutoResearch cycle | `bash autoresearch/telemetry_driven/run.sh` | No new regressions | After significant changes |
| Code cache flush | `scripts/flush_code_cache.sh` | No stale cached responses | After prompt or model changes |
| Arch lint | `bash scripts/lint_architecture.sh` | 0 failures | Before merge, session end |
| Concurrent load test | 100-alert Forge at 5/sec (`POST /api/v1/admin/forge/start`) | ~100 tasks created, 0 cascade timeouts, 0 validation failures, <5 min completion | Before any benchmark, after LLM/endpoint changes |

---

## Architecture Linting

Run `bash scripts/lint_architecture.sh` at session end and before any merge to master.

12 automated checks verify:
1. investigation_workflow.py unmodified
2. Two-model FAST/CODE architecture preserved
3. No cloud SDK imports in pipeline stages
4. Tenant isolation in intelligence layer queries
5. SAST blocklist includes all dangerous modules
6. Bundle importer doesn't hot-load detection tools
7. investigation_plans_db is instance-scoped (no tenant_id)
8. License manager is fail-closed on errors
9. Migration 066 is additive-only (no DROP/TRUNCATE)
10. Regression suite includes Path C
11. No HTTP self-calls in Go API handlers
12. Copilot has semaphore/priority control

If any check FAILS, fix before merging. Warnings get logged to the Kanban board Risks section for review.

---

## 8. RELEASE PROCESS

1. verify_all.sh 16/16
2. dedup_stress_test.sh 14/14
3. Unit tests pass
4. zvadmin diagnose all green
5. zvadmin model check — separation gap healthy
6. Update CLAUDE.md, HANDOVER.md, COMPONENT_REGISTRY.md
7. Update Projects/Zovark_Roadmap.md (move tasks to Done)
8. Commit with descriptive message
9. Tag: `git tag -a v3.X.Y -m "description"`
10. Merge to master: `git checkout master && git merge v3.3-dev`

---

## 9. INCIDENT RESPONSE

When something breaks in order of escalation:

| Step | Action | Command |
|------|--------|---------|
| 1 | Diagnose | `zvadmin diagnose` |
| 2 | Troubleshoot | `zvadmin troubleshoot --symptom <symptom>` |
| 3 | Rollback bundle | `zvadmin bundle rollback <bundle_id>` |
| 4 | Revert model | Swap GGUF back: `docker-compose.distroless.yml` model path |
| 5 | Revert code | `git revert <commit>` then rebuild worker/api |
| 6 | Nuclear restart | `docker compose down && docker compose up -d` |

After recovery: run verify_all.sh to confirm 16/16.
Write incident report with root cause and prevention.

---

## 10. FILE OWNERSHIP

| Subsystem | Key Files | Check Before Touching |
|-----------|-----------|----------------------|
| Pipeline orchestrator | worker/stages/investigation_workflow.py | DO NOT MODIFY |
| Ingest (Stage 1) | worker/stages/ingest.py | Sanitizer patterns, benign routing |
| Analyze (Stage 2) | worker/stages/analyze.py | Plan loading, LLM calls, Path A/C routing |
| Execute (Stage 3) | worker/tools/runner.py | Variable resolution, tool catalog |
| Assess (Stage 4) | worker/stages/assess.py | Signal boost, risk scoring, verdict logic |
| Govern (Stage 4.5) | worker/stages/govern.py | Autonomy levels |
| Store (Stage 5) | worker/stages/store.py | DB writes, NOTIFY, dedup update |
| LLM infra | worker/llm_client.py, worker/stages/llm_gateway.py | Semaphores, model routing |
| Prompts | dpo/prompts_v2.py | Scoring anchors, system prompts — READ ONLY unless approved |
| Tools | worker/tools/catalog.py, detection.py, investigation_plans.json | Always update all 3 together |
| Bundles | worker/bundles/*.py | Security gates, schema, importer |
| Intelligence | worker/intelligence/*.py | Attack paths, contextual risk, copilot |
| Go API | api/*.go | Route registration in main.go |
| Dashboard | web-admin/src/*.tsx | Rebuild after changes, restart nginx |
| Inference | docker-compose.distroless.yml | Model path, --ctx-size, --jinja flags |
