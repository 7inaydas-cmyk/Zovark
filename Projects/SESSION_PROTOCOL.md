# Session Protocol

Checklist for every Claude Code session on Zovark.

---

## SESSION START

- [ ] **Step 1: Read hot cache** `Projects/hot.md` (20 lines, instant context). ONLY read CLAUDE.md/HANDOVER.md if hot.md is stale or you need deep detail about a specific component.

### Step 2: Smoke Test (30 seconds)

Run these in order. Stop at first failure and fix it.
```bash
# 1. Are containers running?
docker compose ps --format "{{.Name}}: {{.Status}}" | grep -c "Up"
# Expect: 11+ containers

# 2. Is the API responding?
curl -sf http://localhost:8090/ready
# Expect: {"status":"ready"}

# 3. Is inference loaded?
docker compose exec -T worker curl -sf http://zovark-inference:8080/health
# Expect: {"status":"ok"}

# 4. Quick regression (single alert, not full 16)
TOKEN=$(curl -sf -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

curl -sf -X POST http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task_type":"brute_force","input":{"prompt":"SSH brute force test","severity":"high","siem_event":{"title":"Smoke Test","source_ip":"10.0.0.99","raw_log":"sshd: Failed password for admin from 10.0.0.99"}}}'
# Expect: {"task_id":"..."}

# 5. Architecture lint
bash scripts/lint_architecture.sh
# Expect: 0 failures
```

If all 5 pass: proceed to Step 3 (check Kanban).
If any fail: diagnose and fix. Do not start feature work on a broken system.

- [ ] **Step 3: Run** `cmd/zvadmin/zvadmin.exe diagnose` — all checks must pass
- [ ] **Step 4: Check** Kanban board "In Progress" column — pick up or pick next unblocked task
- [ ] **Step 5: Run** `bash autoresearch/cycle10/verify_all.sh` — must be 16/16 before any code changes

If any step fails, fix it before proceeding to implementation.

---

## SESSION END

- [ ] **Verify** `bash autoresearch/cycle10/verify_all.sh` — 16/16
- [ ] **Verify** `docker compose exec -T worker python -m pytest tests/ -q --tb=short` — all pass
- [ ] **Update hot cache** — rewrite `Projects/hot.md` with current state (last commit, sprint status, blockers, new anti-patterns)
- [ ] **Run architecture lint** — `bash scripts/lint_architecture.sh` — if any FAIL: fix before committing. Log warnings in Kanban Risks.
- [ ] **Update** Kanban: move completed tasks to Done, add any new blockers discovered
- [ ] **Update** COMPONENT_REGISTRY.md (new files), CLAUDE.md (new tables/routes/services), HANDOVER.md (state changes)
- [ ] **Provide** session report using template below

---

## SESSION REPORT TEMPLATE

Copy-paste this for every session summary:

```markdown
# SESSION REPORT -- [DATE]

## Completed
- [ ] Task 1: description -- files changed
- [ ] Task 2: description -- files changed

## Files Changed
| File | Change Type | Description |
|------|------------|-------------|
| path/to/file | NEW/MODIFY | what changed |

## Verification
- verify_all.sh: X/16
- dedup_stress_test.sh: X/14 (if dedup touched)
- Unit tests: X passed, Y failed (known: 3 adversarial review)
- zvadmin diagnose: PASS/FAIL

## Blockers Found
- None / List any blockers discovered during session

## Next Session
- Task to start with
- Any preparation needed

## Decisions Made
- Decision 1: rationale
```

---

## CONTEXT RECOVERY

If starting a new session with no prior context:

1. Read all 4 mandatory files (HANDOVER.md is the "how to work here" guide)
2. Check `git log --oneline -10` for recent work
3. Check `git status` for uncommitted changes
4. Run diagnose + verify to establish baseline
5. Read the Kanban board to find the current task

The system should be ready to work within 5 minutes of session start.

---

## EMERGENCY PROCEDURES

If the system is broken when you start:

1. `cmd/zvadmin/zvadmin.exe diagnose` — identify which check fails
2. `cmd/zvadmin/zvadmin.exe troubleshoot --symptom <symptom>` — guided fix
3. If containers are down: `docker compose up -d`
4. If inference is crashed: `docker compose -f docker-compose.yml -f docker-compose.distroless.yml up -d zovark-inference`
5. If DB is corrupt: check `docker compose logs postgres` for WAL issues
6. If all else fails: `docker compose down && docker compose up -d` (nuclear option)

After recovery: verify_all.sh 16/16 before any new work.
