# Agent Instructions

This file provides context for AI coding agents working on Zovark.

## Before Making Changes

1. Read `CLAUDE.md` for project overview and current state
2. Check `CHANGELOG.md` for recent changes
3. Run tests before and after changes
4. After Python changes: `docker compose build worker && docker compose up -d worker`
5. After Go changes: `docker compose build api && docker compose up -d api`

## Architecture Decisions

- Temporal for all async work — never use raw goroutines or threading for the investigation pipeline
- PostgreSQL + pgvector for all persistent state — no separate vector DB
- Direct httpx to llama-server via ZOVARK_LLM_ENDPOINT — no LiteLLM (removed)
- Docker sandbox for code execution — never run LLM-generated code in worker process
- NATS for real-time events — never poll the database for status updates
- Redis for ephemeral state only (rate limits, cache) — never for durable data
- go-redis/v9 for Redis access in Go — never raw TCP/RESP parsing
- psycopg2 ThreadedConnectionPool for DB in Python — never per-call psycopg2.connect()
- Alert dispatch path: Go API publishes events to Redpanda (via NATS). The worker's NATS consumer (worker/nats_consumer.py) picks up messages and starts Temporal workflows. There is no direct Temporal dispatch from the Go API.

## Important: Legacy File Layout

The worker has a legacy file layout due to the package/file name conflict:
- `worker/_legacy_activities.py` — the ACTUAL activities file (was `activities.py`, renamed to avoid conflict with `activities/` package)
- `worker/_legacy_workflows.py` — the ACTUAL workflows file (same pattern)
- `worker/activities/__init__.py` — re-exports all functions from `_legacy_activities.py`
- `worker/workflows/__init__.py` — re-exports `ExecuteTaskWorkflow` from `_legacy_workflows.py`

When adding new activities/workflows, add them to the `_legacy_*.py` files AND update the `__init__.py` re-exports.

## Common Tasks

### Add a new API endpoint
1. Add handler in `api/` (group with related handlers by domain)
2. Register route in `api/main.go`
3. Add test in `api/*_test.go`
4. `docker compose build api && docker compose up -d api`

### Add a new Temporal activity
1. Add `@activity.defn` function to `worker/_legacy_activities.py`
2. Add re-export to `worker/activities/__init__.py`
3. Import and register in `worker/main.py` activities list
4. Update the activities count in the log line
5. `docker compose build worker && docker compose up -d worker`

### Add a new Temporal workflow
1. Add `@workflow.defn` class to `worker/_legacy_workflows.py` (or a workflows/ submodule)
2. Re-export in `worker/workflows/__init__.py` if needed
3. Import and register in `worker/main.py` workflows list
4. `docker compose build worker && docker compose up -d worker`

### Add a new migration
1. Create `migrations/NNN_description.sql` where NNN is the next sequential number after the current highest (check with `ls migrations/*.sql | tail -1`). Never reuse or skip numbers.
2. Use IF NOT EXISTS / IF EXISTS for idempotency
3. Run `api -migrate status` before manual applies to check for prefix conflicts or gaps
4. Apply: `docker compose exec -T postgres psql -U zovark -d zovark < migrations/NNN_description.sql`
5. CI validates prefix uniqueness and contiguity via `api migrate validate` (no DB required)

**Note:** There is an intentional gap at prefixes 056-058 (sequence jumps from 055 to 059) due to historical renumbering. Do not attempt to fill this gap — always use the next number after the current highest. The gap is allowlisted in `api/migrate.go` (`allowedMigrationGaps`).

### Debug a failed investigation
```bash
# 1. Check worker logs
docker compose logs worker --tail 50 | grep -iv "nats\|redis"

# 2. Get Temporal workflow history
docker compose exec temporal tctl --address temporal:7233 workflow show -w task-<TASK_ID>

# 3. Find which activity failed
docker compose exec temporal tctl --address temporal:7233 workflow show -w task-<TASK_ID> | grep ActivityType

# 4. Common failure points:
#    - AST prefilter blocks code → check for forbidden imports (os, sys, subprocess)
#    - Adversarial review timeout → passes through (by design)
#    - fill_skill_parameters error → falls back to defaults (non-fatal)
#    - Docker sandbox timeout → 30s kill timer
#    - LLM 429 → LLM single-threaded, retries automatically
```

### Update skill templates in the DB
```bash
# Fix a template import
docker compose exec -T postgres psql -U zovark -d zovark -c "
UPDATE agent_skills
SET code_template = REPLACE(code_template, 'import os', '# import os (blocked)')
WHERE code_template LIKE '%import os%';
"
```

### Run the accuracy benchmark
```bash
# Against existing completed investigations
docker run --rm --network zovark_zovark-internal \
  -v "$(pwd):/app" -w /app -e ZOVARK_API_URL=http://zovark-api:8090 \
  python:3.11-slim sh -c "pip install -q httpx && python scripts/score_baseline.py"
```

### Rebuild and restart a single service
```bash
docker compose build <service> && docker compose up -d <service>
# e.g., docker compose build worker && docker compose up -d worker
```
