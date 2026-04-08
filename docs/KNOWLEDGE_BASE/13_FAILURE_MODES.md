# What Can Go Wrong — Every Failure Mode and What Happens

This document covers every way Zovark can break, what you'll see when it does, what the system does automatically to recover, and what a human operator needs to do. Written for someone who doesn't live in a terminal but needs to understand the risk profile.

---

## How to Read This

Each failure is described with five pieces:

- **What breaks**: The component or situation.
- **What you see**: The symptom — what shows up on the dashboard, in logs, or in behavior.
- **What happens automatically**: Built-in recovery, if any.
- **What an operator must do**: Manual steps required.
- **Blast radius**: How much of the system is affected.

---

## Infrastructure Failures

### PostgreSQL Goes Down

PostgreSQL is the central database. Every stage of the pipeline reads from or writes to it. If Postgres stops, everything stops.

- **What you see**: Dashboard shows errors or won't load. API returns 503 on the readiness endpoint (`GET /ready`). New investigations fail. In-flight investigations fail at the store stage.
- **What happens automatically**: PgBouncer (the connection pooler sitting in front of Postgres) will queue connections briefly — about 30 seconds. If Postgres comes back within that window, things may resume. The healer container checks API readiness every 60 seconds and will flag the issue.
- **What an operator must do**: Restart the postgres container: `docker compose restart postgres`. If the data volume is corrupted, restore from backup.
- **Blast radius**: Total. Nothing works without the database.

### Valkey (Redis) Goes Down

Valkey handles deduplication, batching, code caching, and the circuit breaker state. It's important but not critical to the core pipeline.

- **What you see**: Dashboard still works. Investigations still run. But you may see duplicate alerts being processed (dedup is skipped). The code cache stops working, so repeat alerts that would normally skip the LLM will hit the LLM again.
- **What happens automatically**: Fail-open design. Every component that uses Redis has a fallback — if Redis is unreachable, it skips the Redis step and continues. The pipeline keeps processing alerts, just without dedup/batching/caching.
- **What an operator must do**: Restart the redis container: `docker compose restart redis`. Monitor for duplicate investigations in the meantime.
- **Blast radius**: Low. Pipeline continues. Duplicates may appear. LLM load increases slightly due to cache misses.

### Temporal Goes Down

Temporal is the workflow engine that orchestrates investigations. It tracks which stage each investigation is in and handles retries.

- **What you see**: New investigations don't start — the API accepts alerts but they queue up. In-flight investigations may stall (they'll resume when Temporal comes back). The readiness endpoint returns 503.
- **What happens automatically**: The worker automatically reconnects to Temporal when it restarts. In-flight investigations resume from the last completed stage — no data is lost.
- **What an operator must do**: Restart the temporal container: `docker compose restart temporal`. In-flight work resumes automatically.
- **Blast radius**: High for new work, but no data loss. Existing completed investigations are unaffected.

### Docker Desktop Crashes

If Docker Desktop itself crashes (the engine that runs all containers), everything stops at once.

- **What you see**: All services unreachable. Dashboard gone. API gone. No containers running.
- **What happens automatically**: Nothing — Docker Desktop must be manually restarted.
- **What an operator must do**: Restart Docker Desktop, wait for it to fully initialize (30-60 seconds), then run `docker compose up -d` to bring all services back. Temporal will resume in-flight investigations.
- **Blast radius**: Total. Everything is down until Docker restarts.

### Disk Full

The host machine runs out of disk space. This is one of the most dangerous failures because it can corrupt data.

- **What you see**: Database writes fail with "no space left on device" errors. Logs stop being written. Container logs may also fill disk. Docker may refuse to start new containers.
- **What happens automatically**: Nothing. There is no auto-recovery for disk full.
- **What an operator must do**: Free disk space immediately. Clear old Docker logs (`docker system prune`), remove old investigation data from the database, check for large log files. PostgreSQL may need a manual restart after space is freed.
- **Blast radius**: Critical. Can corrupt the database if writes fail mid-transaction. Most dangerous infrastructure failure.

### Network Interface Down (Air-Gapped Deployments)

In air-gapped environments, the internal Docker network is all that matters. If the host network interface changes or Docker's internal network breaks:

- **What you see**: Containers can't talk to each other. API can't reach Postgres. Worker can't reach Temporal.
- **What happens automatically**: Healer detects connectivity failures within 60 seconds.
- **What an operator must do**: Restart Docker networking: `docker compose down && docker compose up -d`. In severe cases, restart Docker Desktop.
- **Blast radius**: Total, but recoverable without data loss.

---

## Inference (LLM) Failures

### LLM Container Out of Memory (OOM)

Gemma 4 E4B needs about 2GB of RAM with `--ctx-size 4096`. If something causes memory to spike (unusually long prompt, concurrent requests piling up), the container crashes.

- **What you see**: LLM health check fails. Path C investigations (novel alerts with no saved plan) get `needs_manual_review` instead of a verdict. Path A investigations (saved plans) are completely unaffected — they don't use the LLM.
- **What happens automatically**: The healer container detects the LLM health check failure and auto-restarts the inference container. This takes about 60 seconds (model must reload into memory).
- **What an operator must do**: Usually nothing — healer handles it. If it keeps happening, increase Docker Desktop's memory allocation (should be at least 12GB).
- **Blast radius**: Medium. Only affects investigations that need the LLM (Path B param fill, Path C tool selection, verdict summaries). Path A and benign routing continue normally.

### LLM Returns Unparseable Output

Sometimes the LLM generates text that can't be parsed as valid JSON.

- **What you see**: Investigation still completes, but the summary may be generic/templated instead of specific to the alert.
- **What happens automatically**: GBNF grammar constrains tool selection output, so that path rarely fails. For verdict summaries, the output validator catches parse errors and falls back to a deterministic template summary. The investigation still gets a risk score and verdict — just a less detailed explanation.
- **What an operator must do**: Nothing. This is handled automatically.
- **Blast radius**: Minimal. Investigation quality slightly reduced for that one alert.

### LLM Latency Spike (Slow Response)

The LLM takes longer than expected — maybe the GPU is busy with concurrent requests, or the prompt is unusually long.

- **What you see**: Investigations take longer. The assess stage has a 45-second timeout. If the LLM doesn't respond in time, it times out.
- **What happens automatically**: On timeout, the assess stage falls back to a template-based summary. The circuit breaker tracks consecutive failures — after enough timeouts, it goes to YELLOW (warning) or RED (all Path C alerts get `needs_manual_review`).
- **What an operator must do**: Check if the LLM container is healthy. Check GPU utilization. Consider reducing concurrent workflows if the GPU is overloaded.
- **Blast radius**: Low to medium. Individual investigations get template summaries. If it persists, the circuit breaker protects the system.

### GPU Driver Crash

The NVIDIA driver crashes or becomes unresponsive.

- **What you see**: LLM container stops responding. Health check fails.
- **What happens automatically**: Healer detects and restarts the LLM container. If the GPU driver itself is crashed, the restart won't help until the driver recovers.
- **What an operator must do**: Check GPU status with `nvidia-smi`. If the driver is crashed, restart the host machine.
- **Blast radius**: Same as LLM OOM — only LLM-dependent paths affected.

---

## Pipeline Failures

### Single Tool Execution Error

One of the 40 investigation tools throws an error (bad input, unexpected data format, etc.).

- **What you see**: The investigation completes, but one tool's result is marked as an error in the output. The risk score may be lower than expected because that tool's signal is missing.
- **What happens automatically**: Error isolation — each tool runs independently with a 5-second timeout. One tool failing doesn't affect the others. The error is logged in `tool_results`.
- **What an operator must do**: Nothing for the immediate investigation. If the same tool keeps failing, check the tool code for bugs.
- **Blast radius**: Minimal. One tool's contribution is missing from one investigation.

### Tool Execution Timeout

A tool takes longer than its 5-second per-tool limit, or the total execution exceeds 30 seconds.

- **What you see**: Tool result set to `None` with a timeout warning. Investigation continues with remaining tools.
- **What happens automatically**: Timeout is enforced automatically. Other tools are unaffected.
- **What an operator must do**: Nothing unless it recurs. Recurring timeouts on the same tool suggest the tool needs optimization.
- **Blast radius**: Minimal. Same as a single tool error.

### Stage Timeout

Each pipeline stage has its own timeout (ingest: 30s, analyze: 15min, execute: 2min, assess: 1min). If a stage exceeds its timeout, the investigation fails.

- **What you see**: Investigation status shows as failed with `needs_manual_review`. The stage that timed out is logged.
- **What happens automatically**: The investigation is marked for human review. No automatic retry.
- **What an operator must do**: Review the failed investigation. Check which stage timed out and why.
- **Blast radius**: One investigation. Other investigations are unaffected.

### Worker Crashes Mid-Investigation

The Python worker container crashes while processing an investigation (out of memory, unhandled exception, etc.).

- **What you see**: Investigation appears stalled. Worker container may restart.
- **What happens automatically**: Temporal tracks the investigation state. When the worker restarts, it picks up from the last completed stage. No work is lost.
- **What an operator must do**: Check worker logs for the crash reason. If it's OOM, increase container memory.
- **Blast radius**: Temporary delay. No data loss. Temporal handles recovery.

### Sanitizer Rejects an Alert

The input sanitizer detects an injection attempt (template injection, code injection, SSTI pattern, etc.) in the incoming alert data.

- **What you see**: The alert is not processed. An audit event is logged recording the rejection and the pattern that triggered it.
- **What happens automatically**: The alert is blocked. This is intentional — it's a security control.
- **What an operator must do**: Review the audit log. If it's a false positive (legitimate alert that looks like an injection), the sanitizer patterns may need tuning.
- **Blast radius**: One alert. Everything else continues.

### Content Scanner False Positive

The content scanner (54 attack patterns checked against raw log data) flags a benign alert as containing attack content, forcing it into the full investigation path.

- **What you see**: A benign alert gets investigated as if it were suspicious. It will likely come back with a low risk score and benign verdict anyway, just slower.
- **What happens automatically**: The alert goes through the full pipeline. The assess stage will likely score it correctly.
- **What an operator must do**: Nothing. The false positive rate on benchmarks is 0%, so this is extremely rare.
- **Blast radius**: One alert takes longer to process. No harm done.

---

## Network and Integration Failures

### SIEM Stops Sending Alerts

The upstream SIEM (Splunk, Elastic, etc.) stops forwarding alerts to Zovark.

- **What you see**: Dashboard shows zero throughput. No new investigations. This isn't a Zovark failure — it's the data source going quiet.
- **What happens automatically**: Nothing — Zovark can't fix the SIEM.
- **What an operator must do**: Check the SIEM integration. Verify the webhook or HEC forwarder is running.
- **Blast radius**: None to Zovark. The system is healthy, just idle.

### SSE Connection Drops

The real-time event stream (Server-Sent Events) between the API and the dashboard disconnects.

- **What you see**: The live investigation feed stops updating momentarily.
- **What happens automatically**: The dashboard falls back to polling every 10 seconds and automatically attempts to reconnect the SSE stream.
- **What an operator must do**: Nothing. Reconnection is automatic.
- **Blast radius**: Cosmetic. Data is not lost, just delayed by up to 10 seconds.

### Healer Memory Leak (Windows)

Known issue on Windows Docker Desktop. The healer container can grow to 3GB+ due to GIL and asyncio contention.

- **What you see**: Healer container using excessive memory. May become unresponsive.
- **What happens automatically**: Container has a 512MB memory limit. When it hits the limit, Docker kills and restarts it.
- **What an operator must do**: Nothing — the restart is automatic. The healer is a monitoring-only service; its failure doesn't affect investigations.
- **Blast radius**: None to investigations. Monitoring is briefly interrupted.

---

## Data Failures

### Entity Graph Write Fails

The entity graph (which tracks relationships between IPs, users, hosts across investigations) fails to write.

- **What you see**: Investigation completes normally. Entity data for that investigation is missing from the graph.
- **What happens automatically**: Entity writes are fire-and-forget. The investigation result is stored regardless.
- **What an operator must do**: Check database connectivity. Entity data for that investigation can't be recovered retroactively.
- **Blast radius**: Minimal. Correlations may be less complete but investigations are unaffected.

### Database Migration Fails

A SQL migration file fails to apply (syntax error, constraint violation, etc.).

- **What you see**: The migration command returns an error. The database may be in a partially migrated state.
- **What happens automatically**: Nothing. Migrations are manual.
- **What an operator must do**: Fix the migration SQL and re-apply. Migrations are designed to be additive only (they add tables/columns, never remove them), so partial application is usually safe. Never roll back — roll forward with a fix.
- **Blast radius**: Depends on the migration. New features that depend on the new schema won't work until it's applied.

### Investigation Memory Table Grows Unbounded

The `investigation_memory` table stores learned patterns from past investigations. It has no automatic cleanup.

- **What you see**: Database size grows over time. Queries against this table slow down.
- **What happens automatically**: Nothing.
- **What an operator must do**: Periodically clean old entries. A simple SQL delete of entries older than 90 days is usually sufficient.
- **Blast radius**: Low. Gradual performance degradation, not a sudden failure.

---

## Security Failures

### JWT Token Expired

Access tokens last 30 minutes. After that, API calls return 401 Unauthorized.

- **What you see**: Dashboard shows "session expired" or API calls fail with 401.
- **What happens automatically**: Nothing — the client must re-authenticate.
- **What an operator must do**: Log in again. This is normal security behavior, not a failure.
- **Blast radius**: One user session. Everything else is unaffected.

### RLS Policy Violation

Row-Level Security prevents users from accessing data belonging to other tenants. If code accidentally omits the tenant filter, RLS silently returns zero rows.

- **What you see**: A query returns no results when you expected some. No error message.
- **What happens automatically**: RLS is defense-in-depth. The application code also filters by tenant_id in WHERE clauses.
- **What an operator must do**: Check that the query includes the correct tenant_id. Note: the database owner user (`zovark`) bypasses RLS — production deployments should use `zovark_app` user.
- **Blast radius**: One query. No data leak — RLS errs on the side of hiding data.

### Break-Glass Login Used

The system tenant (`00000000-0000-0000-0000-000000000001`) is for emergency access when normal authentication is unavailable.

- **What you see**: An audit event is logged with the system tenant UUID.
- **What happens automatically**: The login works, but the audit trail records it.
- **What an operator must do**: Review why break-glass was needed. This should trigger a security review.
- **Blast radius**: None technically, but it's a security governance concern.

---

## Summary Table

| Failure | Auto-Recovery? | Blast Radius | Operator Action |
|---------|---------------|--------------|-----------------|
| PostgreSQL down | PgBouncer queues ~30s | Total | Restart postgres container |
| Valkey/Redis down | Fail-open (skip dedup/cache) | Low | Restart redis, monitor for duplicates |
| Temporal down | Worker auto-reconnects | High (new work blocked) | Restart temporal container |
| Docker Desktop crash | None | Total | Restart Docker Desktop, then `docker compose up -d` |
| Disk full | None | Critical | Free space immediately, check for corruption |
| Network interface down | Healer detects in 60s | Total | Restart Docker networking |
| LLM container OOM | Healer auto-restarts | Medium (LLM paths only) | Usually nothing; increase memory if recurring |
| LLM returns bad JSON | Falls back to template | Minimal | Nothing |
| LLM latency spike | 45s timeout + circuit breaker | Low-Medium | Check GPU load |
| GPU driver crash | Healer attempts restart | Medium (LLM paths only) | May need host reboot |
| Single tool error | Error isolated | Minimal (one tool) | Nothing unless recurring |
| Tool timeout (5s) | Auto-skipped | Minimal (one tool) | Nothing unless recurring |
| Stage timeout | Marked needs_manual_review | One investigation | Review failed investigation |
| Worker crash mid-investigation | Temporal resumes on restart | Temporary delay | Check crash logs |
| Sanitizer rejects alert | Alert blocked (intentional) | One alert | Review if false positive |
| Content scanner false positive | Full investigation (safe) | One alert slower | Nothing |
| SIEM stops sending | None (not a Zovark issue) | None | Check SIEM integration |
| SSE connection drop | Auto-reconnect + polling fallback | Cosmetic | Nothing |
| Healer memory leak | 512MB limit auto-restart | None (monitoring only) | Nothing |
| Entity graph write fail | Fire-and-forget | Minimal | Check DB connectivity |
| Migration fails | None | Feature-dependent | Fix SQL and re-apply |
| Investigation memory growth | None | Gradual slowdown | Periodic cleanup |
| JWT expired | None (by design) | One user session | Re-login |
| RLS violation | Silent zero rows (safe) | One query | Check tenant_id |
| Break-glass login | Audit logged | Security governance | Review why it was needed |
