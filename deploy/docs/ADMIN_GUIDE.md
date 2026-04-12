# Zovark Administration Guide

## Starting and Stopping

```bash
# Start all core services
docker compose up -d

# Stop all services (preserves data)
docker compose down

# Stop and remove volumes (DESTROYS ALL DATA)
docker compose down -v

# Restart a single service
docker compose restart worker
docker compose restart api

# Start with monitoring stack
docker compose --profile monitoring up -d
```

## Checking Service Health

```bash
# Quick status of all containers
docker compose ps

# API health endpoint
curl -s http://localhost:8090/health | python3 -m json.tool

# Check individual service logs (last 50 lines)
docker compose logs --tail=50 api
docker compose logs --tail=50 worker
docker compose logs --tail=50 postgres
docker compose logs --tail=50 temporal

# Follow logs in real time
docker compose logs -f worker

# Check database connectivity
docker compose exec postgres psql -U zovark -d zovark -c "SELECT 1;"

# Check Redis
docker compose exec redis redis-cli -a "${REDIS_PASSWORD:-hydra-redis-dev-2026}" ping

# Check Temporal is accepting connections
docker compose exec worker python -c "
import asyncio
from temporalio.client import Client
async def check():
    c = await Client.connect('temporal:7233')
    print('Temporal OK')
asyncio.run(check())
"
```

## Database Backups

### Create a Backup

```bash
# Full database dump (compressed)
docker compose exec -T postgres pg_dump -U zovark -d zovark -Fc > \
  "zovark_backup_$(date +%Y%m%d_%H%M%S).dump"

# SQL format (human-readable)
docker compose exec -T postgres pg_dump -U zovark -d zovark > \
  "zovark_backup_$(date +%Y%m%d_%H%M%S).sql"

# Data only (no schema — useful for migrations)
docker compose exec -T postgres pg_dump -U zovark -d zovark --data-only -Fc > \
  "zovark_data_$(date +%Y%m%d_%H%M%S).dump"
```

### Automated Daily Backups

Add to crontab (`crontab -e`):

```cron
0 2 * * * cd /path/to/zovark && docker compose exec -T postgres pg_dump -U zovark -d zovark -Fc > /backups/zovark_$(date +\%Y\%m\%d).dump 2>&1
# Keep last 30 days
0 3 * * * find /backups -name "zovark_*.dump" -mtime +30 -delete
```

### Restore from Backup

```bash
# Stop the worker and API to prevent writes during restore
docker compose stop worker api

# Restore from compressed dump
docker compose exec -T postgres pg_restore -U zovark -d zovark --clean --if-exists < zovark_backup.dump

# Or from SQL format
docker compose exec -T postgres psql -U zovark -d zovark < zovark_backup.sql

# Restart services
docker compose start api worker
```

## Viewing Logs

```bash
# All services
docker compose logs --tail=100

# Specific service with timestamps
docker compose logs --tail=100 -t worker

# Filter for errors
docker compose logs worker 2>&1 | grep -i error | tail -20

# Investigation-specific logs (by task ID)
docker compose logs worker 2>&1 | grep "TASK_ID_HERE"

# API request logs
docker compose logs api 2>&1 | grep "POST\|PUT\|DELETE" | tail -20

# Export logs to file
docker compose logs --no-color > zovark_logs_$(date +%Y%m%d).txt
```

## Scaling Workers

More workers = more parallel investigations. Each worker needs ~512 MB RAM.

```bash
# Scale to 3 workers
docker compose up -d --scale worker=3

# Verify all workers registered with Temporal
docker compose ps | grep worker

# Scale back down
docker compose up -d --scale worker=1
```

Worker scaling is bounded by:
- Available RAM (~512 MB per worker)
- LLM throughput (one LLM call at a time per request)
- Database connection pool (default 50 connections via PgBouncer)

Recommended: 2-3 workers for single-GPU setups, 5-10 for enterprise.

## Updating the LLM Model

### LLM Inference (llama-server)

```bash
# Pull a new model
# Model is pre-loaded in zovark-inference container

# Switch models — update .env
echo 'ZOVARK_LLM_MODEL=qwen2.5:32b' >> .env

# Restart worker to pick up the change
docker compose restart worker
```

### llama.cpp

```bash
# Download new model GGUF file
# Place in models/ directory

# Update the start script or command to point to new model
# Restart llama-server with the new model file

# Update .env if model name changed
echo 'ZOVARK_LLM_MODEL=qwen2.5:32b' >> .env
docker compose restart worker
```

## Monitoring Disk Usage

```bash
# Docker disk usage summary
docker system df

# Per-volume disk usage
docker system df -v | grep zovark

# PostgreSQL database size
docker compose exec postgres psql -U zovark -d zovark -c "
  SELECT pg_size_pretty(pg_database_size('zovark')) AS db_size;
"

# Per-table sizes (top 10)
docker compose exec postgres psql -U zovark -d zovark -c "
  SELECT relname AS table,
         pg_size_pretty(pg_total_relation_size(relid)) AS size
  FROM pg_catalog.pg_statio_user_tables
  ORDER BY pg_total_relation_size(relid) DESC
  LIMIT 10;
"

# Docker container logs disk usage
du -sh /var/lib/docker/containers/*/

# Clean up unused Docker resources
docker system prune -f          # Remove stopped containers, unused networks
docker image prune -f           # Remove dangling images
docker builder prune -f         # Clear build cache
```

## Investigation Management

```bash
# Get auth token
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourorg.local","password":"YourPassword123!"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# List recent tasks
curl -s http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Get specific task result
curl -s http://localhost:8090/api/v1/tasks/TASK_ID \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Check investigation counts
docker compose exec postgres psql -U zovark -d zovark -c "
  SELECT status, count(*) FROM agent_tasks GROUP BY status;
"
```

## Troubleshooting

### Worker Crashes or Restarts Repeatedly

```bash
# Check worker logs for the error
docker compose logs --tail=100 worker

# Common causes:
# 1. Cannot connect to Temporal
#    Fix: Ensure temporal container is running and healthy
docker compose restart temporal
sleep 10
docker compose restart worker

# 2. Cannot connect to PostgreSQL
#    Fix: Check pgbouncer and postgres are healthy
docker compose ps postgres pgbouncer
docker compose restart pgbouncer

# 3. Out of memory
#    Fix: Increase memory limit in docker-compose.yml or reduce worker count
docker stats --no-stream
```

### LLM Timeout (Investigations Stuck)

```bash
# Check if LLM server is responding
curl -s http://zovark-inference:8080/health

# Check inference container is running:
docker compose ps zovark-inference
docker compose logs zovark-inference --tail 5

# Check worker can reach the LLM endpoint
docker compose exec worker python -c "
import urllib.request, json
req = urllib.request.Request('http://zovark-inference:8080/health')
resp = urllib.request.urlopen(req, timeout=5)
print(json.loads(resp.read()))
"

# If LLM is down, restart it
docker compose restart zovark-inference
# or restart llama-server process

# Check GPU isn't out of memory
nvidia-smi
```

### Database Connection Issues

```bash
# Check PgBouncer status
docker compose logs --tail=20 pgbouncer

# Check active connections
docker compose exec postgres psql -U zovark -d zovark -c "
  SELECT count(*) as active_connections FROM pg_stat_activity;
"

# If connections are exhausted, restart PgBouncer
docker compose restart pgbouncer

# Check for long-running queries
docker compose exec postgres psql -U zovark -d zovark -c "
  SELECT pid, now() - pg_stat_activity.query_start AS duration, query
  FROM pg_stat_activity
  WHERE state != 'idle'
  ORDER BY duration DESC
  LIMIT 5;
"

# Kill a stuck query
docker compose exec postgres psql -U zovark -d zovark -c "
  SELECT pg_terminate_backend(PID_HERE);
"
```

### Temporal Issues

```bash
# Check Temporal server logs
docker compose logs --tail=50 temporal

# List running workflows
# (requires tctl — install from temporalio/tctl)
docker compose exec temporal tctl workflow list --open

# Terminate a stuck workflow
docker compose exec temporal tctl workflow terminate -w WORKFLOW_ID -r RUN_ID

# Reset Temporal if persistent issues
docker compose restart temporal
sleep 15
docker compose restart worker
```

### Redis Issues

```bash
# Check Redis memory usage
docker compose exec redis redis-cli -a "${REDIS_PASSWORD:-hydra-redis-dev-2026}" info memory

# Check key count
docker compose exec redis redis-cli -a "${REDIS_PASSWORD:-hydra-redis-dev-2026}" dbsize

# If Redis is at memory limit, it evicts keys automatically (LRU policy)
# To manually clear dedup cache:
docker compose exec redis redis-cli -a "${REDIS_PASSWORD:-hydra-redis-dev-2026}" keys "dedup:*" | head -20
```

### Dashboard Not Loading

```bash
# Check dashboard container
docker compose logs --tail=20 dashboard

# Verify it's running on port 3000
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
# Should return 200

# Rebuild if assets are stale
docker compose build dashboard
docker compose up -d dashboard
```

### Full Reset (Development Only)

```bash
# WARNING: Destroys all data
docker compose down -v
docker compose build
docker compose up -d

# Re-apply migrations
for f in migrations/*.sql; do
  docker compose exec -T postgres psql -U zovark -d zovark < "$f"
done
```
