# Zovark Upgrade Guide

## Pre-Upgrade Checklist

Before upgrading, verify:

- [ ] You know your current version: `git log --oneline -1`
- [ ] No investigations are actively running: check `docker compose logs --tail=5 worker`
- [ ] You have enough disk space for rebuild: `docker system df`
- [ ] Backup is complete (see Step 1)

## Step 1: Backup

Always back up before upgrading. This is not optional.

```bash
cd /path/to/zovark

# Database backup
docker compose exec -T postgres pg_dump -U zovark -d zovark -Fc > \
  "zovark_pre_upgrade_$(date +%Y%m%d_%H%M%S).dump"

# Save current .env
cp .env .env.backup.$(date +%Y%m%d)

# Record current commit
git log --oneline -1 > .upgrade_rollback_point
cat .upgrade_rollback_point
```

## Step 2: Pull Latest Code

```bash
# Stash any local changes
git stash

# Pull latest
git pull origin master

# Check what changed
git log --oneline HEAD@{1}..HEAD

# Review if .env.example has new variables
git diff HEAD@{1}..HEAD -- .env.example
```

If new environment variables were added, update your `.env` file accordingly.

## Step 3: Rebuild Images

```bash
# Rebuild all services (uses cache where possible)
docker compose build

# Or rebuild specific services that changed
docker compose build api worker dashboard
```

## Step 4: Apply Database Migrations

Check for new migration files:

```bash
# See which migrations were added
git diff HEAD@{1}..HEAD --name-only -- migrations/

# Apply new migrations only
# Example: if you were on migration 035, apply 036+
for f in migrations/036_*.sql migrations/037_*.sql migrations/038_*.sql; do
  if [ -f "$f" ]; then
    echo "Applying $f ..."
    docker compose exec -T postgres psql -U zovark -d zovark < "$f"
  fi
done
```

To apply all migrations safely (idempotent if already applied):

```bash
for f in migrations/*.sql; do
  echo "Applying $f ..."
  docker compose exec -T postgres psql -U zovark -d zovark < "$f" 2>&1 | \
    grep -v "already exists" || true
done
```

## Step 5: Restart Services

```bash
# Restart with new images
docker compose up -d

# Watch startup logs
docker compose logs -f --tail=20
# Press Ctrl+C once all services report healthy
```

## Step 6: Verify Health

```bash
# Check all containers are running
docker compose ps

# API health
curl -s http://localhost:8090/health | python3 -m json.tool

# Verify worker is connected
docker compose logs --tail=10 worker

# Run a test investigation
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourorg.local","password":"YourPassword123!"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -s -X POST http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "brute_force",
    "input": {
      "prompt": "Post-upgrade test: analyze SSH brute force from 192.168.1.100",
      "severity": "low"
    }
  }' | python3 -m json.tool

# Check dashboard loads
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
# Should return 200
```

## Rollback Procedure

If the upgrade fails, roll back to the previous version.

### Step R1: Stop Services

```bash
docker compose down
```

### Step R2: Revert Code

```bash
# Read the saved rollback point
ROLLBACK_COMMIT=$(cat .upgrade_rollback_point | awk '{print $1}')
echo "Rolling back to: $ROLLBACK_COMMIT"

# Revert to previous commit
git checkout $ROLLBACK_COMMIT

# Restore .env if it was changed
cp .env.backup.* .env 2>/dev/null
```

### Step R3: Restore Database

```bash
# Start only postgres
docker compose up -d postgres
sleep 10

# Restore from pre-upgrade backup
docker compose exec -T postgres pg_restore -U zovark -d zovark \
  --clean --if-exists < zovark_pre_upgrade_*.dump

# Rebuild and restart with old code
docker compose build
docker compose up -d
```

### Step R4: Verify Rollback

```bash
docker compose ps
curl -s http://localhost:8090/health
```

## Upgrading the LLM Model

LLM model upgrades are independent of Zovark code upgrades.

```bash
# LLM inference
# Models are pre-loaded in the inference container

# llama.cpp — download new GGUF, restart server
# Update ZOVARK_LLM_MODEL in .env if model name changed

# Restart worker to pick up model change
docker compose restart worker
```

## Major Version Upgrades

For major version changes (e.g., v1.x to v2.x), additional steps may be required:

1. Read the release notes and `CHANGELOG.md` for breaking changes
2. Check for schema migrations that drop/rename columns
3. Test the upgrade on a staging environment first
4. Plan for downtime during database migration
5. Keep the old backup for at least 7 days after upgrade

## Upgrade Frequency

| Type | Frequency | Downtime |
|------|-----------|----------|
| Patch (bug fixes) | As needed | < 1 minute (rolling restart) |
| Minor (new features) | Monthly | 2-5 minutes |
| Major (breaking changes) | Quarterly | 10-30 minutes |
| LLM model update | As needed | < 1 minute (worker restart) |
