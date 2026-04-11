#!/bin/bash
# ============================================================
# Zovark Installation Script
# Checks prerequisites, configures environment, starts services
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$DEPLOY_DIR")"

echo "=== Zovark Installation ==="
echo ""

# Check prerequisites
echo "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "ERROR: Docker is not installed."; exit 1; }
command -v docker compose >/dev/null 2>&1 || { echo "ERROR: Docker Compose V2 is not installed."; exit 1; }
echo "  Docker: $(docker --version | head -1)"
echo "  Compose: $(docker compose version | head -1)"

# Check NVIDIA (optional)
if command -v nvidia-smi >/dev/null 2>&1; then
    echo "  NVIDIA: $(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)"
else
    echo "  NVIDIA: Not detected (will use CPU or remote LLM)"
fi

# Check .env
if [ ! -f "$DEPLOY_DIR/.env" ]; then
    echo ""
    echo "Creating .env from .env.example..."
    cp "$DEPLOY_DIR/.env.example" "$DEPLOY_DIR/.env"
    echo "IMPORTANT: Edit $DEPLOY_DIR/.env and set all CHANGE_ME values!"
    echo "Then run this script again."
    exit 0
fi

# Check for CHANGE_ME values
if grep -q "CHANGE_ME" "$DEPLOY_DIR/.env"; then
    echo ""
    echo "WARNING: .env still contains CHANGE_ME values."
    echo "Edit $DEPLOY_DIR/.env before continuing."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 0
fi

echo ""
echo "Building images..."
cd "$DEPLOY_DIR"
docker compose -f docker-compose.production.yml build

echo ""
echo "Running database migrations..."
docker compose -f docker-compose.production.yml up -d postgres
sleep 5

# Wait for postgres
for i in $(seq 1 30); do
    if docker compose -f docker-compose.production.yml exec -T postgres pg_isready -U zovark -d zovark >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

# Validate and apply migrations via Go binary (validates prefixes, gaps, then applies in NNN order)
echo "  Validating and applying migrations..."
docker compose -f docker-compose.production.yml run --rm -T api ./api migrate up
if [ $? -ne 0 ]; then
    echo "ERROR: Migration validation or application failed. Check output above."
    exit 1
fi

echo ""
echo "Starting all services..."
docker compose -f docker-compose.production.yml up -d

echo ""
echo "Waiting for services to be healthy..."
sleep 10

# Health check
"$SCRIPT_DIR/health-check.sh"

echo ""
echo "=== Zovark is running ==="
echo "  API:       http://localhost:${API_PORT:-8090}"
echo "  Dashboard: http://localhost:${DASHBOARD_PORT:-3000}"
echo "  Health:    http://localhost:${API_PORT:-8090}/health"
