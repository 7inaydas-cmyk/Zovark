# Zovark Installation Guide

## Hardware Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32 GB |
| Disk | 50 GB free | 100 GB SSD |
| GPU | None (CPU-only mode) | NVIDIA GPU with 8+ GB VRAM |
| Network | LAN access to SIEM | Same subnet as SIEM |

GPU is optional. Without one, investigations run 5-10x slower using CPU inference. See `HARDWARE_GUIDE.md` for GPU selection.

## Software Prerequisites

Install these before proceeding:

### Docker Engine + Compose V2

```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect

# Verify
docker --version        # 24.0+ required
docker compose version  # V2 required (not docker-compose v1)
```

### NVIDIA Container Toolkit (GPU only)

```bash
# Add NVIDIA package repository
distribution=$(. /etc/os-release; echo $ID$VERSION_ID)
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | \
  sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L "https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list" | \
  sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
  sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# Verify
nvidia-smi              # Should show your GPU
docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi
```

### Git

```bash
sudo apt-get install -y git
```

## Download and Setup

```bash
# Clone the repository
git clone https://github.com/your-org/zovark.git
cd zovark

# Or if using a release tarball
tar xzf zovark-v1.0.0.tar.gz
cd zovark
```

## Environment Configuration

Copy the example environment file and edit it:

```bash
cp .env.example .env
```

If `.env.example` does not exist, create `.env` with these settings:

```bash
# === REQUIRED: Change these for production ===

# JWT signing key — MUST be at least 32 characters
JWT_SECRET=your-secret-key-minimum-32-characters-long-change-me

# Database password
POSTGRES_PASSWORD=change-this-strong-password

# Redis password
REDIS_PASSWORD=change-this-redis-password

# === LLM Configuration ===

# Points workers to LLM inference container.
# For GPU on host machine:
ZOVARK_LLM_ENDPOINT=http://zovark-inference:8080/v1/chat/completions
# Inference is provided by zovark-inference container (see distroless overlay)


# Model name
ZOVARK_LLM_MODEL=qwen2.5:14b

# === Optional ===

# NATS messaging credentials
NATS_USER=zovark
NATS_PASSWORD=change-this-nats-password

# MinIO object storage
MINIO_ROOT_USER=zovark
MINIO_ROOT_PASSWORD=change-this-minio-password
```

> **Note:** LiteLLM was previously used as an LLM proxy but has been removed due to supply chain risk (PyPI compromise). Zovark now communicates directly with llama-server via `ZOVARK_LLM_ENDPOINT`.

## Start the LLM Server (GPU Host)

Zovark expects a local LLM running on the host machine. Choose one:

### LLM Inference Setup

```bash
# Start inference container (Nemotron-Mini-4B)
docker compose -f docker-compose.yml -f docker-compose.distroless.yml up -d zovark-inference

# Pull model
# Model: models/Nemotron-Mini-4B-Instruct-Q4_K_M.gguf (must be present)

# llama-server starts on port 8080 inside the container
```

### Option B: llama.cpp (more control)

```bash
# Download model (Q4_K_M quantization recommended)
# Place in ./models/ directory

# Start server
./scripts/start_llama_server.sh
# Or manually:
# llama-server -m models/qwen2.5-14b-instruct-q4_k_m.gguf \
#   --port 8080 --n-gpu-layers 49 -c 4096
```

### Option C: CPU-only (no GPU)

```bash
# Model: models/Nemotron-Mini-4B-Instruct-Q4_K_M.gguf (must be present)
# CPU-only mode: llama-server runs without GPU acceleration
# Expect 5-10x slower investigation times
```

## Run the Installer

```bash
# Build and start all core services
docker compose up -d

# This starts: postgres, redis, pgbouncer, temporal, api, worker, dashboard, squid-proxy
# First run pulls images and builds containers (~5-10 minutes)
```

Wait for all services to become healthy:

```bash
# Watch until all services show "healthy" or "running"
docker compose ps

# Expected output:
# zovark-postgres    running (healthy)
# zovark-redis       running (healthy)
# zovark-pgbouncer   running (healthy)
# zovark-temporal    running
# zovark-api         running
# zovark-dashboard   running
# zovark-egress-proxy running
# worker (1)        running (healthy)
```

## Apply Database Migrations

On first install, the database schema is created by `init.sql`. Apply any additional migrations:

```bash
# Apply all migrations in order
for f in migrations/*.sql; do
  echo "Applying $f ..."
  docker compose exec -T postgres psql -U zovark -d zovark < "$f"
done
```

## Post-Install Verification

```bash
# 1. API health check
curl -s http://localhost:8090/health
# Expected: {"status":"ok",...}

# 2. Dashboard
# Open http://localhost:3000 in your browser

# 3. Check worker is connected to Temporal
docker compose logs worker --tail=20
# Look for: "Worker started" or "Polling for tasks"

# 4. Check database connectivity
docker compose exec postgres psql -U zovark -d zovark -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';"
# Should return 70+ tables
```

## First Login

### Register the Admin Account

```bash
curl -s -X POST http://localhost:8090/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourorg.local",
    "password": "YourStrongPassword123!",
    "name": "Admin"
  }'
```

### Login and Get a Token

```bash
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourorg.local","password":"YourStrongPassword123!"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "Token: $TOKEN"
```

Or log in via the dashboard at http://localhost:3000.

## Start Your First Investigation

```bash
# Submit a test investigation
TASK_ID=$(curl -s -X POST http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "brute_force",
    "input": {
      "prompt": "Analyze SSH brute force from 10.0.0.99 targeting 10.0.0.1 with 500 failed attempts in 5 minutes",
      "severity": "high"
    }
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['task_id'])")

echo "Task ID: $TASK_ID"

# Poll for result (investigations typically complete in 30-60 seconds with GPU)
sleep 10
curl -s http://localhost:8090/api/v1/tasks/$TASK_ID \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

The response includes:
- `status`: `completed` or `in_progress`
- `result.verdict`: `true_positive`, `false_positive`, or `needs_escalation`
- `result.findings`: list of discovered IOCs and behaviors
- `result.recommendations`: suggested response actions
- `result.risk_score`: 0-100 severity rating

## Optional: Enable Monitoring

```bash
# Start Prometheus + Grafana stack
docker compose --profile monitoring up -d

# Grafana: http://localhost:3001 (admin/zovark)
# Prometheus: http://localhost:9090
```

## Next Steps

- Read `ADMIN_GUIDE.md` for day-to-day operations
- Read `HARDWARE_GUIDE.md` to optimize GPU selection
- Read `UPGRADE.md` for future upgrade procedures
- Configure your SIEM to send alerts to `POST /api/v1/tasks`
