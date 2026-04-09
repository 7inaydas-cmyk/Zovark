# Zovark v3.3 — Product Guide

## 1. What is Zovark?

Zovark is an air-gapped AI SOC investigation platform that receives SIEM alerts, runs fully autonomous investigations using a 6-stage deterministic pipeline, and delivers structured verdicts with risk scores, IOCs, and MITRE ATT&CK mappings. It runs entirely on-premise with zero cloud dependencies, processing investigations in an average of 2.6 seconds. Designed for regulated enterprises under CMMC, HIPAA, and GDPR requirements, Zovark ensures complete data sovereignty — no security telemetry ever leaves the network perimeter.

---

## 2. Architecture Overview

```
SIEM Alert --> Go API (:8090) --> Temporal Queue --> Python Worker Pipeline --> Verdict
                                                         |
                                     +-------------------------------------------+
                                     | Ingest -> Analyze -> Execute ->           |
                                     | Assess -> Govern -> Store                 |
                                     +-------------------------------------------+
                                                         |
                               +-------------------------+-------------------------+
                               |                         |                         |
                         llama-server              PostgreSQL                  Valkey
                       (Gemma 4 E4B)              (86+ tables)            (dedup/cache)
```

### Pipeline Stages

| Stage | LLM? | Purpose |
|-------|------|---------|
| **Ingest** | No | Sanitizes input (25 patterns + Unicode normalization), normalizes 70+ SIEM field formats, PII masks, dedup checks, and scans raw_log against 66 high-confidence attack patterns with caret deobfuscation |
| **Analyze** | Optional | Loads saved investigation plan from 24 pre-built plans (Path A, ~5ms, no LLM) or uses LLM for tool selection on unknown attack types (Path C, ~30s) |
| **Execute** | No | Runs investigation tools via parallel DAG executor with variable resolution ($stepN references), conditional branching, per-tool 5s timeout, and error isolation |
| **Assess** | Optional | LLM generates verdict + risk score (0-100) + MITRE ATT&CK mapping + IOC extraction with evidence refs + signal boost + suppression detection + plain-English summary |
| **Govern** | No | Autonomy slider (observe/assist/autonomous) determines whether the verdict needs human review based on risk level and governance policy |
| **Store** | No | Writes to PostgreSQL with synchronous_commit, fires NOTIFY for real-time SSE updates, updates dedup state in Valkey |

---

## 3. Key Capabilities

- **2.6-second** average investigation time (P50: 1.98s, P95: 8.6s)
- **40+** investigations per minute on a single worker
- **11/11** attack type detection with minimum risk score 65+
- **0%** false positive rate across all benign alert types
- **100%** MITRE ATT&CK coverage across 13 attack categories
- **66-pattern** content scanner with CMD caret deobfuscation
- **3-layer** burst protection (dedup + batch buffer + backpressure)
- **14/14** dedup stress test passing (severity escalation, force reinvestigate, TTL behavior)
- **Deterministic Path A** — no LLM needed for known attack types
- **Fail-closed** on LLM failure (Path C investigations get `needs_manual_review`, never `benign`)
- **Air-gapped** operation — zero internet dependency
- **Multi-tenant** with row-level security on 10 tables
- **40 investigation tools** across 7 categories (extraction, analysis, parsing, scoring, detection, enrichment)
- **24 saved investigation plans** covering all major attack types
- **22 remediation rule sets** with circuit breaker and kill switch

---

## 4. Attack Types Supported

Detection accuracy from the 100-alert clean-slate benchmark test:

| Attack Type | Avg Risk | Min | Max | Stddev | Status |
|-------------|----------|-----|-----|--------|--------|
| c2_communication | 99.3 | 95 | 100 | 1.9 | Excellent |
| brute_force | 95.0 | 95 | 95 | 0.0 | Perfect |
| golden_ticket | 91.7 | 75 | 100 | 14.4 | Good |
| kerberoasting | 91.7 | 80 | 100 | 9.8 | Good |
| phishing | 86.7 | 70 | 100 | 12.0 | Good |
| lolbin_abuse | 81.3 | 70 | 100 | 14.4 | Good |
| ransomware | 77.5 | 70 | 100 | 11.3 | Good |
| dns_exfiltration | 77.5 | 70 | 100 | 15.0 | Good |
| data_exfiltration | 70.0 | 65 | 90 | 11.2 | Acceptable |
| lateral_movement | 70.0 | 70 | 70 | 0.0 | Good |
| unusual_network_traffic | — | — | — | — | Path C (LLM-dependent) |

All benign alert types (password_change, windows_update, health_check, service_restart, etc.) score risk=0 with 0% false positive rate.

---

## 5. Dashboard Guide

### System Health
- **What**: Container status for all 11+ services, service health indicators, inference model load status
- **Use**: First thing to check when investigations are slow or failing

### SIEM & Ingestion
- **What**: Alert ingestion configuration, Splunk HEC and Elastic webhook connectors, ingestion health metrics
- **Use**: Configure where alerts come from, monitor ingestion rates

### Configuration
- **What**: System settings (system_configs table), feature flags, model configuration, governance policy
- **Use**: Toggle parallel tools, fast-fill mode, auto-verify, dedup settings

### Zvadmin
- **What**: CLI-equivalent web interface — diagnose (8 health checks), alerts (verdict distribution), model check (per-type calibration), dedup health (decision distribution), troubleshoot (5 guided symptom flows)
- **Use**: Operator diagnostics, model calibration monitoring, system tuning

### Alert Forge
- **What**: Synthetic alert load generator with integrated live pipeline monitor
- **Controls**: Total alerts (100-10,000), attack ratio (0-100%), novelty rate (0-100%), rate per second (1-10), campaign mode, include benign toggle
- **Pipeline Monitor** (right panel, always visible):
  - Status bar with pulsing state indicator (green=active, gray=idle, red=errors)
  - 6 metric cards: throughput/min, avg latency, P95 latency, 24h total, queue depth, dedup rate
  - Pipeline stage flow visualization with color-coded count badges
  - Throughput sparkline (30-min area chart) and latency sparkline (avg + P95 dual line)
  - Verdict distribution donut and risk distribution horizontal bar chart
  - Attack type breakdown table with per-type avg risk, min, max, stddev, latency
  - Recent investigations feed with colored verdict dots and latency indicators
  - Collapsible error panel (only shows when errors exist)
- **Use**: Stress test the pipeline, validate detection accuracy, benchmark throughput

### Analytics
- **What**: Investigation pipeline performance, verdict and risk distribution, detection quality trends
- **Metrics**: Total investigations, separation gap (attack vs benign risk), attack count, benign count
- **Charts**: Verdict distribution donut, avg risk by attack type (horizontal bar), risk score distribution (5-bucket table), throughput time series (30m), latency time series (30m avg + P95)
- **Tables**: Attack type detail (count, avg_risk, min, max, stddev, latency per type)
- **Filters**: Time range (1h/6h/24h/7d), exclude forge data toggle
- **Pipeline indicator**: Live status bar showing active, completed, errors, throughput
- **Use**: Monitor ongoing detection quality, identify scoring drift, track pipeline performance

---

## 6. Access Credentials

| Resource | URL / Address | Username | Password |
|----------|--------------|----------|----------|
| Dashboard | http://localhost:3100 | admin@test.local | TestPass2026 |
| Dashboard (analyst) | http://localhost:3100 | analyst2@test.local | TestPass2026 |
| Go API | http://localhost:8090 | (JWT via /api/v1/auth/login) | — |
| PostgreSQL | localhost:5432 | zovark | zovark_dev_2026 |
| Valkey (Redis) | localhost:6379 | — | zovark_valkey_dev_2026 |
| LLM Inference | http://zovark-inference:8080 | — | — |
| Temporal | localhost:7233 | — | — |
| Signoz | localhost:3301 (tracing profile) | admin@zovark.local | TestPass2026 |
| OOB Watchdog | localhost:9091 | — | — |

---

## 7. Quick Start Guide

```bash
# 1. Start all services (11 core containers)
docker compose up -d

# 2. Start LLM inference (llama-server with Gemma 4 E4B)
docker compose -f docker-compose.yml -f docker-compose.distroless.yml up -d zovark-inference
# Wait ~60s for model load

# 3. Verify readiness
curl -sf http://localhost:8090/ready
# Expected: {"status":"ready","checks":{"postgresql":{"ready":true},"redis":{"ready":true},"temporal":{"ready":true}}}

# 4. Run system diagnostics
cmd/zvadmin/zvadmin.exe diagnose
# Expected: 8/8 checks passing

# 5. Run regression test (16 alerts: 11 attacks + 5 benign)
bash autoresearch/cycle10/verify_all.sh
# Expected: 16/16 PASSED

# 6. Open dashboard
# Navigate to http://localhost:3100
# Login: admin@test.local / TestPass2026

# 7. Run a forge benchmark
# Go to Alert Forge tab
# Set: 100 alerts, 70% attack ratio, 5/sec rate
# Click "Start Forge"
# Watch the Pipeline Monitor panel on the right for real-time metrics
```

---

## 8. API Reference (Key Endpoints)

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/auth/login | Get JWT token (30 min) |
| POST | /api/v1/auth/register | Create new user |

### Investigations
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/tasks | Submit alert for investigation |
| GET | /api/v1/tasks/:id | Get investigation result |
| GET | /api/v1/tasks | List investigations (paginated) |
| GET | /api/v1/tasks/stream | SSE stream for real-time updates |

### SIEM Ingestion
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/ingest/splunk | Splunk HEC format ingestion |
| POST | /api/v1/ingest/elastic | Elastic SIEM webhook ingestion |

### Remediation
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/remediation/suggest | Get remediation suggestions for an investigation |
| POST | /api/v1/remediation/verify | Run verification (synthetic re-test) |
| GET | /api/v1/remediation/actions | List remediation actions (with status/investigation filters) |
| PATCH | /api/v1/remediation/actions/:id | Update remediation status/assignee |

### Admin / Monitoring
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/admin/pipeline/status | Live pipeline metrics (throughput, latency, verdicts, time series) |
| POST | /api/v1/analytics/summary | Analytics data with time range and forge filter |
| POST | /api/v1/admin/diagnose | System health check (8 checks) |
| POST | /api/v1/admin/forge/start | Start synthetic alert forge run |
| GET | /api/v1/admin/forge/:id/stream | SSE stream for forge progress |

### Governance
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/governance/config | Get autonomy slider settings |
| PUT | /api/v1/governance/config | Update governance policy |

---

## 9. Competitive Position

Summary from the competitive benchmark (see docs/COMPETITIVE_BENCHMARK_v3.3.md):

| Metric | Zovark v3.3 | Dropzone AI | Torq HyperSOC | Human Analyst |
|--------|-------------|-------------|----------------|---------------|
| Investigation time | **2.6s avg** | 3-10 min | ~2 min | 70 min |
| Speed advantage | — | **60-250x faster** | **~50x faster** | **~1,600x faster** |
| Deployment | Air-gapped | Cloud SaaS only | Cloud SaaS only | On-site |
| LLM dependency | Minimal (Path A = zero) | Core | Core | N/A |
| Per-alert cost | $0 (hardware only) | ~$9/investigation | Enterprise pricing | ~$50/hour labor |
| Data residency | 100% on-premise | Single-tenant cloud | Cloud | On-site |

**Positioning**: Zovark is the fastest fully autonomous SOC investigation platform that runs entirely air-gapped. It delivers 2-second investigations with 100% detection accuracy (min risk 65+), zero false positives across all benign types, and full MITRE ATT&CK coverage on 13 attack categories — without sending a single byte to the cloud.

---

## 10. Roadmap

### Done (Sprint A + B + C1)
- Bundle system (schema, security gates, SAST/DAST, importer with semver + rollback)
- Intelligence layer (dynamic plan loading, attack path correlator, contextual risk scoring)
- Remediation engine (suggest/verify with circuit breaker, rate limiter, kill switch)
- Dashboard v2 (pipeline monitor, analytics, alert forge with SSE)
- Red team hardening (66 content scanner patterns, caret deobfuscation, ReDoS fixes)

### In Progress (Sprint C)
- C2: Copilot API — explain, suggest, correlate, brief endpoints with LLM priority management
- C3: License enforcement — Ed25519 signature verification, fail-closed, 30-day grace period

### Up Next (Sprint D)
- D1: zvadmin bundle CLI
- D2: OTA sync service
- D3: Bundle publisher
- D4: Signing key distribution

### Blocked
- E1: Model benchmark on A100 hardware (needs 48h stable pipeline)
- E3: Fine-tuning pilot (needs 200 DPO training pairs)

### Backlog
- Healthcare template pack (30 industry-specific templates)
- Blue/green deployment with auto-rollback
- Horizontal worker scaling (multi-worker Temporal queue)
- SIEM connector framework (native Splunk/Elastic plugins)
- Independent benchmark (CSA or MITRE Engenuity validation)
