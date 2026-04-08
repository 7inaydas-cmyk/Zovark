# Every Service in Zovark (17 Docker Containers)

Zovark runs as a fleet of 17 containers, each with a single job. Think of them as departments in a company -- each one is specialized, and they communicate through well-defined channels. Here is every service, what it does, and why it exists.

---

## 1. postgres (PostgreSQL 16 + pgvector)

| Field | Value |
|-------|-------|
| Port | 5432 |
| Health check | `pg_isready` (asks "are you accepting connections?") |
| Who talks to it | API (Go), Worker (Python), PgBouncer |
| Analogy | **The filing cabinet room.** Every investigation result, every audit trail entry, every user account, every configuration setting lives here. If Zovark has a memory, this is it. |

PostgreSQL is the main database. It stores 86+ tables across 70 migrations. The `pgvector` extension adds vector similarity search, which enables finding alerts that are "similar" to past ones. Row-Level Security (RLS) is enabled on 10 tables so that one customer's data is invisible to another, even if a bug leaks a query.

---

## 2. redis / valkey (Valkey 7)

| Field | Value |
|-------|-------|
| Port | 6379 |
| Health check | `valkey-cli ping` (responds "PONG") |
| Who talks to it | API (Go), Worker (Python), Temporal |
| Analogy | **The whiteboard in the war room.** Fast, temporary information that everyone can see at a glance -- "we already investigated this alert," "there are 47 alerts in the batch buffer right now," "the circuit breaker is yellow." |

Valkey is a BSD-licensed drop-in replacement for Redis (we switched to avoid Redis's license change). It handles deduplication lookups, the code cache (so repeat alerts skip the AI), batch buffering, backpressure counters, and the circuit breaker state. Everything in Valkey is transient -- if it restarts, the data rebuilds itself. No permanent data lives here.

---

## 3. pgbouncer (Connection Pooler)

| Field | Value |
|-------|-------|
| Port | 6432 |
| Health check | `pg_isready` |
| Who talks to it | API and Worker connect *through* PgBouncer to reach PostgreSQL |
| Analogy | **The receptionist who manages the meeting rooms.** PostgreSQL can only handle about 25 simultaneous connections efficiently. PgBouncer sits in front and juggles up to 400 incoming requests across those 25 slots, so nobody has to wait. |

Without PgBouncer, a burst of 100 simultaneous API requests would each try to open a direct database connection, overwhelming PostgreSQL. PgBouncer queues and reuses connections transparently.

---

## 4. temporal (Workflow Orchestration)

| Field | Value |
|-------|-------|
| Port | 7233 |
| Health check | None (relied on by Worker connecting) |
| Who talks to it | API (starts workflows), Worker (executes activities) |
| Analogy | **The project manager.** When the API says "investigate this alert," Temporal creates a workflow -- a durable, resumable sequence of steps. If the Worker crashes mid-investigation, Temporal remembers where it left off and retries. It guarantees every investigation either completes or fails explicitly -- nothing silently disappears. |

Temporal handles up to 32 concurrent workflows and 16 concurrent activities. It is the backbone that makes Zovark reliable under load.

---

## 5. api (Go Gin Server)

| Field | Value |
|-------|-------|
| Port | 8090 |
| Health check | `GET /ready` (checks PostgreSQL + Redis + Temporal) |
| Who talks to it | Dashboard, Web-Admin, SIEM systems, external integrations, analysts |
| Analogy | **The front desk of the entire operation.** Every request -- submitting an alert, checking a verdict, logging in, pulling analytics -- comes through the API. It has 162 routes covering authentication, alert intake, investigation results, entity graphs, copilot queries, remediation, licensing, governance, diagnostics, and more. |

The API handles the three-layer burst protection (dedup, batch buffer, backpressure) before handing alerts to Temporal. It also serves the SSE (Server-Sent Events) stream that pushes real-time investigation updates to the dashboard.

---

## 6. worker (Python Temporal Worker)

| Field | Value |
|-------|-------|
| Port | None (no external port -- only talks to Temporal and internal services) |
| Health check | Python import check |
| Who talks to it | Temporal (assigns it work), PostgreSQL (reads/writes), Valkey (caching), Inference (AI calls) |
| Analogy | **The team of detectives.** The Worker is where the actual investigations happen. It runs the 6-stage pipeline (Ingest through Store), executes the 40 investigation tools, calls the AI model when needed, and writes the verdicts. It can handle 16 investigations simultaneously. |

The Worker is the most complex service. It contains all the Python code for sanitization, normalization, tool execution, AI model interaction, verdict assessment, and governance checks.

---

## 7. dashboard (React 19 + Vite + Tailwind)

| Field | Value |
|-------|-------|
| Port | 3000 |
| Health check | `wget 127.0.0.1:3000` |
| Who talks to it | Analysts via web browser; talks to the API for data |
| Analogy | **The SOC war room's big screen.** This is what analysts look at all day. 17 pages showing live investigations, verdicts, risk scores, entity graphs, analytics charts, and the real-time investigation feed. Dark theme (#060A14 background, green accents) designed for 24/7 monitoring. |

The dashboard connects to the API's SSE stream so verdicts appear in real time without page refreshes.

---

## 8. web-admin (React Admin Panel)

| Field | Value |
|-------|-------|
| Port | 3100 |
| Health check | `wget 127.0.0.1:80` |
| Who talks to it | Administrators via web browser; talks to the API |
| Analogy | **The manager's office.** While the dashboard is for day-to-day SOC analysts, the web-admin is for system administrators. It has the Pipeline Monitor (live metrics, stage flow, sparklines), Analytics Panel (verdict charts, time series), and Alert Forge (test alert submission). 8 components focused on system health and configuration. |

---

## 9. healer (Python Self-Healing Agent)

| Field | Value |
|-------|-------|
| Port | 8081 |
| Health check | `curl 127.0.0.1:8081/api/health` |
| Who talks to it | Monitors all other services; talks to Docker API (through proxy) and AI inference |
| Analogy | **The building maintenance crew that also has a medical degree.** Every 60 seconds, the healer checks that the API can reach the database, the dashboard is responding, and the AI model is loaded. If something is down, it follows a 3-level escalation: (1) auto-restart the container, (2) ask the AI to diagnose the crash logs, (3) alert the operator. It also has a Sneakernet web UI for air-gapped deployments where you cannot SSH in. |

The healer is memory-limited to 512MB because of a known Windows Docker issue where it can grow to 3GB+ under sustained load.

---

## 10. squid-proxy (Egress Proxy)

| Field | Value |
|-------|-------|
| Port | 3128 |
| Health check | None |
| Who talks to it | Any container that needs outbound internet access |
| Analogy | **The single guarded exit.** In an air-gapped deployment, nothing should reach the internet. But for non-air-gapped setups, any outbound traffic must go through Squid so it can be logged and restricted. This is a compliance requirement for regulated environments (CMMC, HIPAA). |

---

## 11. docker-socket-proxy (Container Lifecycle Proxy)

| Field | Value |
|-------|-------|
| Port | 2375 |
| Health check | None |
| Who talks to it | Healer (to restart containers), Worker (for legacy sandbox mode) |
| Analogy | **The security guard at the server room door.** The Docker socket is extremely powerful -- full access means you can do anything to any container. Instead of giving services direct access, they go through this proxy which only allows "start," "stop," and "inspect" operations. Attempts to pull images, execute commands inside containers, or access volumes get a 403 Forbidden. |

This is a critical security boundary. Without it, a compromised Worker could take over the entire system.

---

## 12. zovark-inference (llama-server + Gemma 4 E4B)

| Field | Value |
|-------|-------|
| Port | 8080 (internal only) |
| Health check | `curl /health` |
| Who talks to it | Worker (for AI-powered analysis and assessment) |
| Analogy | **The brain.** This is the local AI model that runs entirely on-premises with no internet connection. It uses llama.cpp (an efficient C++ inference engine) to run Google's Gemma 4 E4B model quantized to Q4_K_M (5GB file, needs about 7GB RAM). The Worker asks it two kinds of questions: "What tools should I use for this unusual alert?" (Stage 2, Path C) and "Based on what the tools found, what is the risk and verdict?" (Stage 4). Context window is set to 4,096 tokens to keep memory usage low -- Zovark prompts rarely exceed 800 tokens. |

No data ever leaves this container. No cloud AI service is used. This is the core of Zovark's air-gap story.

---

## 13. clickhouse (Signoz Trace Backend)

| Field | Value |
|-------|-------|
| Port | 9000 (native), 8123 (HTTP) |
| Health check | TCP connect on 9000 |
| Who talks to it | Signoz collector (writes traces), Signoz query (reads traces) |
| Analogy | **The high-speed filing system for performance data.** ClickHouse is a column-oriented database optimized for analytics. It stores every OpenTelemetry trace -- every stage timing, every tool execution duration, every AI call latency. When you ask "how long did Stage 3 take on average last week?" ClickHouse answers in milliseconds even across millions of traces. |

---

## 14. signoz-collector (OTEL Collector)

| Field | Value |
|-------|-------|
| Ports | 4317 (gRPC), 4318 (HTTP) |
| Health check | TCP connect on 4318 |
| Who talks to it | Worker and API send traces to it; it forwards to ClickHouse |
| Analogy | **The mail sorting facility.** The Worker and API generate OpenTelemetry traces (performance data) and send them to the collector. The collector batches, processes, and routes them into ClickHouse. It speaks two protocols: gRPC (fast, binary) and HTTP (compatible, JSON). |

---

## 15. signoz-query (Trace Query Service)

| Field | Value |
|-------|-------|
| Port | Internal only |
| Health check | `GET /api/v1/health` |
| Who talks to it | Signoz frontend sends queries to it; it reads from ClickHouse |
| Analogy | **The research librarian.** When an engineer asks "show me all traces where Stage 4 took longer than 10 seconds," the query service translates that into a ClickHouse query, runs it, and returns formatted results. |

---

## 16. signoz-frontend (Signoz UI)

| Field | Value |
|-------|-------|
| Port | 3301 |
| Health check | HTTP 200 on port 3301 |
| Who talks to it | Engineers via web browser |
| Analogy | **The observatory.** A web interface where engineers can see trace waterfalls, latency distributions, error rates, and service maps. Login: admin@zovark.local / TestPass2026. This is the engineering team's tool -- not for SOC analysts or customers. |

---

## 17. juice-shop (OWASP Test App)

| Field | Value |
|-------|-------|
| Port | 3001 |
| Health check | None |
| Who talks to it | Test scripts, Filebeat (in SIEM lab profile) |
| Analogy | **The crash test dummy.** OWASP Juice Shop is an intentionally vulnerable web application. We run attacks against it, capture the resulting security logs, feed them into Zovark, and verify that Zovark correctly identifies every attack. It is a testing tool, not a production service. Our benchmark: 99/100 accuracy on Juice Shop traffic (70/70 attacks detected, 29/30 benign correctly classified). |

---

## How They All Connect

Here is the simplified flow:

1. **SIEM** sends an alert to the **API** (port 8090).
2. The **API** checks **Valkey** for dedup/batching, then starts a workflow in **Temporal**.
3. **Temporal** assigns the workflow to the **Worker**.
4. The **Worker** runs the 6-stage pipeline. During Stages 2 and 4, it may call **zovark-inference** for AI analysis.
5. The **Worker** writes results to **PostgreSQL** (through **PgBouncer**) and sends OpenTelemetry traces to the **Signoz collector**.
6. **PostgreSQL** fires a NOTIFY, which the **API** picks up and pushes to the **Dashboard** via SSE.
7. The **Healer** watches everything and auto-restarts any service that goes down.
8. Engineers use **Signoz frontend** to debug performance issues.
9. Admins use **Web-Admin** for system configuration and pipeline monitoring.

All inter-service communication happens on an internal Docker network. Only ports 8090 (API), 3000 (Dashboard), 3100 (Web-Admin), 8081 (Healer), and 3301 (Signoz) are exposed to the host machine.
