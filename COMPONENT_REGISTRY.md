# COMPONENT_REGISTRY.md — Living System Inventory
# Updated: 2026-04-05 | Version: v3.3-dev
# 
# PURPOSE: This file prevents the reasoning engine and Claude Code from
# forgetting components that already exist. Before generating any prompt
# or starting any task, scan this registry and ask:
# "Which of these are relevant to what I'm about to do?"
#
# UPDATE RULE: At the end of every session, add any new components
# and update status of existing ones.

## Pipeline (6 stages)
| Stage | File | LLM? | Key functions |
|-------|------|------|--------------|
| 1. INGEST | worker/stages/ingest.py | No | sanitize, normalize, dedup, PII mask, attack scan |
| 2. ANALYZE | worker/stages/analyze.py | FAST | Path A (saved plan) or Path C (LLM tool select) |
| 3. EXECUTE | worker/tools/runner.py | No | DAG builder, parallel batch executor, $stepN resolution |
| 4. ASSESS | worker/stages/assess.py | CODE | verdict, signal boost, MITRE extraction, summary |
| 4.5 GOVERN | worker/stages/govern.py | No | autonomy slider (observe/assist/autonomous) |
| 5. STORE | worker/stages/store.py | No | DB write, NOTIFY, dedup update |

## LLM Infrastructure
| Component | File | What it does | When to use |
|-----------|------|-------------|-------------|
| LLM Client | worker/llm_client.py | Singleton httpx, dual semaphores, GBNF grammar, output sanitizer | Any LLM-related change |
| LLM Gateway | worker/stages/llm_gateway.py | Dual endpoint routing (FAST/CODE), model swap | Model changes, endpoint config |
| Tool Selection Grammar | worker/grammars/tool_selection.gbnf | Constrains FAST model JSON output | Tool selection changes |
| Verdict Grammar | worker/grammars/verdict.gbnf | Constrains CODE model JSON output | Verdict format changes |
| Prompt Library | dpo/prompts_v2.py | System prompts, scoring anchors (~900 LOC) | READ ONLY unless explicitly approved |
| Output Sanitizer | worker/llm_client.py:_sanitize_llm_output() | Strips Gemma 4 control tokens | Model swap, output corruption |

## Tools & Plans
| Component | File | Count | When to use |
|-----------|------|-------|-------------|
| Tool Registry | worker/tools/catalog.py | 40 tools | Adding/removing tools |
| Tool Subsets | worker/tools/tool_subsets.py | Per-attack pruned catalogs | Adding tools to attack types |
| Investigation Plans | worker/tools/investigation_plans.json | 24 plans | New attack types, plan restructuring |
| Detection Tools | worker/tools/detection.py | 12 tools | Scoring calibration |
| MITRE Mapping | worker/stages/mitre_mapping.py | MITRE_MAP dict | MITRE coverage gaps |

## Burst Protection (3 layers)
| Layer | File | What it does |
|-------|------|-------------|
| L1: Dedup | api/alert_dedup.go | Investigation-aware Redis dedup, severity escalation |
| L2: Batch | api/batch_buffer.go | Lua-atomic batching by (type, source_ip) |
| L3: Backpressure | api/backpressure.go | Workflow queue depth throttle + drain |

## Observability Stack
| Tool | Location | What it provides | WHEN TO USE IT |
|------|----------|-----------------|----------------|
| zvadmin diagnose | cmd/zvadmin/ | 8-check system health | Every session start, every verification |
| zvadmin alerts | cmd/zvadmin/ | Verdict distribution, latency by path | After pipeline changes |
| zvadmin model check | cmd/zvadmin/ | Per-type calibration, separation gap | After scoring/calibration changes |
| zvadmin dedup health | cmd/zvadmin/ | Dedup decision distribution, efficiency | After dedup changes |
| zvadmin troubleshoot | cmd/zvadmin/ | 5-symptom guided diagnosis | When something is broken |
| zvadmin update | cmd/zvadmin/ | Staging + backup + rollback | Deployments |
| Signoz/OTEL | docker compose --profile tracing | Distributed traces, per-stage latency, P95/P99 | Performance optimization |
| AutoResearch Engine | autoresearch/telemetry_driven/ | 6-module weakness finder + test generator | After ANY change — finds what regression missed |
| OOB Watchdog | api/oob.go (:9091) | Health endpoint, debug state, Redis counters | Container health, dedup observability |
| Pipeline Status | api/zvadmin_handlers.go | GET /admin/pipeline/status — active, latency, verdicts, risk, recent | Dashboard, monitoring |

## Dashboard (web-admin)
| Component | File | What it shows | Data source |
|-----------|------|--------------|-------------|
| PipelineMonitor | web-admin/src/components/PipelineMonitor.tsx | Status bar, metrics, stage flow, charts, activity log | GET /admin/pipeline/status |
| AnalyticsPanel | web-admin/src/components/AnalyticsPanel.tsx | Verdict/risk distribution, attack type bar chart | POST /analytics/summary |
| AlertForge | web-admin/src/components/AlertForge.tsx | Forge config + PipelineMonitor, SSE progress | POST /admin/forge/start |
| AdminDashboard | web-admin/src/components/AdminDashboard.tsx | Tab container for zvadmin, forge, analytics | N/A |
| ZvadminPanel | web-admin/src/components/ZvadminPanel.tsx | Diagnose, config, bootstrap | POST /admin/diagnose |

## Remediation Engine (Sprint C1)
| Component | File | What it does |
|-----------|------|-------------|
| Remediation Rules | worker/intelligence/remediation.py | 22 attack types, circuit breaker, rate limiter |
| Remediation API | api/remediation_handlers.go | suggest, verify, list, patch (4 endpoints) |
| Kill Switch | system_configs: remediation.auto_verify_enabled | Default false, controls verification |

## Security (Content Scanner)
| Component | File | Count | What it does |
|-----------|------|-------|-------------|
| Content Scanner | worker/stages/ingest.py:RAW_LOG_ATTACK_PATTERNS | 66 patterns | Overrides benign routing when attack content in raw_log |
| Caret Deobfuscation | worker/stages/ingest.py:_has_raw_log_attack_content | On ^ detection | Strips CMD caret escapes before pattern matching |
| Parse Guard | worker/tools/parsing.py:parse_windows_event | 4KB limit | Prevents ReDoS on large payloads |

## Quality Gates
| Gate | Command | When to run |
|------|---------|-------------|
| 16/16 Regression | bash autoresearch/cycle10/verify_all.sh | After ANY pipeline change |
| Dedup Stress | bash autoresearch/cycle10/dedup_stress_test.sh | After dedup changes |
| AutoResearch Cycle | bash autoresearch/telemetry_driven/run.sh | After any change — finds hidden regressions |
| Unit Tests | docker compose exec -T worker python -m pytest tests/ -q | After Python changes |
| Code Cache Flush | scripts/flush_code_cache.sh | After model swap or prompt changes |
| Path C Smoke Test | Submit unusual_network_traffic via API | After ANY analyze.py or prompt changes |

## Feature Flags
| Flag | Default | What it controls |
|------|---------|-----------------|
| ZOVARK_EXECUTION_MODE | tools | tools (v3) vs sandbox (v2 legacy) |
| ZOVARK_PARALLEL_TOOLS_ENABLED | false | Parallel tool execution in runner.py |
| ZOVARK_MAX_PARALLEL_TOOLS | 4 | Concurrency limit for parallel tools |
| ZOVARK_FAST_FILL | false | Skip LLM, template-only |

## Templates
| Source | Count | Location |
|--------|-------|----------|
| Hand-written | 12 | skill_templates DB table |
| Flywheel | 2 | skill_templates DB table |
| AutoResearch | 10 | skill_templates DB table |
| Quorum-promoted | 1 | skill_templates DB table |
| Total | 25 | |

## Infrastructure
| Component | Container | Port | Notes |
|-----------|-----------|------|-------|
| Go API | zovark-api | 8090 | Main entry point |
| Python Worker | worker | — | Temporal worker |
| Inference | zovark-inference | 8080 | llama-server, Gemma 4 E4B |
| PostgreSQL | postgres | 5432 | 86+ tables, 65 migrations |
| Valkey | valkey | 6379 | BSD Redis replacement |
| Temporal | zovark-temporal | 7233 | Workflow orchestration |
| Healer | zovark-healer | — | Auto-recovery (512MB limit) |
| OOB Watchdog | — | 9091 | Health monitoring |
| Web Admin | zovark-web-admin | 3100 | nginx:alpine, SPA fallback |
| Signoz | tracing profile | 3301 | OTEL trace backend |

## Engineering Process
| Tool | File | When to use |
|------|------|-------------|
| Engineering Framework | ENGINEERING_DISCIPLINE.md | Every Claude Code session start |
| /grill-me | ENGINEERING_DISCIPLINE.md | Before any new feature |
| /write-a-prd | ENGINEERING_DISCIPLINE.md | After /grill-me reaches shared understanding |
| /prd-to-issues | ENGINEERING_DISCIPLINE.md | After PRD approved |
| /tdd | ENGINEERING_DISCIPLINE.md | For each issue |
| /status | ENGINEERING_DISCIPLINE.md | Session start, context recovery |
| /improve-codebase-architecture | ENGINEERING_DISCIPLINE.md | After implementation, before commit |
| /improvement-cycle | ENGINEERING_DISCIPLINE.md | Weekly or after major feature sessions |
| Cycle Reports | CYCLE_REPORT_N.md | Output of each improvement cycle |
| Benchmark Comparison | BENCHMARK_COMPARISON_v3.2.1.md | Model swap evaluation |
| Overnight Batch | OVERNIGHT_REPORT.md | Autonomous stress test + fix cycle results |
| Component Registry | COMPONENT_REGISTRY.md | Living inventory — check before every task |
| Kanban Roadmap | Projects/Zovark_Roadmap.md | Session start, task selection |
| Sprint Board | Projects/Sprint_C_Pipeline.md | Current sprint tracking |
| Ship Process | Projects/ENGINEERING_PROCESS.md | Every session, every commit |
| Session Protocol | Projects/SESSION_PROTOCOL.md | Session start and end |
