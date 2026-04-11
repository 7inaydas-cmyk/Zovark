# ZOVARK Codebase Census

Generated: 2026-03-24 (v1.5.1)
Commit: 161 commits on master

## Lines of Code

| Language | Source | Tests | Total |
|----------|--------|-------|-------|
| Go | 9758 | 863 | 10621 |
| Python | 26428 | 15581 | 42009 |
| TypeScript | 8862 | 0 | 8862 |
| SQL | 3222 | — | 3222 |
| Shell | 4103 | — | 4103 |
| YAML/Config | 5998 | — | 5998 |
| **Total** | — | — | **74815** |

## File Counts by Directory

| Directory | Files | Description |
|-----------|-------|-------------|
| api/ | 49 | Go API gateway — auth, RBAC, handlers, middleware |
| worker/ | 154 | Python Temporal worker — investigation pipeline |
| dashboard/ | 55 | React 19 + Vite 7 + Tailwind 4 frontend |
| mcp-server/ | 25 | TypeScript MCP server (tools, resources, prompts) |
| sandbox/ | 4 | AST prefilter + seccomp + kill timer |
| scripts/ | 35 | Operational scripts (PoV, load testing, census) |
| migrations/ | 55 | SQL migration files (001-055) |
| k8s/ | 32 | Kubernetes manifests (Kustomize, 4 overlays) |
| helm/ | 11 | Helm charts for K8s deployment |
| terraform/ | 7 | AWS/GCP infrastructure-as-code |
| config/ | 2 | PostgreSQL configuration |
| proxy/ | 1 | Squid egress proxy configuration |
| monitoring/ | 9 | Prometheus rules + Grafana dashboards |
| security-fixes/ | 18 | Security remediation specs and reports |
| sdk/ | 6 | Client SDK |
| tests/ | 83 | Integration tests + test corpus |
| docs/ | 23 | Architecture, deployment, security docs |
| demo/ | 1 | Demo scenario data |
| files/ | 4 | Prompt archives |
| data/ | 2 | Runtime data directory |
| temporal-config/ | 1 | Temporal workflow engine configuration |
| .github/ | 4 | CI/CD workflows |

## Go Source Files

- `./api/analytics.go` (161 lines)
- `./api/apikeys.go` (209 lines)
- `./api/approval_handlers.go` (143 lines)
- `./api/approvals.go` (1 lines)
- `./api/audit_export.go` (144 lines)
- `./api/auth.go` (267 lines)
- `./api/db.go` (24 lines)
- `./api/envelope.go` (72 lines)
- `./api/error_context.go` (245 lines)
- `./api/errors.go` (17 lines)
- `./api/export.go` (101 lines)
- `./api/feedback.go` (109 lines)
- `./api/gdpr.go` (69 lines)
- `./api/handlers.go` (58 lines)
- `./api/integrations.go` (235 lines)
- `./api/killswitch.go` (408 lines)
- `./api/main.go` (286 lines)
- `./api/mcp_approvals.go` (439 lines)
- `./api/middleware.go` (128 lines)
- `./api/migrate.go` (185 lines)
- `./api/models.go` (295 lines)
- `./api/nats.go` (221 lines)
- `./api/oidc.go` (657 lines)
- `./api/playbooks.go` (156 lines)
- `./api/ratelimit.go` (220 lines)
- `./api/security.go` (252 lines)
- `./api/shadow.go` (422 lines)
- `./api/siem.go` (602 lines)
- `./api/skill_handlers.go` (58 lines)
- `./api/sse.go` (132 lines)
- `./api/stats_handlers.go` (91 lines)
- `./api/task_handlers.go` (865 lines)
- `./api/temporal.go` (21 lines)
- `./api/tenants.go` (517 lines)
- `./api/tokenquota.go` (418 lines)
- `./api/totp.go` (300 lines)
- `./api/user_handlers.go` (106 lines)
- `./api/vault.go` (167 lines)
- `./security-fixes/api/auth_registration_fix.go` (197 lines)
- `./security-fixes/api/request_hardening.go` (176 lines)
- `./security-fixes/api/security_hardening_p1p2.go` (163 lines)
- `./security-fixes/api/siem_sanitizer.go` (212 lines)
- `./security-fixes/api/tenant_isolation_fix.go` (209 lines)

## Python Source Files (worker/)

- `./worker/activities.py` (1086 lines)
- `./worker/activities/__init__.py` (0 lines)
- `./worker/activities/network_analysis.py` (280 lines)
- `./worker/approvals/__init__.py` (4 lines)
- `./worker/approvals/human_gate.py` (300 lines)
- `./worker/bootstrap/__init__.py` (0 lines)
- `./worker/bootstrap/activities.py` (402 lines)
- `./worker/bootstrap/cisa_parser.py` (27 lines)
- `./worker/bootstrap/kev_alert_generator.py` (58 lines)
- `./worker/bootstrap/mitre_parser.py` (52 lines)
- `./worker/bootstrap/workflow.py` (133 lines)
- `./worker/context_manager.py` (70 lines)
- `./worker/correlation/__init__.py` (1 lines)
- `./worker/correlation/engine.py` (218 lines)
- `./worker/correlation/workflow.py` (78 lines)
- `./worker/cost_calculator.py` (40 lines)
- `./worker/database/__init__.py` (0 lines)
- `./worker/database/pool_manager.py` (109 lines)
- `./worker/database/routing.py` (116 lines)
- `./worker/detection/__init__.py` (0 lines)
- `./worker/detection/pattern_miner.py` (155 lines)
- `./worker/detection/rule_validator.py` (246 lines)
- `./worker/detection/sigma_generator.py` (253 lines)
- `./worker/detection/workflow.py` (109 lines)
- `./worker/egress_controller.py` (164 lines)
- `./worker/embedding/__init__.py` (1 lines)
- `./worker/embedding/batch.py` (129 lines)
- `./worker/embedding/versioning.py` (204 lines)
- `./worker/entity_graph.py` (444 lines)
- `./worker/entity_normalize.py` (131 lines)
- `./worker/finetuning/__init__.py` (1 lines)
- `./worker/finetuning/data_export.py` (150 lines)
- `./worker/finetuning/evaluation.py` (293 lines)
- `./worker/finetuning/evaluator.py` (153 lines)
- `./worker/finetuning/workflow.py` (230 lines)
- `./worker/integrations/__init__.py` (20 lines)
- `./worker/integrations/abuseipdb.py` (61 lines)
- `./worker/integrations/email.py` (255 lines)
- `./worker/integrations/jira.py` (178 lines)
- `./worker/integrations/servicenow.py` (152 lines)
- `./worker/integrations/slack.py` (171 lines)
- `./worker/integrations/teams.py` (179 lines)
- `./worker/integrations/virustotal.py` (69 lines)
- `./worker/intelligence/__init__.py` (0 lines)
- `./worker/intelligence/blast_radius.py` (109 lines)
- `./worker/intelligence/cross_tenant.py` (256 lines)
- `./worker/intelligence/cross_tenant_workflow.py` (69 lines)
- `./worker/intelligence/fp_analyzer.py` (285 lines)
- `./worker/intelligence/stix_taxii.py` (268 lines)
- `./worker/investigation/__init__.py` (0 lines)
- `./worker/investigation/deeplog_analyzer.py` (231 lines)
- `./worker/investigation_cache.py` (321 lines)
- `./worker/investigation_memory.py` (184 lines)
- `./worker/llm_logger.py` (81 lines)
- `./worker/logger.py` (29 lines)
- `./worker/main.py` (213 lines)
- `./worker/model_config.py` (94 lines)
- `./worker/models/__init__.py` (1 lines)
- `./worker/models/registry.py` (163 lines)
- `./worker/nats_consumer.py` (347 lines)
- `./worker/pii_detector.py` (354 lines)
- `./worker/prompt_init.py` (219 lines)
- `./worker/prompt_registry.py` (66 lines)
- `./worker/prompts/__init__.py` (1 lines)
- `./worker/prompts/entity_extraction.py` (61 lines)
- `./worker/prompts/investigation_prompt.py` (82 lines)
- `./worker/rate_limiter.py` (130 lines)
- `./worker/redis_client.py` (49 lines)
- `./worker/reporting/__init__.py` (0 lines)
- `./worker/reporting/export.py` (413 lines)
- `./worker/reporting/incident_report.py` (284 lines)
- `./worker/response/__init__.py` (0 lines)
- `./worker/response/actions.py` (309 lines)
- `./worker/response/auto_trigger.py` (94 lines)
- `./worker/response/template_resolver.py` (169 lines)
- `./worker/response/workflow.py` (318 lines)
- `./worker/retention/purge_job.py` (133 lines)
- `./worker/scheduler/__init__.py` (1 lines)
- `./worker/scheduler/workflow.py` (167 lines)
- `./worker/search/__init__.py` (1 lines)
- `./worker/search/semantic.py` (189 lines)
- `./worker/security/__init__.py` (0 lines)
- `./worker/security/adversarial_review.py` (168 lines)
- `./worker/security/alert_sanitizer.py` (193 lines)
- `./worker/security/injection_detector.py` (92 lines)
- `./worker/security/prompt_sanitizer.py` (31 lines)
- `./worker/security/risk_validator.py` (63 lines)
- `./worker/shadow.py` (520 lines)
- `./worker/skills/__init__.py` (0 lines)
- `./worker/skills/deobfuscation.py` (160 lines)
- `./worker/sla/__init__.py` (1 lines)
- `./worker/sla/monitor.py` (153 lines)
- `./worker/sre/__init__.py` (0 lines)
- `./worker/sre/applier.py` (248 lines)
- `./worker/sre/diagnose.py` (196 lines)
- `./worker/sre/monitor.py` (138 lines)
- `./worker/sre/patcher.py` (218 lines)
- `./worker/sre/tester.py` (147 lines)
- `./worker/sre/workflow.py` (154 lines)
- `./worker/stampede.py` (422 lines)
- `./worker/tests/__init__.py` (0 lines)
- `./worker/tests/accuracy/run_validation.py` (270 lines)
- `./worker/tests/test_adversarial_review.py` (249 lines)
- `./worker/tests/test_alert_sanitizer.py` (339 lines)
- `./worker/tests/test_ast_prefilter.py` (225 lines)
- `./worker/tests/test_egress_controller.py` (245 lines)
- `./worker/tests/test_risk_validator.py` (312 lines)
- `./worker/tests/test_template_resolver.py` (102 lines)
- `./worker/tests/test_vault_manager.py` (311 lines)
- `./worker/threat_intel/__init__.py` (0 lines)
- `./worker/threat_intel/attack_surface.py` (168 lines)
- `./worker/token_quota.py` (277 lines)
- `./worker/training/__init__.py` (1 lines)
- `./worker/training/trigger.py` (137 lines)
- `./worker/validation/__init__.py` (3 lines)
- `./worker/validation/dry_run.py` (160 lines)
- `./worker/vault_manager.py` (138 lines)
- `./worker/workflows.py` (1244 lines)
- `./worker/workflows/__init__.py` (0 lines)
- `./worker/workflows/feedback_aggregation.py` (224 lines)
- `./worker/workflows/zovark_workflows.py` (148 lines)
- `./worker/workflows/kev_processing.py` (194 lines)

## Database

- Migration files: 55+
- Init schema: init.sql
