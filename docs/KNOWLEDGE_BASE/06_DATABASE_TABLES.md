# Database Tables in Zovark

Zovark uses PostgreSQL 16 with the pgvector extension (for AI-powered similarity search). There are 86+ tables spread across 70 migration files. Think of the database as the platform's permanent memory -- every investigation, every entity, every decision, and every configuration lives here.

This document covers the most important tables grouped by what they do.

---

## Core Investigation Tables

These tables hold the primary data: the alerts that come in, the investigations that run, and everything Zovark learns along the way.

### agent_tasks

This is the main table. Every alert that enters Zovark becomes a row in agent_tasks. It is the single source of truth for "what happened."

| Column | What it stores |
|--------|---------------|
| id | Unique identifier (UUID) for this investigation |
| tenant_id | Which customer this belongs to (multi-tenant isolation) |
| task_type | The type of alert: brute_force, phishing, ransomware, etc. |
| input | The full SIEM alert data as JSON -- everything the SIEM sent |
| output | The complete investigation result as JSON -- verdict, risk score, findings, IOCs, MITRE techniques, summary |
| status | Where the investigation stands: pending, running, completed, failed |
| verdict | The final call: true_positive, false_positive, benign, suspicious, inconclusive |
| risk_score | 0-100 severity rating |
| path_taken | How the investigation was processed: plan_A (saved plan), plan_B (template + AI), plan_C (AI tool selection) |
| plan_executed | Which investigation plan was used (e.g., "brute_force") |
| execution_mode | tools (v3) or sandbox (v2 legacy) |
| trace_id | UUID that follows this alert through every system, for debugging |
| dedup_count | How many duplicate alerts were suppressed because this investigation already covers them |
| created_at | When the alert arrived |

This table has Row-Level Security (RLS) enabled -- a customer can only see their own rows, enforced by the database itself.

### investigations

A summary table linked to agent_tasks. Where agent_tasks stores everything, investigations stores the curated result for analytics and reporting.

| Column | What it stores |
|--------|---------------|
| id | Unique identifier |
| tenant_id | Customer isolation |
| task_id | Link back to the agent_tasks row |
| alert_type | Category of the alert |
| verdict | Same as agent_tasks but optimized for queries |
| risk_score | 0-100 |
| confidence | How confident Zovark is in the verdict (0.0 to 1.0) |
| attack_techniques | Array of MITRE ATT&CK technique IDs |
| summary | Plain-English investigation summary |
| summary_embedding | A vector (768 dimensions) for AI-powered similarity search -- "find investigations that look like this one" |
| model_id / model_version | Which AI model was used |
| analyst_feedback | JSON blob of analyst corrections (thumbs up/down, notes) |

This table is partitioned by month -- each month gets its own physical storage partition. This means queries for "all April investigations" are fast because PostgreSQL only scans one partition instead of the entire table.

### investigation_memory

Stores patterns learned from successful investigations. Think of this as Zovark's "experience" -- it remembers what worked before.

| Column | What it stores |
|--------|---------------|
| task_type | The attack type (brute_force, phishing, etc.) |
| alert_signature | A fingerprint of the alert pattern |
| code_template | The investigation code or plan that worked |
| iocs_found | What IOCs were discovered (JSON) |
| findings_found | What findings were generated (JSON) |
| risk_score | The risk score that resulted |
| success | Whether the investigation succeeded |

When a new alert comes in, Zovark checks investigation_memory to see if a similar alert was successfully investigated before. If so, it uses that experience to guide the current investigation.

### audit_events

The complete audit trail. Every significant action in the system gets logged here -- investigations starting, completing, users logging in, entities being extracted, approvals being granted.

| Column | What it stores |
|--------|---------------|
| tenant_id | Customer isolation |
| event_type | What happened: investigation_started, investigation_completed, code_executed, approval_granted, entity_extracted, user_login, injection_detected, cross_tenant_hit, etc. |
| actor_id / actor_type | Who did it: a user, the worker process, or the system |
| resource_type / resource_id | What was affected |
| trace_id | Links back to the original alert for end-to-end tracing |
| metadata | JSON blob with event-specific details |

This table is also partitioned by month for query performance and is essential for compliance (GDPR, HIPAA, CMMC all require audit trails).

---

## Entity Graph Tables

The entity graph is how Zovark connects the dots between investigations. See the dedicated Entity Graph document (07_ENTITY_GRAPH.md) for a full explanation.

### entities

Every IP address, domain, file hash, username, email, and device that Zovark encounters during investigations becomes an entity.

| Column | What it stores |
|--------|---------------|
| id | Unique identifier |
| entity_hash | SHA-256 hash of the value (for privacy-safe cross-tenant sharing) |
| entity_type | ip, domain, file_hash, url, user, device, process, email |
| value | The actual value (e.g., "185.220.101.45") |
| tenant_id | Customer isolation |
| threat_score | 0-100 based on how often this entity appears in malicious investigations |
| observation_count | How many times Zovark has seen this entity across all investigations |
| first_seen / last_seen | Time range of observations |

### entity_edges

Relationships between entities. "IP X logged into username Y" or "domain A resolved to IP B."

| Column | What it stores |
|--------|---------------|
| source_entity_id / target_entity_id | The two entities connected by this relationship |
| edge_type | The relationship: communicates_with, resolved_to, logged_into, executed, downloaded, contains, parent_of, accessed, sent_to, received_from, associated_with |
| investigation_id | Which investigation discovered this relationship |
| mitre_technique | The MITRE technique associated with this relationship |
| confidence | How confident the system is in this connection (0.0 to 1.0) |

### cross_tenant_entities

Shared intelligence across customers WITHOUT revealing customer-specific data.

| Column | What it stores |
|--------|---------------|
| entity_hash | SHA-256 hash only -- the raw value is never stored here |
| entity_type | ip, domain, file_hash, etc. |
| tenant_count | How many different customers have seen this entity |
| threat_score | Aggregate threat score across all customers |

If Customer A sees IP X in a ransomware attack, and Customer B later sees the same IP, the cross_tenant_entities table tells Customer B "this IP has been seen by multiple organizations with a high threat score" without revealing that Customer A was one of them.

---

## Authentication and Tenancy Tables

### tenants

Every customer is a tenant. The tenant_id column appears on nearly every other table, enforcing data isolation.

### users

User accounts with email, hashed password, role (admin/analyst/viewer), and tenant_id. Passwords are stored using bcrypt hashing.

### api_keys

For programmatic access. API keys are tied to a tenant and have a role, just like users.

### sessions

Active login sessions with JWT token references and expiry times.

Row-Level Security (RLS) is enabled on 10 tenant-scoped tables, meaning the database itself enforces that Customer A cannot see Customer B's data, regardless of what the application code does. This is defense-in-depth.

---

## Template and Skill Tables

### agent_skills

Stores investigation templates (skill templates) that Zovark uses to process alerts quickly.

| Column | What it stores |
|--------|---------------|
| skill_slug | Unique name like "brute-force-investigation" or "auto-kerberoasting-research" |
| code_template | The investigation template code |
| investigation_plan | JSON plan for v3 tool-calling execution |
| task_types | Which alert types this skill handles (array) |
| auto_promoted | Whether this was automatically promoted from a successful investigation |
| promotion_status | pending, approved, rejected |

There are currently 25 active skills: 12 hand-written by analysts, 2 promoted automatically by the flywheel system, 10 generated by the AutoResearch engine, and 1 promoted through the 2-person quorum approval process.

### template_promotion_approvals

When a new template is proposed for promotion (moving from experimental to production), two different analysts must approve it. This table tracks who approved what and when.

| Column | What it stores |
|--------|---------------|
| skill_id | Which template is being reviewed |
| analyst_id | Who is approving |
| analyst_verdict | true_positive, false_positive, suspicious, benign |
| approved_at | When they approved |

The same analyst cannot approve a template twice -- this is a security control to prevent a single person from pushing a bad template into production.

---

## Intelligence Tables

### institutional_knowledge

Analyst-provided baselines about what is "normal" in the customer's environment. This is how Zovark avoids false positives on legitimate but unusual-looking activity.

| Column | What it stores |
|--------|---------------|
| entity_value | The entity (e.g., "jsmith" or "10.0.0.50") |
| entity_type | user, ip, domain, etc. |
| description | What this entity is ("Night shift DBA") |
| expected_behavior | What is normal for it ("Large data transfers between 22:00-06:00") |
| hours_active | When this entity is typically active |
| analyst_notes | Free-form context from the human analyst |

This table has pgvector support for semantic search -- you can ask "find baselines similar to this user's behavior" and get relevant results even if the wording is different.

### detection_rules

Sigma-format detection rules for identifying specific attack patterns in log data.

### response_playbooks

SOAR (Security Orchestration, Automation, and Response) playbooks that define automated response actions when specific threats are confirmed.

---

## Configuration Tables

### system_configs

A key-value store for system-wide settings, scoped per tenant.

| Column | What it stores |
|--------|---------------|
| config_key | The setting name (e.g., "siem.pushback.enabled", "siem.pushback.type") |
| config_value | The setting value |
| is_secret | Whether this value should be masked in exports and logs |

Used for SIEM push-back configuration, license keys, and other runtime settings. Has a full audit trail via the system_config_audit companion table.

### governance_config

Controls the autonomy level per tenant and task type.

| Column | What it stores |
|--------|---------------|
| tenant_id | Which customer |
| task_type | Which alert type (or * for all) |
| autonomy_level | observe (all need human review), assist (only non-benign need review), autonomous (only edge cases need review) |
| consecutive_correct | How many correct verdicts in a row |
| upgrade_threshold | How many correct verdicts needed before auto-upgrading the autonomy level |

### llm_audit_log

Records every call made to the AI model -- the prompt sent, the response received, which model was used, and how long it took. Essential for debugging AI behavior and for compliance audits.

---

## Dedup and Performance Tables

### alert_fingerprints

SHA-256 hashes of incoming alerts used for deduplication. When the same alert comes in twice, the fingerprint match prevents a duplicate investigation.

These tables work alongside Redis-based dedup layers. The database fingerprints handle long-term dedup; Redis handles real-time dedup for burst protection.

---

## Table Count Summary

| Domain | Approximate count |
|--------|------------------|
| Core investigation | 4 tables |
| Entity graph | 4 tables (entities, entity_edges, entity_observations, cross_tenant_entities) |
| Auth and tenancy | 4+ tables |
| Templates and skills | 3 tables |
| Intelligence | 3 tables |
| Configuration | 4 tables (system_configs, system_config_audit, governance_config, llm_audit_log) |
| Compliance | 2 tables (cipher_audit_events, cipher_audit_summary) |
| Detection and response | 2 tables |
| Dedup | 1 table |
| Monthly partitions | ~24 partition tables for audit_events and investigations |
| Indexes, views, functions | 30+ supporting objects |
| **Total** | **86+ tables and views** |

All critical tables have indexes for common query patterns, and the most frequently queried tables (agent_tasks, entities, audit_events) have composite indexes that match the exact queries the API and dashboard run.
