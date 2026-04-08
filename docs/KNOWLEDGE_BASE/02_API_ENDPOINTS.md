# API Endpoints: What You Can Ask Zovark To Do

The Zovark API runs on port 8090 and has 162 routes. Every request (except health checks) requires a JWT token obtained by logging in. Think of the API as a hotel concierge desk -- you show your room key (JWT), ask for something, and get a structured response.

All endpoints live under `/api/v1/` unless noted otherwise.

---

## Alert Intake -- "Here's something to investigate"

These are the front doors where alerts enter the system. SIEM systems, scripts, and the Alert Forge UI all use these.

**POST /tasks** -- Submit a single alert for investigation. You send a JSON body with the alert type (e.g., "brute_force"), severity, and the raw SIEM event data. Zovark returns a task ID immediately, then investigates asynchronously. The alert passes through the 3-layer burst protection (dedup, batch buffer, backpressure) before entering the pipeline.

**POST /tasks/bulk** -- Submit multiple alerts in one request. Same as above but batched. Useful when replaying historical alerts or running benchmarks. Each alert gets its own task ID.

**POST /ingest/splunk** -- Splunk HEC-compatible endpoint. Splunk forwards alerts here using its standard HTTP Event Collector format. Zovark normalizes the Splunk-specific field names into its common schema automatically.

**POST /ingest/elastic** -- Elastic SIEM webhook endpoint. Elastic Security sends alerts here using its webhook action format. Same normalization applies.

*Who calls these:* SIEM systems (automated), Alert Forge UI (manual testing), benchmark scripts.
*Auth required:* Yes (JWT or API key).
*What you get back:* Task ID and status. The actual investigation result comes later via polling or SSE.

---

## Investigation Results -- "What did you find?"

These endpoints let you check on investigations and stream live updates.

**GET /tasks** -- List all investigations with filters. Returns task ID, type, status, verdict, risk score, and which investigation path was taken (Path A or Path C). Supports pagination. This is what the Dashboard's main table calls every few seconds.

**GET /tasks/:id** -- Get the full details of a single investigation. Returns everything: the raw alert, every tool that ran, all extracted IOCs with evidence references, the risk score, verdict, MITRE ATT&CK mappings, the plain-English summary, and timing data. This is the investigation detail page.

**GET /tasks/stream** -- Server-Sent Events (SSE) stream. Opens a persistent connection and pushes real-time updates as investigations complete. The Dashboard subscribes to this so verdicts appear instantly without polling. Also streams intermediate events: "tool started," "IOC discovered," "verdict ready."

**GET /tasks/:id/audit/steps/timeline** -- Step-by-step audit trail for a single investigation. Shows exactly what happened at each pipeline stage, what decisions were made, and how long each step took. Essential for compliance audits -- proves that Zovark followed its process.

*Who calls these:* Dashboard (automated polling + SSE), analysts (manual lookup), compliance auditors, SIEM push-back engine.
*Auth required:* Yes.
*What you get back:* JSON with investigation data, filterable and paginated.

---

## Entity Graph -- "Show me the connections"

The entity graph tracks every IP address, domain, username, hash, and other indicator Zovark has ever seen, plus the relationships between them.

**GET /entities** -- List all known entities with filters by type (IP, domain, hash, etc.) and time range. Returns entity ID, type, value, first/last seen, and how many investigations reference it.

**GET /entities/:id** -- Full detail on a single entity: every investigation it appeared in, every relationship to other entities, risk history over time.

**GET /entities/:id/graph** -- The relationship graph for one entity. Returns nodes and edges that the Dashboard renders as a visual network diagram. "This IP connected to these 3 domains, which were also contacted by these 2 usernames." This is the analyst's tool for tracing attacker infrastructure.

**GET /entities/search** -- Free-text search across all entities. Type in an IP address or domain and find every investigation that ever mentioned it.

**GET /entities/stats** -- Aggregate statistics: total entities by type, most-connected entities, entities seen across multiple tenants (cross-tenant correlation).

*Who calls these:* Dashboard entity explorer, analyst investigations, cross-tenant correlation engine.
*Auth required:* Yes.

---

## Dashboard Data -- "Give me the big picture"

These power the analytics panels and status displays.

**GET /pipeline/status** -- Current pipeline health: how many investigations are running, queued, completed in the last hour, average latency per stage, circuit breaker state (green/yellow/red). The Pipeline Monitor widget calls this.

**POST /analytics/summary** -- Aggregated analytics for a time range. Verdict distribution (how many true positives vs. benign vs. suspicious), risk score distribution, attack type breakdown, investigations per hour over time. Powers the Analytics Panel charts.

**GET /dashboard-stats** -- Quick summary numbers for the dashboard header: total investigations today, detection rate, false positive rate, average investigation time.

**GET /stats** -- Historical statistics for trend analysis. Includes per-type accuracy, per-path latency, template coverage percentage.

*Who calls these:* Dashboard and Web-Admin panels (automated, every 30-60 seconds).
*Auth required:* Yes.

---

## Authentication -- "Prove who you are"

**POST /auth/login** -- Email + password login. Returns a JWT token valid for 30 minutes. Two built-in accounts: admin@test.local and analyst2@test.local (both password: TestPass2026).

**POST /auth/register** -- Create a new user account. Admin-only.

**POST /auth/refresh** -- Exchange a still-valid JWT for a fresh one. Extends the session without re-entering credentials.

**POST /auth/logout** -- Invalidate the current token.

**GET /auth/sso/login** and **GET /auth/callback** -- OIDC/SSO flow for Azure AD and Okta. Redirects the user to their identity provider, then handles the callback with the authorization code.

**POST /auth/totp/setup** and **POST /auth/totp/verify** -- Two-factor authentication. Setup returns a QR code for Google Authenticator or similar. Verify checks the 6-digit code.

**POST /auth/breakglass/login** -- Emergency login using the system tenant. For situations where the normal auth system is broken and an operator needs to get in to fix things.

*Who calls these:* Dashboard login page, SSO identity providers, mobile authenticator apps.
*Auth required:* No (these *create* auth tokens).

---

## Admin and Diagnostics -- "Is everything healthy?"

**POST /admin/diagnose** -- Run the 8-point health diagnostic: services, throughput, dedup, model/GPU, database, queue, containers, disk. Returns a structured report with pass/fail for each check and suggested operator actions.

**POST /admin/alerts** -- Pipeline statistics with verdict bar chart, top alert types, low-confidence alerts, latency by investigation path.

**POST /admin/model-check** -- Risk score calibration report. Shows per-attack-type risk averages, attack/benign separation gap, MITRE coverage, and flags any types where the model is under- or over-scoring.

**POST /admin/dedup-health** -- Deduplication efficiency report: how many alerts were deduplicated vs. investigated, decision distribution, top deduplicated rules, TTL status.

**GET /admin/diagnostics/export** -- Downloads a `.zvk` zip file containing audit events, LLM logs, healer status, and system info. All secrets are automatically scrubbed by 5 regex patterns before packaging. This is the "flight data recorder" for support cases.

**GET /system-stats** and **GET /system/health** -- Quick system status for monitoring dashboards and health check scripts.

**Config and Forge endpoints** -- System configuration management and the Alert Forge (test alert submission tool in the Web-Admin panel).

*Who calls these:* Web-Admin panel, zvadmin CLI tool, operators during troubleshooting.
*Auth required:* Yes (admin role).

---

## Copilot -- "Help me understand this"

Four AI-powered endpoints that let analysts ask questions about investigations. Each one uses the local AI model with a dedicated semaphore (only 1 copilot call at a time, carved from the AI budget).

**POST /copilot/explain** -- "Explain this investigation to me." Send a task ID, get a plain-English explanation of what happened, what was found, and why the verdict was assigned. If the AI is unavailable, falls back to a deterministic template.

**POST /copilot/suggest** -- "What should I do next?" Given an investigation, suggests follow-up actions: additional queries to run, indicators to block, teams to notify.

**POST /copilot/correlate** -- "Is this related to anything else?" Finds similar past investigations and highlights connections -- same attacker IP, same technique, same time window.

**POST /copilot/brief** -- "Give me the executive summary." Generates a brief suitable for a shift handover or management report: key incidents, trends, and recommended actions.

*Who calls these:* Dashboard investigation detail page (Explain/Suggest buttons), Analytics panel (Shift Brief).
*Auth required:* Yes.

---

## Remediation -- "What should we do about it?"

**POST /remediation/suggest** -- Given an investigation, returns recommended remediation actions from a library of 22 attack-type-specific rules. For a brute force: "Block source IP at firewall, enforce account lockout policy, reset affected passwords."

**POST /remediation/verify** -- Check whether a proposed remediation action is safe and appropriate. Acts as a sanity check before execution.

**GET /remediation/actions** -- List all remediation actions that have been suggested or executed, with status tracking.

**PATCH /remediation/actions/:id** -- Update a remediation action's status (e.g., mark as executed, mark as rejected). Protected by a circuit breaker (max 3 remediations per attack type per 24 hours) and rate limiter (max 10 per hour) with a global kill switch.

*Who calls these:* Dashboard remediation panel, automated playbooks.
*Auth required:* Yes.

---

## License -- "Are we authorized to run?"

**GET /license/status** -- Current license state: valid/expired/grace period, expiry date, licensed features, tenant count.

**GET /license/verify** -- Re-verify the license signature right now (normally cached for 5 minutes). Uses Ed25519 cryptographic verification. If verification fails for any reason, the system fails closed -- it does not silently continue without a valid license.

**POST /license/install** -- Install a new license. The license is a signed JSON payload containing the customer name, expiry date, feature flags, and a 30-day grace period. The payload is verified against the public key stored in the database.

*Who calls these:* Web-Admin license page, deployment scripts.
*Auth required:* Yes (admin role).

---

## Governance -- "How much autonomy does Zovark have?"

**GET /governance/config** -- Current autonomy settings per tenant and per alert type. Shows whether each category is in observe, assist, or autonomous mode.

**PUT /governance/config** -- Update autonomy settings. For example, switch brute_force investigations from "observe" (human reviews every one) to "assist" (only escalated ones need review). Changes take effect on the next investigation.

*Who calls these:* Web-Admin governance panel, deployment configuration scripts.
*Auth required:* Yes (admin role).

---

## Template Management -- "How does Zovark learn?"

**GET /auto-templates** -- List all investigation templates, including the 12 hand-written ones, 10 AutoResearch-generated ones, and any promoted from Path C investigations.

**DELETE /auto-templates/:slug** -- Remove a template. Used when a template is found to be inaccurate or outdated.

**GET /promotion-queue** -- Templates waiting for analyst approval. When a Path C investigation (AI-generated) produces a high-quality result, it can be promoted to a reusable template -- but only after 2-person quorum approval.

**POST /analyst-feedback** -- Submit feedback on a template in the promotion queue. Analysts review the template's logic and vote to approve or reject. The same analyst cannot approve twice (quorum requires two different people).

**POST /promotion-approve** -- Final approval to promote a template from the queue into production. After this, future alerts of the same type will use the fast Path A instead of the slow Path C.

*Who calls these:* Dashboard promotion queue page, analysts reviewing templates.
*Auth required:* Yes (analyst or admin role).

---

## Feedback and Analytics -- "How accurate are we?"

**GET /feedback/stats** -- Accuracy statistics: how often analysts agree with Zovark's verdicts, broken down by attack type and investigation path.

**GET /analytics/feedback/*** -- Detailed feedback analytics including per-analyst agreement rates, most-contested verdict types, and accuracy trends over time. This data feeds the continuous improvement loop -- if analysts consistently override verdicts for a specific attack type, it signals a calibration problem.

*Who calls these:* Analytics Panel, management reports, model calibration scripts.
*Auth required:* Yes.

---

## Quick Reference: Common Workflows

**"I want to test if Zovark detects a phishing attack"**
1. POST /auth/login (get token)
2. POST /tasks (submit phishing alert)
3. GET /tasks/stream (wait for verdict event)
4. GET /tasks/:id (read full investigation)

**"I want to see what Zovark found about a suspicious IP"**
1. GET /entities/search?q=185.220.101.45
2. GET /entities/:id/graph (see all connections)

**"I want to check if the system is healthy"**
1. GET /ready (quick: 200 = healthy, 503 = problem)
2. POST /admin/diagnose (detailed: 8-point check)

**"I want to give Zovark more autonomy for brute force alerts"**
1. GET /governance/config (see current settings)
2. PUT /governance/config (change brute_force to "assist")
