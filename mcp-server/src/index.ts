#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { query, testConnection, closePool } from "./db.js";
import { apiPost, apiGet, apiHealthCheck, getJwt, API_URL } from "./api.js";
import { dockerComposeExec, dockerComposeLogs } from "./exec.js";

// ── Self-test mode ──────────────────────────────────────────────
if (process.argv.includes("--test")) {
  console.log("zovark-mcp server v1.0.0 — self-test");
  const dbOk = await testConnection();
  console.log(`  postgres: ${dbOk ? "ok" : "FAIL"}`);
  const apiOk = await apiHealthCheck();
  console.log(`  api:      ${apiOk ? "ok" : "FAIL"}`);
  console.log("  tools:    7 registered");
  console.log("  resources: 7 registered");
  console.log("  prompts:  6 registered");
  await closePool();
  process.exit(dbOk ? 0 : 1);
}

// ── Server setup ────────────────────────────────────────────────
const server = new McpServer(
  { name: "zovark-mcp", version: "1.0.0" },
  { capabilities: { tools: {}, resources: {}, prompts: {} } }
);

// ═══════════════════════════════════════════════════════════════
//  TOOL 1: zovark_submit_alert
// ═══════════════════════════════════════════════════════════════
server.tool(
  "zovark_submit_alert",
  "Submit a security alert to Zovark for automated investigation. Returns task_id for tracking.",
  {
    alert_type: z
      .enum([
        "brute_force",
        "ransomware",
        "c2_beacon",
        "phishing",
        "log_analysis",
        "ioc_scan",
        "code_audit",
        "incident_response",
        "threat_hunt",
      ])
      .describe("Type of security alert"),
    prompt: z
      .string()
      .describe("Alert description, raw log data, or investigation prompt"),
    tenant_slug: z.string().default("zovark-dev").describe("Tenant slug"),
  },
  async ({ alert_type, prompt, tenant_slug }) => {
    try {
      // Map snake_case to API task_type format
      const typeMap: Record<string, string> = {
        brute_force: "Log Analysis",
        ransomware: "Incident Response",
        c2_beacon: "Threat Hunt",
        phishing: "Log Analysis",
        log_analysis: "Log Analysis",
        ioc_scan: "IOC Scan",
        code_audit: "Code Audit",
        incident_response: "Incident Response",
        threat_hunt: "Threat Hunt",
      };

      const result = (await apiPost(
        "/api/v1/tasks",
        {
          task_type: typeMap[alert_type] || "Log Analysis",
          input: { prompt },
        },
        tenant_slug
      )) as { id: string; status: string };

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                task_id: result.id,
                status: result.status || "pending",
                message: `Investigation submitted. Track with task_id: ${result.id}`,
                alert_type,
              },
              null,
              2
            ),
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error submitting alert: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ═══════════════════════════════════════════════════════════════
//  TOOL 2: zovark_get_report
// ═══════════════════════════════════════════════════════════════
server.tool(
  "zovark_get_report",
  "Fetch an investigation report from Zovark. Can look up by task_id, investigation_id, or get the latest.",
  {
    task_id: z.string().optional().describe("Task UUID"),
    investigation_id: z.string().optional().describe("Investigation UUID"),
    latest: z.boolean().default(false).describe("Get most recent investigation"),
  },
  async ({ task_id, investigation_id, latest }) => {
    try {
      let sql: string;
      let params: unknown[];

      if (task_id) {
        sql = `
          SELECT i.id::text, i.verdict, i.risk_score, i.attack_techniques,
                 i.summary, i.confidence, i.source,
                 ir.executive_summary, ir.technical_timeline, ir.remediation_steps,
                 ir.full_report,
                 (SELECT count(*) FROM entity_observations eo WHERE eo.investigation_id = i.id) as entity_count
          FROM investigations i
          LEFT JOIN investigation_reports ir ON ir.investigation_id = i.id
          WHERE i.task_id = $1
          ORDER BY i.created_at DESC LIMIT 1`;
        params = [task_id];
      } else if (investigation_id) {
        sql = `
          SELECT i.id::text, i.verdict, i.risk_score, i.attack_techniques,
                 i.summary, i.confidence, i.source,
                 ir.executive_summary, ir.technical_timeline, ir.remediation_steps,
                 ir.full_report,
                 (SELECT count(*) FROM entity_observations eo WHERE eo.investigation_id = i.id) as entity_count
          FROM investigations i
          LEFT JOIN investigation_reports ir ON ir.investigation_id = i.id
          WHERE i.id = $1
          LIMIT 1`;
        params = [investigation_id];
      } else if (latest) {
        sql = `
          SELECT i.id::text, i.verdict, i.risk_score, i.attack_techniques,
                 i.summary, i.confidence, i.source,
                 ir.executive_summary, ir.technical_timeline, ir.remediation_steps,
                 ir.full_report,
                 (SELECT count(*) FROM entity_observations eo WHERE eo.investigation_id = i.id) as entity_count
          FROM investigations i
          LEFT JOIN investigation_reports ir ON ir.investigation_id = i.id
          ORDER BY i.created_at DESC LIMIT 1`;
        params = [];
      } else {
        return {
          content: [
            {
              type: "text" as const,
              text: "Provide task_id, investigation_id, or set latest=true",
            },
          ],
          isError: true,
        };
      }

      const result = await query(sql, params);
      if (result.rows.length === 0) {
        return {
          content: [
            { type: "text" as const, text: "No investigation found." },
          ],
        };
      }

      const row = result.rows[0];
      const report = {
        investigation_id: row.id,
        verdict: row.verdict,
        risk_score: row.risk_score,
        confidence: row.confidence,
        techniques: row.attack_techniques || [],
        entities_found: parseInt(row.entity_count) || 0,
        summary: row.summary,
        executive_summary: row.executive_summary,
        report_markdown:
          row.full_report ||
          [row.executive_summary, row.technical_timeline, row.remediation_steps]
            .filter(Boolean)
            .join("\n\n---\n\n") ||
          row.summary ||
          "No report generated yet.",
      };

      return {
        content: [
          { type: "text" as const, text: JSON.stringify(report, null, 2) },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ═══════════════════════════════════════════════════════════════
//  TOOL 3: zovark_create_tenant
// ═══════════════════════════════════════════════════════════════
server.tool(
  "zovark_create_tenant",
  "Onboard a new customer: create tenant, admin user, and return JWT.",
  {
    name: z.string().describe("Tenant display name"),
    slug: z.string().describe("URL-safe slug (lowercase, no spaces)"),
    admin_email: z.string().describe("Admin email address"),
    admin_password: z.string().describe("Admin password (min 8 chars)"),
  },
  async ({ name, slug, admin_email, admin_password }) => {
    try {
      // 1. Create tenant via DB (API requires existing admin JWT)
      const tenantResult = await query(
        `INSERT INTO tenants (name, slug, tier) VALUES ($1, $2, 'professional')
         ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
         RETURNING id::text`,
        [name, slug]
      );
      const tenantId = tenantResult.rows[0].id;

      // 2. Register admin user via API
      let regOk = true;
      try {
        await fetch(`${API_URL}/api/v1/auth/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: admin_email,
            password: admin_password,
            display_name: `${name} Admin`,
            tenant_slug: slug,
            role: "admin",
          }),
        });
      } catch {
        regOk = false;
      }

      // 3. Login to get JWT
      let jwt = "";
      try {
        const loginResp = await fetch(`${API_URL}/api/v1/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: admin_email,
            password: admin_password,
          }),
        });
        if (loginResp.ok) {
          const data = (await loginResp.json()) as { token: string };
          jwt = data.token;
        }
      } catch {
        // JWT not available
      }

      // 4. Count seeded playbooks
      const pbResult = await query(
        "SELECT count(*) as cnt FROM playbooks WHERE tenant_id = $1",
        [tenantId]
      );

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                tenant_id: tenantId,
                slug,
                registered: regOk,
                jwt_token: jwt || "(login manually)",
                playbooks_seeded: parseInt(pbResult.rows[0].cnt) || 0,
              },
              null,
              2
            ),
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ═══════════════════════════════════════════════════════════════
//  TOOL 4: zovark_stats  (replaces removed zovark_query)
// FIX #7: zovark_query removed — it bypassed JWT auth, RLS tenant isolation,
// and audit logging by connecting directly to PostgreSQL. Replaced with
// zovark_stats which fetches pre-aggregated stats via the Go API.
// ═══════════════════════════════════════════════════════════════
server.tool(
  "zovark_stats",
  "Fetch pre-aggregated investigation statistics from the Zovark API. Use zovark_get_report for individual investigation details.",
  {
    period_hours: z.number().default(24).describe("Look-back window in hours (default 24)"),
  },
  async ({ period_hours }) => {
    try {
      const result = await apiGet(`/api/v1/stats?hours=${period_hours}`);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Stats error: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ═══════════════════════════════════════════════════════════════
//  TOOL 5: zovark_health
// ═══════════════════════════════════════════════════════════════
server.tool(
  "zovark_health",
  "Check health status of all Zovark services (API, worker, Postgres, Redis, LiteLLM, Temporal).",
  {},
  async () => {
    const checks: Record<string, string> = {};

    // API
    checks.api = (await apiHealthCheck()) ? "ok" : "down";

    // Postgres
    checks.postgres = (await testConnection()) ? "ok" : "down";

    // Worker — check via docker compose
    try {
      const { stdout } = await dockerComposeExec("worker", [
        "python",
        "-c",
        "print('ok')",
      ]);
      checks.worker = stdout.trim() === "ok" ? "ok" : "down";
    } catch {
      checks.worker = "down";
    }

    // Redis
    try {
      const { stdout } = await dockerComposeExec("redis", [
        "redis-cli",
        "ping",
      ]);
      checks.redis = stdout.trim() === "PONG" ? "ok" : "down";
    } catch {
      checks.redis = "down";
    }

    // LiteLLM
    try {
      const resp = await fetch("http://localhost:4000/health/liveliness", {
        signal: AbortSignal.timeout(5000),
      });
      checks.litellm = resp.ok ? "ok" : "down";
    } catch {
      checks.litellm = "down";
    }

    // Temporal
    try {
      const { stdout } = await dockerComposeExec(
        "worker",
        [
          "python",
          "-c",
          "import asyncio; from temporalio.client import Client; asyncio.run(Client.connect('temporal:7233')); print('ok')",
        ],
        10000
      );
      checks.temporal = stdout.trim().includes("ok") ? "ok" : "down";
    } catch {
      checks.temporal = "down";
    }

    const upCount = Object.values(checks).filter((v) => v === "ok").length;
    const total = Object.keys(checks).length;
    const summary =
      upCount === total
        ? `All ${total} services healthy`
        : `${upCount}/${total} services up — ${Object.entries(checks)
            .filter(([, v]) => v !== "ok")
            .map(([k]) => k)
            .join(", ")} down`;

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({ ...checks, summary }, null, 2),
        },
      ],
    };
  }
);

// ═══════════════════════════════════════════════════════════════
//  TOOL 6: zovark_logs
// ═══════════════════════════════════════════════════════════════
server.tool(
  "zovark_logs",
  "Tail and filter Docker Compose service logs from Zovark.",
  {
    service: z
      .enum(["worker", "api", "litellm", "temporal", "postgres", "redis", "all"])
      .describe("Service name"),
    lines: z.number().default(50).describe("Number of lines to tail"),
    filter: z.string().optional().describe("Case-insensitive grep pattern"),
  },
  async ({ service, lines, filter }) => {
    try {
      const output = await dockerComposeLogs(service, lines, filter);
      const lineCount = output.split("\n").filter(Boolean).length;
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ logs: output, line_count: lineCount }),
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ═══════════════════════════════════════════════════════════════
//  TOOL 7: zovark_trigger_workflow
// ═══════════════════════════════════════════════════════════════
//
// SECURITY — HUMAN-IN-THE-LOOP APPROVAL GATE
// ────────────────────────────────────────────
// All workflow executions require explicit human approval before they run.
//
// Flow:
//   1. This tool submits a pending approval request to the Zovark API
//      (POST /api/v1/mcp/approvals/pending is handled by the API, but
//       approval creation here calls the approval gate via the API).
//   2. The tool returns immediately with status="pending_approval" and
//      an approval_id that the human must act on.
//   3. A Zovark admin approves or denies via:
//        POST /api/v1/mcp/approvals/:token/decide
//   4. After approval, the caller (human or orchestrator) may re-invoke
//      this tool with the same parameters — the second call checks Redis
//      for an approved token and proceeds with execution.
//   5. If denied or expired, the tool returns an error; no workflow runs.
//
// The approval token (full URL-safe random string) is NEVER returned to
// the MCP caller. Only the short approval_id is surfaced. This prevents
// the AI client from self-approving its own requests.
server.tool(
  "zovark_trigger_workflow",
  "Start a Temporal workflow (detection, self_healing, cross_tenant, bootstrap, finetuning). " +
    "REQUIRES human approval — returns pending_approval status on first call. " +
    "A Zovark admin must approve via POST /api/v1/mcp/approvals/:token/decide before the workflow runs.",
  {
    workflow: z
      .enum([
        "detection",
        "self_healing",
        "cross_tenant",
        "bootstrap",
        "finetuning",
      ])
      .describe("Workflow type"),
    params: z
      .string()
      .default("{}")
      .describe("Workflow parameters as JSON string"),
    dry_run: z
      .boolean()
      .default(true)
      .describe("Dry run mode (default true for self_healing)"),
    approval_token: z
      .string()
      .optional()
      .describe(
        "Approval token from a prior pending_approval response. " +
          "Omit on first call — the tool will request approval and return immediately. " +
          "Supply on the follow-up call after a human has approved the request."
      ),
    tenant_slug: z
      .string()
      .default("zovark-dev")
      .describe("Tenant slug for the approval context"),
  },
  async ({ workflow, params: paramsStr, dry_run, approval_token, tenant_slug }) => {
    const workflowMap: Record<string, string> = {
      detection: "DetectionGenerationWorkflow",
      self_healing: "SelfHealingWorkflow",
      cross_tenant: "CrossTenantRefreshWorkflow",
      bootstrap: "BootstrapCorpusWorkflow",
      finetuning: "FineTuningPipelineWorkflow",
    };

    const wfType = workflowMap[workflow];
    if (!wfType) {
      return {
        content: [
          { type: "text" as const, text: `Unknown workflow: ${workflow}` },
        ],
        isError: true,
      };
    }

    let parsedParams: Record<string, unknown> = {};
    try {
      parsedParams = JSON.parse(paramsStr || "{}");
    } catch {
      // ignore parse errors, use empty params
    }

    // For self_healing, inject dry_run into params.
    const wfParams =
      workflow === "self_healing"
        ? { lookback_minutes: 60, dry_run, ...parsedParams }
        : { ...parsedParams };

    // ── APPROVAL GATE ────────────────────────────────────────────
    // Phase 1 (no token): create a pending approval and return immediately.
    // Phase 2 (token supplied): verify approval is in 'approved' state,
    //         then execute the workflow.
    if (!approval_token) {
      // Request approval via the Zovark API approval gate.
      try {
        const approvalResult = (await apiPost(
          "/api/v1/mcp/approvals/request",
          {
            workflow_id: wfType,
            workflow_args: wfParams,
            requested_by: "mcp:zovark_trigger_workflow",
            tenant_id: tenant_slug,
          },
          tenant_slug
        )) as {
          approval_id: string;
          status: string;
          expires_at: number;
          message: string;
        };

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  status: "pending_approval",
                  approval_id: approvalResult.approval_id,
                  workflow_type: wfType,
                  workflow_params: wfParams,
                  expires_at: approvalResult.expires_at,
                  message:
                    approvalResult.message ||
                    `Workflow '${wfType}' is pending human approval. ` +
                      `A Zovark admin must approve via the dashboard or ` +
                      `POST /api/v1/mcp/approvals/:token/decide before execution proceeds. ` +
                      `Re-invoke this tool with approval_token=<token> after approval.`,
                  next_step:
                    "Wait for a Zovark admin to approve the request, then re-invoke " +
                    "this tool supplying the approval_token returned to the admin.",
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err) {
        // Approval creation failed — block execution (fail-closed).
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  status: "blocked",
                  error: `Approval gate unavailable: ${err instanceof Error ? err.message : String(err)}`,
                  message:
                    "Workflow execution blocked. The approval gate must be available before any workflow can run.",
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        };
      }
    }

    // Phase 2 — approval_token was supplied. Verify it before executing.
    try {
      const checkResult = (await apiGet(
        `/api/v1/mcp/approvals/check/${encodeURIComponent(approval_token)}`,
        tenant_slug
      )) as { status: string; approval_id?: string; workflow_id?: string };

      if (checkResult.status !== "approved") {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  status: checkResult.status,
                  error: `Workflow execution blocked — approval status is '${checkResult.status}'. Only 'approved' tokens allow execution.`,
                  approval_id: checkResult.approval_id,
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        };
      }

      // Confirm the approved workflow matches what we are about to run.
      if (checkResult.workflow_id && checkResult.workflow_id !== wfType) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  status: "blocked",
                  error: `Token mismatch: approval was issued for '${checkResult.workflow_id}' but '${wfType}' was requested.`,
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        };
      }
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Approval check failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }

    // ── EXECUTE WORKFLOW ─────────────────────────────────────────
    const wfId = `mcp-${workflow}-${Date.now()}`;
    const paramsJson = JSON.stringify(wfParams).replace(/'/g, "\\'");

    const pyScript = `
import asyncio, json
from temporalio.client import Client
async def main():
    c = await Client.connect('temporal:7233')
    r = await c.execute_workflow('${wfType}', json.loads('${paramsJson}'), id='${wfId}', task_queue='zovark-tasks')
    print(json.dumps(r))
asyncio.run(main())
`.trim();

    try {
      const { stdout, stderr } = await dockerComposeExec(
        "worker",
        ["python", "-c", pyScript],
        120000
      );

      let result: unknown;
      try {
        result = JSON.parse(stdout.trim());
      } catch {
        result = stdout.trim() || stderr.trim();
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                workflow_id: wfId,
                workflow_type: wfType,
                status: "completed",
                result,
              },
              null,
              2
            ),
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Workflow error: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ═══════════════════════════════════════════════════════════════
//  RESOURCES — Read-only data endpoints
// ═══════════════════════════════════════════════════════════════

server.resource(
  "Recent Investigations",
  "zovark://investigations/recent",
  { description: "Last 10 investigations with verdicts and risk scores" },
  async () => {
    const result = await query(`
      SELECT i.id::text, i.verdict, i.risk_score, i.attack_techniques,
             i.summary, i.source, i.created_at::text
      FROM investigations i
      ORDER BY i.created_at DESC LIMIT 10
    `);
    return {
      contents: [
        {
          uri: "zovark://investigations/recent",
          mimeType: "application/json",
          text: JSON.stringify(result.rows, null, 2),
        },
      ],
    };
  }
);

server.resource(
  "Top Threat Entities",
  "zovark://entities/top-threats",
  { description: "Top 20 entities by threat score" },
  async () => {
    const result = await query(`
      SELECT id::text, entity_type, value, threat_score, observation_count,
             tenant_count, last_seen::text
      FROM entities
      WHERE threat_score > 0
      ORDER BY threat_score DESC, observation_count DESC
      LIMIT 20
    `);
    return {
      contents: [
        {
          uri: "zovark://entities/top-threats",
          mimeType: "application/json",
          text: JSON.stringify(result.rows, null, 2),
        },
      ],
    };
  }
);

server.resource(
  "Detection Rules",
  "zovark://detection/rules",
  { description: "All active Sigma detection rules" },
  async () => {
    const result = await query(`
      SELECT id::text, technique_id, rule_name, rule_version, status,
             tp_rate, fp_rate, investigations_matched, created_at::text
      FROM detection_rules
      WHERE status = 'active'
      ORDER BY created_at DESC
    `);
    return {
      contents: [
        {
          uri: "zovark://detection/rules",
          mimeType: "application/json",
          text: JSON.stringify(result.rows, null, 2),
        },
      ],
    };
  }
);

server.resource(
  "Active Playbooks",
  "zovark://playbooks/active",
  { description: "Active SOAR response playbooks" },
  async () => {
    const result = await query(`
      SELECT id::text, name, description, trigger_conditions, enabled,
             created_at::text
      FROM response_playbooks
      WHERE enabled = true
      ORDER BY name
    `);
    return {
      contents: [
        {
          uri: "zovark://playbooks/active",
          mimeType: "application/json",
          text: JSON.stringify(result.rows, null, 2),
        },
      ],
    };
  }
);

server.resource(
  "Health Summary",
  "zovark://health/summary",
  { description: "Current system health overview" },
  async () => {
    const stats = await query(`
      SELECT
        (SELECT count(*) FROM agent_tasks) as total_tasks,
        (SELECT count(*) FROM agent_tasks WHERE status = 'completed') as completed_tasks,
        (SELECT count(*) FROM agent_tasks WHERE status = 'failed') as failed_tasks,
        (SELECT count(*) FROM investigations) as total_investigations,
        (SELECT count(*) FROM entities) as total_entities,
        (SELECT count(*) FROM detection_rules WHERE status = 'active') as active_rules,
        (SELECT count(*) FROM self_healing_events) as healing_events
    `);
    return {
      contents: [
        {
          uri: "zovark://health/summary",
          mimeType: "application/json",
          text: JSON.stringify(stats.rows[0], null, 2),
        },
      ],
    };
  }
);

server.resource(
  "LLM Metrics",
  "zovark://metrics/llm",
  { description: "LLM call statistics — cost, latency, token usage" },
  async () => {
    const result = await query(`
      SELECT
        model_id,
        activity_name,
        count(*) as calls,
        round(avg(latency_ms)) as avg_latency_ms,
        sum(input_tokens) as total_input_tokens,
        sum(output_tokens) as total_output_tokens,
        round(sum(estimated_cost_usd)::numeric, 4) as total_cost_usd
      FROM llm_call_log
      GROUP BY model_id, activity_name
      ORDER BY calls DESC
    `);
    return {
      contents: [
        {
          uri: "zovark://metrics/llm",
          mimeType: "application/json",
          text: JSON.stringify(result.rows, null, 2),
        },
      ],
    };
  }
);

server.resource(
  "Feedback Accuracy",
  "zovark://feedback/accuracy",
  { description: "Investigation feedback accuracy — analyst verdicts and correction rates" },
  async () => {
    const result = await query(`
      SELECT
        COUNT(*) as total_feedback,
        SUM(CASE WHEN verdict_correct THEN 1 ELSE 0 END) as correct,
        SUM(CASE WHEN NOT verdict_correct THEN 1 ELSE 0 END) as incorrect,
        SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) as false_positives,
        SUM(CASE WHEN missed_threat THEN 1 ELSE 0 END) as missed_threats,
        COALESCE(ROUND(AVG(CASE WHEN verdict_correct THEN 1.0 ELSE 0.0 END), 3), 0) as accuracy_rate,
        COALESCE(ROUND(AVG(analyst_confidence), 3), 0) as avg_analyst_confidence
      FROM investigation_feedback
    `);
    return {
      contents: [
        {
          uri: "zovark://feedback/accuracy",
          mimeType: "application/json",
          text: JSON.stringify(result.rows[0] || {}, null, 2),
        },
      ],
    };
  }
);

// ═══════════════════════════════════════════════════════════════
//  PROMPTS — Pre-built investigation templates
// ═══════════════════════════════════════════════════════════════

server.prompt(
  "zovark-investigate-brute-force",
  "Investigate a brute force attack — submits alert and tracks results",
  {
    source_ip: z.string().describe("Attacker source IP"),
    target_account: z.string().describe("Target account/email"),
    attempt_count: z.string().default("100").describe("Number of attempts"),
  },
  ({ source_ip, target_account, attempt_count }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Investigate brute force attack: ${attempt_count} failed login attempts from ${source_ip} targeting ${target_account} in the last 30 minutes. Use zovark_submit_alert with alert_type="brute_force" and this description as the prompt. Then wait 30 seconds and use zovark_get_report with latest=true to get the results.`,
        },
      },
    ],
  })
);

server.prompt(
  "zovark-investigate-ransomware",
  "Investigate a ransomware incident",
  {
    hostname: z.string().describe("Affected hostname"),
    indicators: z.string().describe("File extensions, ransom note, IOCs"),
  },
  ({ hostname, indicators }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Investigate ransomware on host ${hostname}. Indicators: ${indicators}. Use zovark_submit_alert with alert_type="ransomware" and this description. Then check the report.`,
        },
      },
    ],
  })
);

server.prompt(
  "zovark-investigate-c2",
  "Investigate a C2 beacon / command-and-control communication",
  {
    beacon_ip: z.string().describe("Suspected C2 IP/domain"),
    internal_host: z.string().describe("Internal host communicating with C2"),
  },
  ({ beacon_ip, internal_host }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Investigate suspected C2 beacon: ${internal_host} is communicating with ${beacon_ip} on unusual ports. Use zovark_submit_alert with alert_type="c2_beacon". Then retrieve the report.`,
        },
      },
    ],
  })
);

server.prompt(
  "zovark-daily-health-check",
  "Run a comprehensive daily health check of the Zovark platform",
  () => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Perform a daily Zovark health check:
1. Run zovark_health to check all services
2. Run zovark_trigger_workflow with workflow="self_healing" and dry_run=true to scan for failures
3. Use zovark_query to get today's investigation stats: SELECT status, count(*) FROM agent_tasks WHERE created_at > NOW() - INTERVAL '24 hours' GROUP BY status
4. Use zovark_query to check for high-risk entities: SELECT entity_type, value, threat_score FROM entities WHERE threat_score > 70 ORDER BY threat_score DESC LIMIT 10
5. Summarize the platform state and any issues found.`,
        },
      },
    ],
  })
);

server.prompt(
  "zovark-onboard-customer",
  "Walk through onboarding a new customer tenant",
  {
    company_name: z.string().describe("Company name"),
    admin_email: z.string().describe("Admin email"),
  },
  ({ company_name, admin_email }) => {
    const slug = company_name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
    return {
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `Onboard new customer "${company_name}":
1. Use zovark_create_tenant with name="${company_name}", slug="${slug}", admin_email="${admin_email}", admin_password="ChangeMeN0w!"
2. Verify with zovark_query: SELECT id, name, slug, tier FROM tenants WHERE slug='${slug}'
3. Report the tenant_id and JWT token for API access.`,
          },
        },
      ],
    };
  }
);

server.prompt(
  "zovark-generate-demo",
  "Run 3 different investigation types to demo Zovark capabilities",
  () => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Generate a Zovark demo by running 3 investigations:
1. zovark_submit_alert: alert_type="brute_force", prompt="500 failed SSH login attempts from 203.0.113.50 targeting root@prod-server-01 over 10 minutes"
2. zovark_submit_alert: alert_type="c2_beacon", prompt="Internal host 10.0.1.42 making periodic HTTPS connections to 185.220.100.252 every 60 seconds, user-agent: Mozilla/4.0"
3. zovark_submit_alert: alert_type="ransomware", prompt="Files on FILESERVER01 being renamed with .locked extension, ransom note README_RESTORE.txt found in multiple directories"
Wait 60 seconds, then get all 3 reports with zovark_get_report latest=true for each.
Compile a summary of all findings, risk scores, and recommendations.`,
        },
      },
    ],
  })
);

// ═══════════════════════════════════════════════════════════════
//  START SERVER
// ═══════════════════════════════════════════════════════════════
const transport = new StdioServerTransport();
await server.connect(transport);

// Cleanup on exit
process.on("SIGINT", async () => {
  await closePool();
  process.exit(0);
});
process.on("SIGTERM", async () => {
  await closePool();
  process.exit(0);
});
