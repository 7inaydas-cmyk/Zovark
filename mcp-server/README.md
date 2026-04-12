# Zovark MCP Server

MCP (Model Context Protocol) server that lets any MCP-compatible client operate the Zovark SOC automation platform through natural language.

## Prerequisites

- Node.js >= 18
- Zovark stack running (`docker compose up -d`)
- Postgres accessible on localhost:5432
- API accessible on localhost:8090

## Setup

```bash
cd mcp-server
npm install
npm run build
```

## Registration

### Claude Code

```bash
claude mcp add zovark -- node /path/to/zovark/mcp-server/dist/index.js
```

Or with environment variables:

```bash
claude mcp add zovark -e ZOVARK_DB_URL=postgresql://zovark:hydra_dev_2026@localhost:5432/zovark -e ZOVARK_API_URL=http://localhost:8090 -e ZOVARK_PROJECT_DIR=/path/to/zovark -- node /path/to/zovark/mcp-server/dist/index.js
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "zovark": {
      "command": "node",
      "args": ["/path/to/zovark/mcp-server/dist/index.js"],
      "env": {
        "ZOVARK_DB_URL": "postgresql://zovark:hydra_dev_2026@localhost:5432/zovark",
        "ZOVARK_API_URL": "http://localhost:8090",
        "ZOVARK_PROJECT_DIR": "/path/to/zovark"
      }
    }
  }
}
```

### Cursor

Add to MCP settings with the same command and args as above.

## Tools (7)

| Tool | Description |
|------|-------------|
| `zovark_submit_alert` | Submit a security alert for automated investigation |
| `zovark_get_report` | Fetch investigation report by task_id, investigation_id, or latest |
| `zovark_create_tenant` | Onboard a new customer tenant with admin user |
| `zovark_query` | Read-only SQL access to Zovark's database (SELECT only) |
| `zovark_health` | Check health of all Zovark services |
| `zovark_logs` | Tail and filter Docker Compose service logs |
| `zovark_trigger_workflow` | Start a Temporal workflow (detection, self_healing, etc.) |

## Resources (6)

| URI | Description |
|-----|-------------|
| `zovark://investigations/recent` | Last 10 investigations |
| `zovark://entities/top-threats` | Top 20 entities by threat score |
| `zovark://detection/rules` | Active Sigma detection rules |
| `zovark://playbooks/active` | Active SOAR playbooks |
| `zovark://health/summary` | System health overview |
| `zovark://metrics/llm` | LLM call statistics |

## Prompts (6)

| Prompt | Description |
|--------|-------------|
| `zovark-investigate-brute-force` | Brute force attack investigation template |
| `zovark-investigate-ransomware` | Ransomware incident investigation |
| `zovark-investigate-c2` | C2 beacon investigation |
| `zovark-daily-health-check` | Comprehensive daily health check |
| `zovark-onboard-customer` | Customer onboarding workflow |
| `zovark-generate-demo` | Run 3 demo investigations |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZOVARK_DB_URL` | `postgresql://zovark:hydra_dev_2026@localhost:5432/zovark` | Postgres connection string |
| `ZOVARK_API_URL` | `http://localhost:8090` | Go API base URL |
| `ZOVARK_PROJECT_DIR` | `/path/to/zovark` | Project root for docker compose |

## Self-Test

```bash
node dist/index.js --test
```

## Security Notes

- `zovark_query` rejects all write operations (INSERT, UPDATE, DELETE, DROP, etc.)
- All DB queries have a 10-second statement timeout
- JWT tokens are cached for 55 minutes to avoid re-authentication
- Docker compose commands require the host Docker daemon
