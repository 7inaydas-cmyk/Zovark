"""
Copilot intelligence module — analyst-facing investigation assistant.
Uses CODE model with deprioritized semaphore (Invariant #11).

Four operations:
- explain(investigation_id) — natural language explanation of verdict
- suggest(investigation_id) — next steps based on findings
- correlate(investigation_id) — find related investigations (no LLM)
- brief(hours) — shift handoff summary

Copilot semaphore: asyncio.Semaphore(1), carved from CODE budget.
Pipeline calls always get priority. Copilot max 1 concurrent LLM call.
"""
import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Copilot-specific semaphore — max 1 concurrent LLM call
_copilot_semaphore = asyncio.Semaphore(1)

_DB_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark",
)


def _get_conn():
    import psycopg2
    return psycopg2.connect(_DB_URL)


def _query(sql: str, params: tuple = ()) -> list[dict]:
    import psycopg2.extras
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def _query_one(sql: str, params: tuple = ()) -> Optional[dict]:
    rows = _query(sql, params)
    return rows[0] if rows else None


async def _copilot_llm_call(prompt: str, system: str, timeout: float = 15.0) -> Optional[str]:
    """Make an LLM call with copilot priority and dedicated semaphore."""
    try:
        from llm_client import llm_request
        from settings import settings

        model = settings.model_code

        async with asyncio.timeout(timeout):
            async with _copilot_semaphore:
                result = await llm_request(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    role="summary",  # Uses CODE semaphore with summary sampling
                    stage="copilot",
                    max_tokens=1024,
                )
                return result["choices"][0]["message"]["content"]
    except asyncio.TimeoutError:
        logger.warning("Copilot LLM call timed out after %.1fs", timeout)
        return None
    except Exception as e:
        logger.warning("Copilot LLM call failed: %s", e)
        return None


# ── explain ─────────────────────────────────────────────────

def _get_investigation(investigation_id: str, tenant_id: str) -> Optional[dict]:
    """Fetch investigation data from agent_tasks + investigations."""
    return _query_one("""
        SELECT t.id, t.task_type, t.input, t.output, t.status,
               t.created_at, t.completed_at,
               COALESCE(t.output->>'verdict', 'unknown') as verdict,
               COALESCE((t.output->>'risk_score')::int, 0) as risk_score,
               t.output->'iocs' as iocs,
               t.output->'findings' as findings,
               t.output->'mitre_attack' as mitre_attack,
               t.input->'siem_event'->>'raw_log' as raw_log,
               t.input->'siem_event'->>'source_ip' as source_ip,
               t.input->'siem_event'->>'username' as username
        FROM agent_tasks t
        WHERE t.id = %s AND t.tenant_id = %s
    """, (investigation_id, tenant_id))


def _explain_fallback(inv: dict) -> str:
    """Template-based explanation when LLM is unavailable."""
    tt = inv["task_type"].replace("_", " ")
    verdict = inv["verdict"]
    risk = inv["risk_score"]
    findings = inv.get("findings") or []
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            findings = []

    finding_text = "; ".join(f[:80] for f in findings[:3]) if findings else "No specific findings recorded"

    return (
        f"This {tt} investigation was classified as {verdict} with a risk score of {risk}/100. "
        f"Key findings: {finding_text}. "
        f"{'This warrants immediate attention.' if risk >= 70 else 'This is a low-priority finding.' if risk < 40 else 'This should be reviewed by an analyst.'}"
    )


async def explain(investigation_id: str, tenant_id: str) -> dict:
    """Generate a natural language explanation of an investigation verdict."""
    start = time.time()
    inv = _get_investigation(investigation_id, tenant_id)
    if not inv:
        return {"error": "Investigation not found"}

    system = "You are a SOC analyst explaining an investigation verdict to a colleague. Be concise and technical."
    prompt = (
        f"Explain this investigation in 3-5 sentences:\n"
        f"Type: {inv['task_type']}\n"
        f"Verdict: {inv['verdict']} (risk: {inv['risk_score']}/100)\n"
        f"Findings: {json.dumps(inv.get('findings') or [], default=str)[:500]}\n"
        f"IOCs: {json.dumps(inv.get('iocs') or [], default=str)[:300]}\n"
        f"MITRE: {json.dumps(inv.get('mitre_attack') or [], default=str)[:200]}\n"
        f"Raw log (first 500 chars): {(inv.get('raw_log') or '')[:500]}\n\n"
        f"Explain: what was detected, why it was scored as {inv['verdict']} with risk {inv['risk_score']}, "
        f"what the key indicators were, and what MITRE techniques apply."
    )

    explanation = await _copilot_llm_call(prompt, system)
    if explanation is None:
        explanation = _explain_fallback(inv)

    return {
        "explanation": explanation,
        "investigation_id": investigation_id,
        "task_type": inv["task_type"],
        "verdict": inv["verdict"],
        "risk_score": inv["risk_score"],
        "latency_ms": round((time.time() - start) * 1000),
    }


# ── suggest ─────────────────────────────────────────────────

async def suggest(investigation_id: str, tenant_id: str) -> dict:
    """Get remediation suggestions with optional LLM narrative."""
    start = time.time()
    inv = _get_investigation(investigation_id, tenant_id)
    if not inv:
        return {"error": "Investigation not found"}

    # Phase 1: deterministic suggestions from remediation engine
    from intelligence.remediation import suggest_actions
    suggestions = suggest_actions(
        attack_type=inv["task_type"],
        risk_score=inv["risk_score"],
        verdict=inv["verdict"],
        iocs=inv.get("iocs") if isinstance(inv.get("iocs"), list) else None,
    )

    # Phase 2: optional LLM narrative
    narrative = None
    if suggestions and inv["verdict"] != "benign":
        system = "You are a SOC analyst recommending next steps. Be concise and actionable."
        prompt = (
            f"Given a {inv['task_type']} investigation with verdict={inv['verdict']} "
            f"and risk={inv['risk_score']}, these remediation actions are recommended:\n"
            + "\n".join(f"- [{s['action_type']}] {s['description']} (priority: {s['priority']})" for s in suggestions[:5])
            + "\n\nWrite a 2-3 sentence narrative explaining the priority order and any dependencies between actions."
        )
        narrative = await _copilot_llm_call(prompt, system)

    return {
        "suggestions": suggestions,
        "narrative": narrative,
        "investigation_id": investigation_id,
        "task_type": inv["task_type"],
        "verdict": inv["verdict"],
        "latency_ms": round((time.time() - start) * 1000),
    }


# ── correlate ───────────────────────────────────────────────

def correlate(investigation_id: str, tenant_id: str) -> dict:
    """Find related investigations by source_ip, username, task_type. No LLM."""
    start = time.time()
    inv = _get_investigation(investigation_id, tenant_id)
    if not inv:
        return {"error": "Investigation not found"}

    source_ip = inv.get("source_ip") or ""
    username = inv.get("username") or ""
    task_type = inv["task_type"]

    # Build dynamic query based on available search criteria
    conditions = []
    params: list = [tenant_id, investigation_id]
    idx = 3

    if source_ip:
        conditions.append(f"t.input->'siem_event'->>'source_ip' = ${idx}")
        params.append(source_ip)
        idx += 1
    if username:
        conditions.append(f"t.input->'siem_event'->>'username' = ${idx}")
        params.append(username)
        idx += 1
    conditions.append(f"t.task_type = ${idx}")
    params.append(task_type)

    where_clause = " OR ".join(conditions)

    related = _query(f"""
        SELECT t.id::text, t.task_type,
               COALESCE(t.output->>'verdict', 'pending') as verdict,
               COALESCE((t.output->>'risk_score')::int, 0) as risk_score,
               t.created_at::text as created_at,
               t.input->'siem_event'->>'source_ip' as source_ip
        FROM agent_tasks t
        WHERE t.tenant_id = %s
          AND t.id != %s
          AND ({where_clause})
          AND t.created_at > NOW() - INTERVAL '7 days'
        ORDER BY t.created_at DESC
        LIMIT 20
    """.replace("$3", "%s").replace("$4", "%s").replace("$5", "%s"),
        tuple(params))

    # Query attack paths involving this investigation
    attack_paths = _query("""
        SELECT id::text, chain_type, confidence,
               composite_risk, status, created_at::text
        FROM attack_paths
        WHERE tenant_id = %s
          AND %s = ANY(investigation_ids)
        ORDER BY created_at DESC
        LIMIT 10
    """, (tenant_id, investigation_id))

    return {
        "related": related,
        "attack_paths": attack_paths,
        "investigation_id": investigation_id,
        "search_criteria": {
            "source_ip": source_ip,
            "username": username,
            "task_type": task_type,
        },
        "latency_ms": round((time.time() - start) * 1000),
    }


# ── brief ───────────────────────────────────────────────────

def _brief_fallback(stats: dict, top_attacks: list, hours: int) -> str:
    """Template-based brief when LLM is unavailable."""
    total = stats.get("total", 0)
    attacks = stats.get("attacks", 0)
    benign = stats.get("benign", 0)
    critical = stats.get("critical", 0)
    avg_risk = stats.get("avg_attack_risk", 0)

    top_str = ", ".join(f"{a['task_type']} ({a['count']})" for a in top_attacks[:3])

    return (
        f"Shift brief for the last {hours} hours: "
        f"{total} investigations processed — {attacks} attacks detected, {benign} benign, "
        f"{critical} critical (risk>=85). "
        f"Average attack risk: {avg_risk}. "
        f"{'Top attack types: ' + top_str + '. ' if top_str else ''}"
        f"{'Immediate action required on critical findings.' if critical > 0 else 'No critical findings requiring immediate action.'}"
    )


async def brief(hours: int, tenant_id: str) -> dict:
    """Generate a shift handoff brief for the given time window."""
    start = time.time()
    hours = max(1, min(168, hours))

    stats = _query_one("""
        SELECT
            COUNT(*)::int as total,
            COUNT(*) FILTER (WHERE output->>'verdict' = 'true_positive')::int as attacks,
            COUNT(*) FILTER (WHERE output->>'verdict' = 'benign')::int as benign,
            COUNT(*) FILTER (WHERE output->>'verdict' = 'suspicious')::int as suspicious,
            COUNT(*) FILTER (WHERE (output->>'risk_score')::int >= 85)::int as critical,
            COALESCE(ROUND(AVG((output->>'risk_score')::numeric) FILTER (WHERE output->>'verdict' != 'benign'), 1), 0) as avg_attack_risk
        FROM agent_tasks
        WHERE tenant_id = %s AND status = 'completed'
          AND created_at > NOW() - INTERVAL '%s hours'
    """.replace("'%s hours'", f"'{hours} hours'"), (tenant_id,)) or {}

    top_attacks = _query("""
        SELECT task_type, COUNT(*)::int as count
        FROM agent_tasks
        WHERE tenant_id = %s AND status = 'completed'
          AND output->>'verdict' IN ('true_positive', 'suspicious')
          AND created_at > NOW() - INTERVAL '%s hours'
        GROUP BY task_type ORDER BY count DESC LIMIT 5
    """.replace("'%s hours'", f"'{hours} hours'"), (tenant_id,))

    # Optional LLM narrative
    system = "You are writing a SOC shift handoff brief. Be concise, actionable, and highlight critical items."
    prompt = (
        f"Generate a shift handoff brief for the last {hours} hours.\n"
        f"Stats: {json.dumps(stats, default=str)}\n"
        f"Top attack types: {json.dumps(top_attacks, default=str)}\n\n"
        f"Summarize: total alerts, key attacks, critical findings, and actions for the incoming shift."
    )
    narrative = await _copilot_llm_call(prompt, system, timeout=20.0)
    if narrative is None:
        narrative = _brief_fallback(stats, top_attacks, hours)

    return {
        "brief": narrative,
        "stats": stats,
        "top_attacks": top_attacks,
        "hours": hours,
        "latency_ms": round((time.time() - start) * 1000),
    }
