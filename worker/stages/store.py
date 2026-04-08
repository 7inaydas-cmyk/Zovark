"""
Stage 5: STORE — Persist all investigation artifacts.
NO LLM calls. DB writes only.

Self-contained: imports psycopg2 directly.
Does NOT import from _legacy_activities.py or entity_graph.py.
"""
import os
import json
import time
from dataclasses import asdict

import psycopg2

from temporalio import activity
from stages import StoreOutput

try:
    from settings import settings as _settings
    DATABASE_URL = os.environ.get("DATABASE_URL", _settings.database_url)
except ImportError:
    DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:hydra_dev_2026@pgbouncer:5432/zovark")
FAST_FILL = os.environ.get("ZOVARK_FAST_FILL", "false").lower() == "true"


REDIS_URL = os.environ.get("REDIS_URL", "redis://:zovark-redis-dev-2026@redis:6379/0")


def _get_redis():
    """Get a Redis connection for dedup entry updates. Returns None on failure."""
    try:
        import redis as _redis
        return _redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        return None


def _update_dedup_entry(task_id: str, verdict: str, risk_score: int, status: str, siem_event: dict):
    """Update the Redis dedup entry with investigation results (v2 dedup).
    Non-fatal — dedup still works via TTL if this fails."""
    try:
        r = _get_redis()
        if r is None:
            return
        # Recompute the same hash used by the Go API (alert_dedup.go)
        import hashlib
        import re as _re
        ts_patterns = [
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?',
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
            r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}',
        ]
        raw_log = siem_event.get("raw_log", "") if isinstance(siem_event, dict) else ""
        for pat in ts_patterns:
            raw_log = _re.sub(pat, "TIMESTAMP", raw_log)
        se = siem_event if isinstance(siem_event, dict) else {}
        canonical = {
            "destination_ip": se.get("destination_ip", se.get("dest_ip", "")),
            "hostname": se.get("hostname", ""),
            "raw_log": raw_log,
            "rule_name": se.get("rule_name", ""),
            "source_ip": se.get("source_ip", ""),
            "username": se.get("username", ""),
        }
        data = json.dumps(canonical, sort_keys=True).encode()
        alert_hash = hashlib.sha256(data).hexdigest()
        key = f"dedup:exact:{alert_hash}"

        existing = r.get(key)
        if existing:
            entry = json.loads(existing)
            if entry.get("task_id") == task_id:
                entry["status"] = "completed" if status == "completed" else "failed"
                entry["verdict"] = verdict
                entry["risk_score"] = risk_score
                ttl = r.ttl(key)
                if ttl and ttl > 0:
                    r.setex(key, ttl, json.dumps(entry))
        r.close()
    except Exception as e:
        print(f"Dedup entry update failed (non-fatal): {e}")


def _get_db():
    return psycopg2.connect(DATABASE_URL)


def _get_worker_id():
    import socket, random, string
    host = socket.gethostname()
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"{host}-{suffix}"


# --- Task status update ---
def _update_task_status(conn, task_id: str, status: str, output: dict,
                        tokens_in: int = 0, tokens_out: int = 0,
                        execution_ms: int = 0, severity: str = None,
                        error_message: str = None, model_name: str = "unknown",
                        path_taken: str = "", generated_code: str = ""):
    """Update agent_tasks with final status. Uses synchronous_commit for durability."""
    worker_id = _get_worker_id()
    human_review_threshold = int(os.environ.get("ZOVARK_HUMAN_REVIEW_THRESHOLD", "60"))

    risk_score = 0
    if isinstance(output, dict):
        risk_score = output.get("risk_score", 0) or 0

    needs_review = False
    review_reason = None
    # Check if assess stage explicitly flagged for review (e.g., LLM down)
    if isinstance(output, dict) and output.get("needs_human_review"):
        needs_review = True
        review_reason = output.get("review_reason", "Flagged for manual review")
    elif status != "completed":
        needs_review = True
        review_reason = error_message or "Investigation failed"
    elif risk_score < human_review_threshold:
        needs_review = True
        review_reason = f"Risk score {risk_score} below threshold {human_review_threshold}"

    with conn.cursor() as cur:
        # Critical write: ensure WAL flush before acknowledging
        cur.execute("SET LOCAL synchronous_commit = on;")
        cur.execute("""
            UPDATE agent_tasks
            SET status = %s, output = %s, error_message = %s,
                tokens_used_input = %s, tokens_used_output = %s, execution_ms = %s,
                severity = %s, worker_id = COALESCE(%s, worker_id),
                needs_human_review = %s, review_reason = %s,
                model_name = %s,
                path_taken = %s, generated_code = %s,
                completed_at = NOW()
            WHERE id = %s
        """, (
            status, json.dumps(output), error_message,
            tokens_in, tokens_out, execution_ms,
            severity, worker_id,
            needs_review, review_reason,
            model_name,
            path_taken or None, (generated_code or "")[:50000] if generated_code else None,
            task_id,
        ))


# --- Investigation memory ---
def _save_pattern(conn, task_type: str, alert_sig: str, code: str,
                  iocs: list, findings: list, risk_score: int, success: bool):
    """Save investigation pattern to memory table. No LLM."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO investigation_memory
                (task_type, alert_signature, code_template, iocs_found,
                 findings_found, risk_score, success)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                task_type, alert_sig, (code or "")[:10000],
                json.dumps(iocs), json.dumps(findings),
                risk_score, success,
            ))
    except Exception as e:
        print(f"Pattern save failed (non-fatal): {e}")


# --- Investigation row (no embedding) ---
def _create_investigation(conn, tenant_id: str, task_id: str, verdict: str,
                          risk_score: int, confidence: float, summary: str,
                          model_name: str = "unknown"):
    """Insert investigations row without embedding. Uses synchronous_commit for durability.
    Returns investigation_id."""
    try:
        with conn.cursor() as cur:
            # Critical write: ensure WAL flush before acknowledging
            cur.execute("SET LOCAL synchronous_commit = on;")
            cur.execute("""
                INSERT INTO investigations
                (tenant_id, task_id, verdict, risk_score, confidence,
                 summary, source, model_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (tenant_id, task_id, verdict, risk_score, confidence,
                  (summary or "")[:2000], "production", model_name))
            row = cur.fetchone()
            return str(row[0]) if row else None
    except Exception as e:
        print(f"Investigation insert failed (non-fatal): {e}")
        return None


# --- Audit event ---
def _insert_audit_event(conn, tenant_id: str, event_type: str,
                        resource_type: str, resource_id: str,
                        metadata: dict = None, trace_id: str = ""):
    """Insert audit_events row. Non-fatal on failure."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_events
                (tenant_id, event_type, actor_type, resource_type, resource_id, metadata, trace_id)
                VALUES (%s, %s, 'worker', %s, %s, %s, %s)
            """, (
                tenant_id, event_type, resource_type,
                resource_id, json.dumps(metadata or {}),
                trace_id or None,
            ))
    except Exception as e:
        print(f"Audit event insert failed (non-fatal): {e}")


# --- Severity from risk score ---
def _severity_from_risk(risk_score: int) -> str:
    if risk_score >= 80:
        return "critical"
    elif risk_score >= 60:
        return "high"
    elif risk_score >= 40:
        return "medium"
    elif risk_score >= 20:
        return "low"
    return "informational"


# --- Main entry point ---
@activity.defn
async def store_investigation(data: dict) -> dict:
    """
    Stage 5: Persist all investigation artifacts.
    NO LLM calls. DB writes only.

    Input: merged dict from AssessOutput + ExecuteOutput + task metadata
    Returns: dict (serializable StoreOutput fields)
    """
    task_id = data.get("task_id", "")
    tenant_id = data.get("tenant_id", "")
    status = data.get("status", "completed")
    verdict = data.get("verdict", "inconclusive")
    risk_score = data.get("risk_score", 0)
    confidence = data.get("confidence", 0.5)
    memory_summary = data.get("memory_summary", "")
    stdout = data.get("stdout", "")
    stderr = data.get("stderr", "")
    iocs = data.get("iocs", [])
    findings = data.get("findings", [])
    recommendations = data.get("recommendations", [])
    code = data.get("code", "")
    tokens_in = data.get("tokens_in", 0)
    tokens_out = data.get("tokens_out", 0)
    execution_ms = data.get("execution_ms", 0)
    task_type = data.get("task_type", "")
    model_name = data.get("model_name", "unknown")
    siem_event = data.get("siem_event", {})
    path_taken = data.get("path_taken", "")
    generated_code = data.get("generated_code", data.get("code", ""))
    trace_id = data.get("trace_id", "")

    severity = _severity_from_risk(risk_score)
    investigation_id = None

    conn = _get_db()
    try:
        # Set RLS tenant context for this transaction
        # Use string format (not parameterized) because SET LOCAL doesn't
        # support $1 params through PgBouncer transaction pooling.
        # tenant_id is a UUID from the workflow, not user input.
        if tenant_id:
            with conn.cursor() as cur:
                cur.execute(f"SET LOCAL app.current_tenant = '{tenant_id}'")

        # 0. Audit: investigation_started
        if tenant_id:
            _insert_audit_event(
                conn, tenant_id, "investigation_started",
                "agent_task", task_id,
                {"task_type": task_type, "severity": severity, "model": model_name},
                trace_id=trace_id,
            )

        # 1. Update task status
        output = {
            "stdout": stdout,
            "iocs": iocs,
            "findings": findings,
            "risk_score": risk_score,
            "verdict": verdict,
            "recommendations": recommendations,
            "model_used": model_name,
            "stderr": stderr[:500] if stderr else "",
            "generated_code": (code or "")[:2000],
            "mitre_attack": data.get("mitre_attack", []),
            "investigation_metadata": data.get("investigation_metadata", {}),
            "plain_english_summary": data.get("plain_english_summary", ""),
            # v3 fields
            "execution_mode": data.get("execution_mode", ""),
            "path_d_fallback": data.get("path_d_fallback", False),
            "path_d_reason": data.get("path_d_reason", ""),
            "needs_human_review": data.get("needs_human_review"),
            "review_reason": data.get("review_reason", ""),
            "autonomy_level": data.get("autonomy_level", ""),
            "tools_executed": data.get("tools_executed", 0),
        }
        _update_task_status(
            conn, task_id, status, output,
            tokens_in=tokens_in, tokens_out=tokens_out,
            execution_ms=execution_ms, severity=severity,
            model_name=model_name,
            path_taken=path_taken, generated_code=generated_code,
        )

        # 2. Save investigation pattern (no LLM)
        if status == "completed":
            _save_pattern(
                conn, task_type, siem_event.get("rule_name", ""),
                code, iocs, findings, risk_score, True,
            )

        # 3. Create investigation row (skip embedding in FAST_FILL)
        if status == "completed" and not FAST_FILL:
            investigation_id = _create_investigation(
                conn, tenant_id, task_id, verdict,
                risk_score, confidence, memory_summary or stdout[:2000],
                model_name=model_name,
            )

        # 4. Audit: investigation_completed
        if tenant_id:
            _insert_audit_event(
                conn, tenant_id, "investigation_completed",
                "agent_task", task_id,
                {
                    "verdict": verdict, "risk_score": risk_score,
                    "status": status, "execution_ms": execution_ms,
                    "investigation_id": investigation_id,
                    "ioc_count": len(iocs), "finding_count": len(findings),
                },
                trace_id=trace_id,
            )

        # 5. Persist entities and edges to the entity graph (non-fatal)
        if status == "completed" and tenant_id and iocs:
            try:
                from intelligence.entity_graph import (
                    persist_entities, persist_edges,
                    persist_cross_tenant, infer_relationships,
                )
                entity_map = persist_entities(
                    conn, tenant_id, investigation_id or task_id, iocs, risk_score,
                )
                if entity_map:
                    rels = infer_relationships(iocs, siem_event)
                    if rels:
                        persist_edges(conn, tenant_id, investigation_id or task_id, rels, entity_map)
                    persist_cross_tenant(conn, iocs, risk_score, verdict)
            except Exception as eg_err:
                print(f"Entity graph persistence failed (non-fatal): {eg_err}")

        # NOTIFY for SSE real-time updates (Mission 9)
        if status == "completed" and tenant_id:
            try:
                with conn.cursor() as cur:
                    notify_payload = json.dumps({
                        "task_id": task_id,
                        "tenant_id": tenant_id,
                        "verdict": verdict,
                        "risk_score": risk_score,
                        "task_type": task_type,
                    })
                    cur.execute("NOTIFY task_completed, %s", (notify_payload,))
                    # Trigger attack path correlator (async, separate workflow)
                    cur.execute("NOTIFY attack_path_correlate, %s", (notify_payload,))
            except Exception as notify_err:
                print(f"NOTIFY failed (non-fatal): {notify_err}")

        # Update Redis dedup entry with investigation results (v2 dedup)
        _update_dedup_entry(task_id, verdict, risk_score, status, siem_event)

        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Store failed: {e}")
        status = "failed"
    finally:
        conn.close()

    result = StoreOutput(
        task_id=task_id,
        status=status,
        investigation_id=investigation_id,
        memory_saved=status == "completed",
        pattern_saved=status == "completed",
    )

    return asdict(result)
