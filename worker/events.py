"""
Investigation event emitter — sends real-time progress events via PostgreSQL NOTIFY.

Events are fire-and-forget. If NOTIFY fails, the investigation continues.
The Go API listens on the 'investigation_events' channel and forwards to SSE clients.

Usage:
    from events import emit_event
    emit_event(task_id, tenant_id, trace_id, "tool_completed",
               {"tool": "extract_ipv4", "duration_ms": 5, "summary": "Found 3 IPs"})
"""
import json
import os
import logging
from datetime import datetime, timezone

import psycopg2

logger = logging.getLogger(__name__)

try:
    from settings import settings as _settings
    _DB_URL = os.environ.get("DATABASE_URL", _settings.database_url)
except ImportError:
    _DB_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@pgbouncer:5432/zovark")


def emit_event(
    task_id: str,
    tenant_id: str,
    trace_id: str,
    event_type: str,
    data: dict = None,
):
    """Send a real-time investigation event via PostgreSQL NOTIFY.

    Fire-and-forget — never raises, never blocks the pipeline.
    """
    if data is None:
        data = {}
    try:
        payload = json.dumps({
            "event_type": event_type,
            "task_id": task_id,
            "tenant_id": tenant_id,
            "trace_id": trace_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        })
        # NOTIFY payload limit is 8000 bytes
        if len(payload) > 7900:
            for key in ("raw_details", "full_output", "raw_log", "stdout"):
                data.pop(key, None)
            data["truncated"] = True
            payload = json.dumps({
                "event_type": event_type,
                "task_id": task_id,
                "tenant_id": tenant_id,
                "trace_id": trace_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": data,
            })

        conn = psycopg2.connect(_DB_URL)
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_notify('investigation_events', %s)", (payload,))
        finally:
            conn.close()
    except Exception as e:
        logger.debug(f"Event emit failed ({event_type}): {e}")


def tool_summary(tool_name: str, result, duration_ms: int) -> str:
    """Generate a human-readable summary for a tool execution."""
    if isinstance(result, list):
        count = len(result)
        if "extract" in tool_name:
            ioc_type = tool_name.replace("extract_", "")
            return f"Found {count} {ioc_type}{'s' if count != 1 else ''}"
        return f"Returned {count} items"
    if isinstance(result, dict):
        if "risk_score" in result:
            return f"Risk score: {result['risk_score']}/100"
        if "correlation_count" in result:
            cc = result["correlation_count"]
            return f"Found {cc} related alert{'s' if cc != 1 else ''}"
        if "has_context" in result:
            return "Context found" if result["has_context"] else "No context"
        if "findings" in result:
            return f"{len(result['findings'])} findings"
        return f"Completed in {duration_ms}ms"
    if isinstance(result, int):
        if "score" in tool_name:
            return f"Risk score: {result}/100"
        if "count" in tool_name:
            return f"Count: {result}"
        return f"Result: {result}"
    if isinstance(result, float):
        return f"Entropy: {result:.2f}"
    return f"Completed in {duration_ms}ms"
