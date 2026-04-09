#!/usr/bin/env python3
"""Temporal queue depth exporter — lightweight HTTP JSON endpoint.

Queries Temporal for pending/active task counts and exposes them
on port 9092 as JSON (with optional Prometheus text format).

Usage:
    python monitoring/temporal_exporter.py

Endpoints:
    GET /           → JSON: {pending_tasks, active_tasks, workers}
    GET /metrics    → Prometheus text format
    GET /health     → {"status": "ok"}
"""

import os
import json
import asyncio
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# Try Temporal SDK
try:
    from temporalio.client import Client as TemporalClient
    HAS_TEMPORAL_SDK = True
except ImportError:
    HAS_TEMPORAL_SDK = False

# Try psycopg2 as fallback
try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

TEMPORAL_ADDRESS = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
PORT = int(os.environ.get("EXPORTER_PORT", "9092"))

# Cached metrics
_metrics = {
    "pending_tasks": 0,
    "active_tasks": 0,
    "completed_tasks_1h": 0,
    "failed_tasks_1h": 0,
    "workers": 1,
}


def _fetch_metrics_db():
    """Fetch metrics from PostgreSQL (fallback)."""
    global _metrics
    if not HAS_PSYCOPG2:
        return
    try:
        conn = psycopg2.connect(DATABASE_URL)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM agent_tasks WHERE status = 'pending'")
                _metrics["pending_tasks"] = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM agent_tasks WHERE status = 'running'")
                _metrics["active_tasks"] = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM agent_tasks WHERE status = 'completed' AND completed_at > NOW() - INTERVAL '1 hour'")
                _metrics["completed_tasks_1h"] = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM agent_tasks WHERE status = 'failed' AND completed_at > NOW() - INTERVAL '1 hour'")
                _metrics["failed_tasks_1h"] = cur.fetchone()[0]
        finally:
            conn.close()
    except Exception as e:
        print(f"DB metrics fetch failed: {e}")


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._respond(200, json.dumps({"status": "ok"}))
        elif self.path == "/metrics":
            # Prometheus text format
            lines = []
            for key, val in _metrics.items():
                lines.append(f"zovark_temporal_{key}{{task_queue=\"zovark-tasks\"}} {val}")
            self._respond(200, "\n".join(lines) + "\n", "text/plain")
        else:
            self._respond(200, json.dumps(_metrics, indent=2))

    def _respond(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass  # Suppress request logging


def _poll_loop():
    """Background thread: poll metrics every 15 seconds."""
    while True:
        _fetch_metrics_db()
        import time
        time.sleep(15)


def main():
    print(f"Temporal exporter starting on port {PORT}")
    # Start background polling
    t = threading.Thread(target=_poll_loop, daemon=True)
    t.start()
    # Serve HTTP
    server = HTTPServer(("0.0.0.0", PORT), MetricsHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
