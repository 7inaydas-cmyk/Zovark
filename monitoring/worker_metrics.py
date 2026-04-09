#!/usr/bin/env python3
"""Zovark worker metrics exporter — DB-backed Prometheus endpoint.

Queries PostgreSQL for investigation/entity/detection metrics and
exposes them on port 9093 in Prometheus text format.

Usage:
    python monitoring/worker_metrics.py

Endpoints:
    GET /metrics    → Prometheus text format
    GET /health     → {"status": "ok"}
"""

import os
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

try:
    import redis as redis_lib
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
PORT = int(os.environ.get("METRICS_PORT", "9093"))

_metrics = {}


def _fetch_db_metrics():
    """Fetch metrics from PostgreSQL."""
    global _metrics
    if not HAS_PSYCOPG2:
        return
    try:
        conn = psycopg2.connect(DATABASE_URL)
        try:
            with conn.cursor() as cur:
                # Worker up indicator
                _metrics["zovark_worker_up"] = 1

                # Investigation counts
                cur.execute("SELECT COUNT(*) FROM investigations")
                _metrics["zovark_worker_investigations_total"] = cur.fetchone()[0]

                # Entity counts
                cur.execute("SELECT COUNT(*) FROM entities")
                _metrics["zovark_worker_entities_total"] = cur.fetchone()[0]

                # Detection rules (Sigma)
                cur.execute("SELECT COUNT(*) FROM detection_rules")
                _metrics["zovark_worker_sigma_rules_total"] = cur.fetchone()[0]

                # Verdicts breakdown
                cur.execute("""
                    SELECT verdict, COUNT(*) FROM investigations
                    WHERE verdict IS NOT NULL
                    GROUP BY verdict
                """)
                for row in cur.fetchall():
                    _metrics[f'zovark_worker_verdict_total{{verdict="{row[0]}"}}'] = row[1]

                # Tasks by type
                cur.execute("""
                    SELECT task_type, COUNT(*) FROM agent_tasks
                    GROUP BY task_type
                """)
                for row in cur.fetchall():
                    _metrics[f'zovark_worker_tasks_by_type{{task_type="{row[0]}"}}'] = row[1]

                # LLM usage stats (last hour)
                cur.execute("""
                    SELECT
                        COALESCE(AVG(execution_ms) / 1000.0, 0),
                        COALESCE(SUM(tokens_input + tokens_output), 0)
                    FROM usage_records
                    WHERE created_at > NOW() - INTERVAL '1 hour'
                """)
                row = cur.fetchone()
                _metrics["zovark_worker_llm_request_seconds"] = round(float(row[0]), 2)
                _metrics["zovark_worker_llm_tokens_total"] = int(row[1])

                # Response playbooks
                cur.execute("SELECT COUNT(*) FROM response_playbooks WHERE enabled = true")
                _metrics["zovark_worker_playbooks_active"] = cur.fetchone()[0]

                # Response executions (last hour)
                cur.execute("""
                    SELECT status, COUNT(*) FROM response_executions
                    WHERE created_at > NOW() - INTERVAL '1 hour'
                    GROUP BY status
                """)
                for row in cur.fetchall():
                    _metrics[f'zovark_worker_response_executions{{status="{row[0]}"}}'] = row[1]

        finally:
            conn.close()
    except Exception as e:
        _metrics["zovark_worker_up"] = 0
        print(f"DB metrics fetch failed: {e}")


def _fetch_redis_metrics():
    """Fetch rate limiter metrics from Redis."""
    global _metrics
    if not HAS_REDIS:
        return
    try:
        r = redis_lib.from_url(REDIS_URL, decode_responses=True)
        # Count active lease sets
        keys = r.keys("tenant:*:active_leases")
        for key in keys:
            tenant_id = key.split(":")[1]
            count = r.scard(key)
            _metrics[f'zovark_worker_active_leases{{tenant_id="{tenant_id}"}}'] = count
    except Exception as e:
        print(f"Redis metrics fetch failed: {e}")


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._respond(200, json.dumps({"status": "ok"}))
        elif self.path == "/metrics":
            lines = []
            for key, val in _metrics.items():
                if "{" in key:
                    lines.append(f"{key} {val}")
                else:
                    lines.append(f"{key} {val}")
            self._respond(200, "\n".join(lines) + "\n", "text/plain")
        else:
            self._respond(200, json.dumps(_metrics, indent=2, default=str))

    def _respond(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass


def _poll_loop():
    """Background thread: poll metrics every 15 seconds."""
    while True:
        _fetch_db_metrics()
        _fetch_redis_metrics()
        time.sleep(15)


def main():
    print(f"Worker metrics exporter starting on port {PORT}")
    t = threading.Thread(target=_poll_loop, daemon=True)
    t.start()
    server = HTTPServer(("0.0.0.0", PORT), MetricsHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
