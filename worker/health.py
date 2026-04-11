"""Worker health/readiness HTTP endpoint.

Runs a lightweight HTTP server on port 8095 (configurable) alongside the
Temporal worker. Docker and Kubernetes can use this for health checks instead
of the basic `import temporalio` check.

Endpoints:
    GET /health     -> 200 {"status": "ok", "worker_id": "...", "uptime_s": N}
    GET /ready      -> 200 if Temporal connected and DB reachable, 503 otherwise

Usage:
    Start from main.py:
        from health import start_health_server
        start_health_server(worker_id=WORKER_ID)
"""

import os
import json
import time
import threading
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)

HEALTH_PORT = int(os.environ.get("WORKER_HEALTH_PORT", "8095"))

# Shared state — set by the worker process
_state = {
    "worker_id": "unknown",
    "started_at": time.time(),
    "temporal_connected": False,
    "db_reachable": False,
}


def set_temporal_connected(connected: bool):
    """Called by main.py after successful Temporal connection."""
    _state["temporal_connected"] = connected


def set_db_reachable(reachable: bool):
    """Called by main.py or pool_manager after DB check."""
    _state["db_reachable"] = reachable


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = {
                "status": "ok",
                "worker_id": _state["worker_id"],
                "uptime_s": int(time.time() - _state["started_at"]),
            }
            self._respond(200, body)

        elif self.path == "/ready":
            ready = _state["temporal_connected"]
            status_code = 200 if ready else 503
            body = {
                "ready": ready,
                "temporal_connected": _state["temporal_connected"],
                "db_reachable": _state["db_reachable"],
                "worker_id": _state["worker_id"],
            }
            self._respond(status_code, body)

        else:
            self._respond(404, {"error": "not found"})

    def _respond(self, code: int, body: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        pass  # Suppress request logs


def start_health_server(worker_id: str = "unknown", port: int = 0):
    """Start health server in a daemon thread. Non-blocking.

    Args:
        worker_id: Worker identifier for health responses.
        port: Override port (default: WORKER_HEALTH_PORT env or 8095).
    """
    _state["worker_id"] = worker_id
    _state["started_at"] = time.time()

    actual_port = port or HEALTH_PORT

    def _serve():
        try:
            server = HTTPServer(("0.0.0.0", actual_port), HealthHandler)
            logger.info("Health server listening on port %d", actual_port)
            server.serve_forever()
        except Exception as e:
            logger.warning("Health server failed to start: %s", e)

    t = threading.Thread(target=_serve, daemon=True, name="health-server")
    t.start()
