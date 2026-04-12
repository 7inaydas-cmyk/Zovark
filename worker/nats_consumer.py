"""NATS JetStream consumer for high-throughput alert ingestion.

Subscribes to ALERTS.> subject hierarchy using a minimal NATS client
built on raw TCP sockets (no external library required).

Falls back to polling DB if NATS unavailable.

Connection: nats://zovark-nats:4222 (from NATS_URL env var)
"""

import json
import os
import socket
import time
import threading

import logger


NATS_URL = os.environ.get("NATS_URL", "")
DEFAULT_NATS_HOST = "zovark-nats"
DEFAULT_NATS_PORT = 4222
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 30
MAX_RECONNECT_ATTEMPTS = 10
RECONNECT_DELAY = 2


def _parse_nats_url(url: str) -> tuple:
    """Parse nats://host:port into (host, port)."""
    url = url.strip()
    if url.startswith("nats://"):
        url = url[7:]
    if ":" in url:
        host, port_str = url.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = DEFAULT_NATS_PORT
    else:
        host = url
        port = DEFAULT_NATS_PORT
    return host or DEFAULT_NATS_HOST, port


class NATSAlertConsumer:
    """Minimal NATS client for alert ingestion via raw TCP.

    Implements enough of the NATS protocol to:
    - CONNECT to server
    - SUB to subjects
    - Receive MSG payloads
    - Send PUB (for acks)
    - Handle PING/PONG keepalive

    If NATS_URL is not set, the consumer is a no-op and the system
    relies on existing webhook-based alert ingestion.
    """

    def __init__(self, nats_url: str = "", worker_id: str = "unknown"):
        self._url = nats_url
        self._worker_id = worker_id
        self._host, self._port = _parse_nats_url(nats_url) if nats_url else (DEFAULT_NATS_HOST, DEFAULT_NATS_PORT)
        self._sock = None
        self._connected = False
        self._running = False
        self._subscriptions = {}
        self._sid_counter = 0
        self._buffer = b""
        self._handlers = {}
        self._thread = None

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        """Connect to NATS server with retry."""
        if not self._url:
            logger.info("NATS_URL not set, skipping NATS consumer")
            return

        for attempt in range(MAX_RECONNECT_ATTEMPTS):
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.settimeout(CONNECT_TIMEOUT)
                self._sock.connect((self._host, self._port))
                self._sock.settimeout(READ_TIMEOUT)

                # Read INFO line from server
                info_line = self._readline()
                if not info_line.startswith("INFO"):
                    raise ConnectionError(f"Expected INFO, got: {info_line[:50]}")

                # Send CONNECT
                connect_payload = json.dumps({
                    "verbose": False,
                    "pedantic": False,
                    "name": f"zovark-worker-{self._worker_id}",
                    "lang": "python",
                    "version": "0.1.0",
                    "protocol": 1,
                })
                self._send(f"CONNECT {connect_payload}\r\n")

                # Send PING to verify connection
                self._send("PING\r\n")
                pong = self._readline()
                if not pong.startswith("PONG"):
                    raise ConnectionError(f"Expected PONG, got: {pong[:50]}")

                self._connected = True
                logger.info("NATS connected", host=self._host, port=self._port, attempt=attempt + 1)
                return

            except Exception as e:
                logger.warn("NATS connection attempt failed",
                            attempt=attempt + 1, error=str(e))
                self._close_socket()
                if attempt < MAX_RECONNECT_ATTEMPTS - 1:
                    time.sleep(RECONNECT_DELAY)

        logger.error("NATS connection failed after all attempts",
                     host=self._host, port=self._port)

    def subscribe(self, subject: str, handler=None) -> None:
        """Subscribe to a NATS subject.

        Args:
            subject: NATS subject (e.g., 'ALERTS.tenant-slug')
            handler: Optional callback(subject, data_dict). If None, uses default handler.
        """
        if not self._connected:
            logger.warn("Cannot subscribe: not connected to NATS")
            return

        self._sid_counter += 1
        sid = str(self._sid_counter)
        self._subscriptions[sid] = subject
        if handler:
            self._handlers[sid] = handler

        self._send(f"SUB {subject} {sid}\r\n")
        logger.info("NATS subscribed", subject=subject, sid=sid)

    def _process_message(self, subject: str, sid: str, payload: str) -> None:
        """Process a received NATS message."""
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            logger.warn("NATS message not valid JSON", subject=subject, payload=payload[:200])
            return

        handler = self._handlers.get(sid)
        if handler:
            try:
                handler(subject, data)
            except Exception as e:
                logger.error("NATS message handler error", subject=subject, error=str(e))
        else:
            self._default_handler(subject, data)

    def _default_handler(self, subject: str, data: dict) -> None:
        """Default handler logs the alert."""
        logger.info("NATS alert received",
                    subject=subject,
                    alert_type=data.get("type", "unknown"),
                    tenant_id=data.get("tenant_id", "unknown"))

    def process_alert(self, subject: str, data: dict) -> None:
        """Parse, validate, and submit alert to Temporal.

        Called by the NATS message loop for every message on ALERTS.>.
        Starts an InvestigationWorkflowV2 workflow for each valid alert.
        """
        # FIX BUG-001: implement Temporal dispatch so alerts are not silently dropped
        required_fields = ["tenant_id", "alert_type"]
        for field in required_fields:
            if field not in data:
                logger.warn("NATS alert missing required field", field=field, subject=subject)
                return

        tenant_id = data.get("tenant_id")
        alert_type = data.get("alert_type")

        logger.info("Processing NATS alert",
                    subject=subject,
                    tenant_id=tenant_id,
                    alert_type=alert_type)

        try:
            from temporalio.client import Client
            import asyncio

            async def _start():
                temporal_address = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
                client = await Client.connect(temporal_address)
                task_id = data.get("task_id") or __import__("uuid").uuid4().hex
                await client.start_workflow(
                    "InvestigationWorkflowV2",
                    {"task_id": task_id, "tenant_id": tenant_id, "alert_type": alert_type, **data},
                    id=f"nats-{task_id}",
                    task_queue="zovark-tasks",
                )
                logger.info("NATS alert dispatched to Temporal",
                            workflow_id=f"nats-{task_id}",
                            tenant_id=tenant_id)

            asyncio.run(_start())

        except Exception as e:
            logger.error("NATS alert dispatch failed",
                         subject=subject,
                         tenant_id=tenant_id,
                         error=str(e))

    def ack(self, reply_to: str) -> None:
        """Acknowledge a processed message (for JetStream)."""
        if not self._connected or not reply_to:
            return
        try:
            self._send(f"PUB {reply_to} 0\r\n\r\n")
        except Exception as e:
            logger.warn("NATS ack failed", error=str(e))

    def start_listening(self) -> None:
        """Start the message listening loop in a background thread."""
        if not self._connected:
            return

        self._running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="nats-consumer")
        self._thread.start()
        logger.info("NATS listener started")

    def _listen_loop(self) -> None:
        """Main message loop. Runs in background thread."""
        while self._running and self._connected:
            try:
                line = self._readline()
                if not line:
                    continue

                if line.startswith("MSG"):
                    # MSG <subject> <sid> [reply-to] <#bytes>
                    parts = line.split()
                    if len(parts) >= 4:
                        subject = parts[1]
                        sid = parts[2]
                        if len(parts) == 5:
                            # Has reply-to
                            num_bytes = int(parts[4])
                        else:
                            num_bytes = int(parts[3])

                        payload = self._read_bytes(num_bytes)
                        # Read trailing \r\n
                        self._readline()

                        self._process_message(subject, sid, payload.decode("utf-8", errors="replace"))

                elif line.startswith("PING"):
                    self._send("PONG\r\n")

                elif line.startswith("+OK"):
                    pass  # Server acknowledged

                elif line.startswith("-ERR"):
                    logger.error("NATS server error", error=line)

            except socket.timeout:
                # Send PING to keep connection alive
                try:
                    self._send("PING\r\n")
                except Exception:
                    self._connected = False
                    break

            except Exception as e:
                logger.error("NATS listener error", error=str(e))
                self._connected = False
                break

        logger.info("NATS listener stopped")

    def shutdown(self) -> None:
        """Graceful drain and disconnect."""
        self._running = False

        if self._connected:
            try:
                # Unsubscribe from all
                for sid in self._subscriptions:
                    self._send(f"UNSUB {sid}\r\n")
                # Allow drain
                time.sleep(0.5)
            except Exception:
                pass

        self._close_socket()
        self._connected = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        logger.info("NATS consumer shut down")

    # --- Low-level TCP helpers ---

    def _send(self, data: str) -> None:
        """Send raw data to NATS server."""
        if self._sock:
            self._sock.sendall(data.encode("utf-8"))

    def _readline(self) -> str:
        """Read a line (terminated by \\r\\n) from the socket."""
        while b"\r\n" not in self._buffer:
            try:
                chunk = self._sock.recv(4096)
                if not chunk:
                    self._connected = False
                    return ""
                self._buffer += chunk
            except socket.timeout:
                return ""
            except Exception:
                self._connected = False
                return ""

        idx = self._buffer.index(b"\r\n")
        line = self._buffer[:idx].decode("utf-8", errors="replace")
        self._buffer = self._buffer[idx + 2:]
        return line

    def _read_bytes(self, n: int) -> bytes:
        """Read exactly n bytes from the socket."""
        while len(self._buffer) < n:
            try:
                chunk = self._sock.recv(max(4096, n - len(self._buffer)))
                if not chunk:
                    break
                self._buffer += chunk
            except Exception:
                break

        data = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return data

    def _close_socket(self) -> None:
        """Close the socket safely."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def create_nats_consumer(worker_id: str = "unknown") -> NATSAlertConsumer:
    """Create and optionally connect a NATS consumer.

    If NATS_URL env var is not set, returns a disconnected consumer (no-op).
    """
    nats_url = os.environ.get("NATS_URL", "")
    consumer = NATSAlertConsumer(nats_url=nats_url, worker_id=worker_id)
    if nats_url:
        consumer.connect()
        if consumer.connected:
            # FIX BUG-001: pass process_alert as handler so every received alert
            # starts a Temporal InvestigationWorkflowV2 instead of being silently dropped
            consumer.subscribe("ALERTS.>", handler=consumer.process_alert)
            consumer.start_listening()
    else:
        logger.info("NATS_URL not configured, NATS consumer disabled")
    return consumer
