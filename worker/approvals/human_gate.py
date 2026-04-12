"""Human-in-the-loop approval gate for MCP-triggered workflows.

When an external AI assistant requests a workflow via MCP, the request
is held pending human approval. An approval token is stored in Redis
with a 30-minute TTL. The workflow only executes after human approval.

Flow:
  1. MCP tool call → create pending approval in Redis
  2. Notify on-call via webhook/Slack
  3. Human approves/denies via API
  4. On approve: execute workflow
  5. On deny or timeout: log rejection
"""
import hashlib
import json
import logging
import os
import secrets
import time

logger = logging.getLogger(__name__)

APPROVAL_TTL = 1800  # 30 minutes
REDIS_APPROVAL_PREFIX = "zovark:approval:"


def _get_redis():
    """Get Redis connection."""
    try:
        import redis
        url = os.environ.get("REDIS_URL", "redis://:hydra-redis-dev-2026@redis:6379/0")  # FIX #16
        return redis.from_url(url, decode_responses=True)
    except Exception:
        return None


class ApprovalGate:
    """Human-in-the-loop approval gate.

    Stores pending MCP workflow approval requests in Redis with a 30-minute TTL.
    Each approval token is single-use: once approved or denied the TTL is
    shortened and the token cannot be reused.

    The gate is fail-closed: if Redis is unavailable, ``create_approval`` raises
    ``RuntimeError`` and the workflow is never started.
    """

    def __init__(self):
        self._redis = None

    def _get_redis(self):
        if self._redis is None:
            self._redis = _get_redis()
        return self._redis

    def create_approval(self, workflow_id: str, workflow_args: dict,
                        requested_by: str, tenant_id: str) -> dict:
        """Create a pending approval request.

        Args:
            workflow_id: The workflow to execute (e.g. "DetectionGenerationWorkflow").
            workflow_args: Arguments for the workflow (serialised to JSON in Redis).
            requested_by: Identity of the requester (e.g. "mcp:claude-code").
            tenant_id: Tenant context for the approval.

        Returns:
            dict with keys: token, approval_id, status, expires_at, message.

        Raises:
            RuntimeError: When Redis is unavailable (fail-closed — no approval
                          means no execution).
        """
        r = self._get_redis()
        if r is None:
            raise RuntimeError("Redis unavailable — cannot create approval")

        token = secrets.token_urlsafe(32)
        approval_id = hashlib.sha256(token.encode()).hexdigest()[:16]
        expires_at = int(time.time()) + APPROVAL_TTL

        approval = {
            "approval_id": approval_id,
            "workflow_id": workflow_id,
            "workflow_args": json.dumps(workflow_args),
            "requested_by": requested_by,
            "tenant_id": tenant_id,
            "status": "pending",
            "created_at": int(time.time()),
            "expires_at": expires_at,
        }

        key = f"{REDIS_APPROVAL_PREFIX}{token}"
        r.setex(key, APPROVAL_TTL, json.dumps(approval))

        # Secondary index by approval_id (stores the token so callers can
        # look up the primary key without knowing the token).
        r.setex(f"{REDIS_APPROVAL_PREFIX}id:{approval_id}", APPROVAL_TTL, token)

        logger.info(
            "Approval created: %s for workflow %s by %s",
            approval_id, workflow_id, requested_by,
        )

        return {
            "token": token,
            "approval_id": approval_id,
            "status": "pending",
            "expires_at": expires_at,
            "message": (
                f"Workflow '{workflow_id}' requires human approval. "
                f"Approval expires in {APPROVAL_TTL // 60} minutes."
            ),
        }

    def check_approval(self, token: str) -> dict | None:
        """Check the status of an approval request.

        Args:
            token: The approval token returned by :meth:`create_approval`.

        Returns:
            The approval dict or ``None`` if the token has expired or was never
            created.
        """
        r = self._get_redis()
        if r is None:
            return None

        key = f"{REDIS_APPROVAL_PREFIX}{token}"
        data = r.get(key)
        if not data:
            return None

        return json.loads(data)

    def approve(self, token: str, approved_by: str) -> dict:
        """Approve a pending request.

        The token is consumed (single-use): its TTL is reduced to 60 seconds so
        the caller can read the result once, and it cannot be re-approved.

        Args:
            token: The approval token.
            approved_by: User ID or display name of the approver.

        Returns:
            Updated approval dict with status='approved', or an error dict.

        Raises:
            RuntimeError: When Redis is unavailable.
        """
        r = self._get_redis()
        if r is None:
            raise RuntimeError("Redis unavailable")

        key = f"{REDIS_APPROVAL_PREFIX}{token}"
        data = r.get(key)
        if not data:
            return {"error": "Approval not found or expired", "status": "expired"}

        approval = json.loads(data)
        if approval["status"] != "pending":
            return {
                "error": f"Approval already {approval['status']}",
                "status": approval["status"],
            }

        approval["status"] = "approved"
        approval["approved_by"] = approved_by
        approval["approved_at"] = int(time.time())

        # Short TTL — just long enough for the workflow dispatcher to read it.
        r.setex(key, 60, json.dumps(approval))

        logger.info("Approval %s APPROVED by %s", approval["approval_id"], approved_by)
        return approval

    def deny(self, token: str, denied_by: str, reason: str = "") -> dict:
        """Deny a pending request.

        The record is kept for 5 minutes for audit purposes.

        Args:
            token: The approval token.
            denied_by: User ID or display name of the denier.
            reason: Optional human-readable reason for the denial.

        Returns:
            Updated approval dict with status='denied', or an error dict.

        Raises:
            RuntimeError: When Redis is unavailable.
        """
        r = self._get_redis()
        if r is None:
            raise RuntimeError("Redis unavailable")

        key = f"{REDIS_APPROVAL_PREFIX}{token}"
        data = r.get(key)
        if not data:
            return {"error": "Approval not found or expired", "status": "expired"}

        approval = json.loads(data)
        if approval["status"] != "pending":
            return {
                "error": f"Approval already {approval['status']}",
                "status": approval["status"],
            }

        approval["status"] = "denied"
        approval["denied_by"] = denied_by
        approval["denied_at"] = int(time.time())
        approval["deny_reason"] = reason

        # Keep for audit trail (5-minute window).
        r.setex(key, 300, json.dumps(approval))

        logger.info(
            "Approval %s DENIED by %s: %s",
            approval["approval_id"], denied_by, reason,
        )
        return approval

    def list_pending(self, tenant_id: str | None = None) -> list:
        """List all pending approvals, optionally filtered by tenant.

        Args:
            tenant_id: If provided, only return approvals for this tenant.

        Returns:
            List of approval dicts (token field is omitted for security).
            Sorted by creation time, newest first.
        """
        r = self._get_redis()
        if r is None:
            return []

        pending = []
        # Scan only primary token keys (skip the id: secondary index keys).
        for key in r.scan_iter(f"{REDIS_APPROVAL_PREFIX}*"):
            if ":id:" in key:
                continue
            data = r.get(key)
            if not data:
                continue
            try:
                approval = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                continue
            if approval.get("status") != "pending":
                continue
            if tenant_id and approval.get("tenant_id") != tenant_id:
                continue
            # Strip the raw token — callers must use the token they were given
            # at creation time or look it up via the id: index.
            pending.append({
                "approval_id": approval.get("approval_id"),
                "workflow_id": approval.get("workflow_id"),
                "requested_by": approval.get("requested_by"),
                "tenant_id": approval.get("tenant_id"),
                "status": approval.get("status"),
                "created_at": approval.get("created_at"),
                "expires_at": approval.get("expires_at"),
            })

        return sorted(pending, key=lambda x: x.get("created_at", 0), reverse=True)

    def get_by_approval_id(self, approval_id: str) -> dict | None:
        """Look up an approval by its short approval_id (not the full token).

        Useful for admin list views where the full token is not shown.

        Args:
            approval_id: The 16-character hex approval_id.

        Returns:
            Approval dict (token omitted) or ``None`` if not found / expired.
        """
        r = self._get_redis()
        if r is None:
            return None

        id_key = f"{REDIS_APPROVAL_PREFIX}id:{approval_id}"
        token = r.get(id_key)
        if not token:
            return None

        approval = self.check_approval(token)
        if approval:
            approval.pop("token", None)
        return approval


# Module-level singleton — import and call get_approval_gate() everywhere.
_gate = ApprovalGate()


def get_approval_gate() -> ApprovalGate:
    """Return the module-level ApprovalGate singleton."""
    return _gate
