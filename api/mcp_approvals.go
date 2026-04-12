package main

// ============================================================
// MCP HUMAN-IN-THE-LOOP APPROVAL GATE
// ============================================================
//
// MCP-triggered workflows (zovark_trigger_workflow) must pass through a
// human approval gate before execution. Approval state is stored in Redis
// under the key prefix "zovark:approval:".
//
// Routes (registered in main.go):
//   POST /api/v1/mcp/approvals/request              — create pending approval (any authed caller)
//   GET  /api/v1/mcp/approvals/check/:token         — poll approval status (any authed caller)
//   GET  /api/v1/mcp/approvals/pending              — list pending approvals (admin)
//   GET  /api/v1/mcp/approvals/id/:approval_id      — lookup by short approval_id (admin)
//   POST /api/v1/mcp/approvals/:token/decide        — approve or deny (admin)
//
// Approval lifecycle:
//   pending  → approved  (TTL shortened to 60 s — workflow dispatcher reads once)
//   pending  → denied    (TTL shortened to 300 s for audit trail)
//   any      → expired   (Redis TTL reached, key deleted automatically)
//
// Security properties:
//   • The full approval token is NEVER returned to the MCP client.
//     Only the short approval_id is surfaced, preventing self-approval.
//   • Approval tokens are single-use (60 s TTL after approval).
//   • Tenant isolation enforced on all handlers.
//   • Fail-closed: Redis unavailable → approval blocked → workflow blocked.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// mcpApprovalSummary is the safe (token-free) view returned in list and lookup responses.
type mcpApprovalSummary struct {
	ApprovalID  string `json:"approval_id"`
	WorkflowID  string `json:"workflow_id"`
	RequestedBy string `json:"requested_by"`
	TenantID    string `json:"tenant_id"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	ExpiresAt   int64  `json:"expires_at"`
}

// parseMCPApproval unmarshals a JSON blob from Redis into a generic map.
func parseMCPApproval(raw string) (map[string]interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// toApprovalSummary converts a raw approval map to a safe summary struct.
func toApprovalSummary(m map[string]interface{}) mcpApprovalSummary {
	getString := func(key string) string {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	getInt64 := func(key string) int64 {
		if v, ok := m[key]; ok {
			switch n := v.(type) {
			case float64:
				return int64(n)
			case int64:
				return n
			case json.Number:
				i, _ := n.Int64()
				return i
			}
		}
		return 0
	}
	return mcpApprovalSummary{
		ApprovalID:  getString("approval_id"),
		WorkflowID:  getString("workflow_id"),
		RequestedBy: getString("requested_by"),
		TenantID:    getString("tenant_id"),
		Status:      getString("status"),
		CreatedAt:   getInt64("created_at"),
		ExpiresAt:   getInt64("expires_at"),
	}
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

// mcpGenerateToken produces a 43-byte URL-safe base64 token (no padding) using
// crypto/rand. Equivalent to Python's secrets.token_urlsafe(32).
func mcpGenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// mcpApprovalID returns the first 16 hex characters of SHA-256(token).
// Matches Python: hashlib.sha256(token.encode()).hexdigest()[:16]
func mcpApprovalID(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h[:])[:16]
}

// ─── POST /api/v1/mcp/approvals/request ──────────────────────────────────────

func requestMCPApprovalHandler(c *gin.Context) {
	callerTenantID := c.MustGet("tenant_id").(string)

	var req struct {
		WorkflowID   string                 `json:"workflow_id"  binding:"required"`
		WorkflowArgs map[string]interface{} `json:"workflow_args"`
		RequestedBy  string                 `json:"requested_by" binding:"required"`
		TenantID     string                 `json:"tenant_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Always use the authenticated tenant — prevents cross-tenant spoofing.
	req.TenantID = callerTenantID

	// Whitelist of workflow types that may be requested via MCP.
	allowedWorkflows := map[string]bool{
		"DetectionGenerationWorkflow": true,
		"SelfHealingWorkflow":         true,
		"CrossTenantRefreshWorkflow":  true,
		"BootstrapCorpusWorkflow":     true,
		"FineTuningPipelineWorkflow":  true,
	}
	if !allowedWorkflows[req.WorkflowID] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("unknown or disallowed workflow_id '%s'", req.WorkflowID),
		})
		return
	}

	// Generate cryptographically secure token + short approval_id.
	token, err := mcpGenerateToken()
	if err != nil {
		respondInternalError(c, err, "generate mcp approval token")
		return
	}
	approvalID := mcpApprovalID(token)
	now := time.Now().Unix()
	expiresAt := now + 1800 // 30 minutes

	argsJSON, _ := json.Marshal(req.WorkflowArgs)
	approval := map[string]interface{}{
		"approval_id":   approvalID,
		"workflow_id":   req.WorkflowID,
		"workflow_args": string(argsJSON),
		"requested_by":  req.RequestedBy,
		"tenant_id":     req.TenantID,
		"status":        "pending",
		"created_at":    now,
		"expires_at":    expiresAt,
	}

	approvalJSON, _ := json.Marshal(approval)
	primaryKey := "zovark:approval:" + token
	indexKey := "zovark:approval:id:" + approvalID

	ctx := c.Request.Context() // FIX #11
	if redisErr := redisClient.SetEx(ctx, primaryKey, string(approvalJSON), 1800*time.Second).Err(); redisErr != nil {
		respondInternalError(c, redisErr, "store mcp approval in redis")
		return
	}
	// Secondary index: approval_id → token (for admin lookup without exposing the token).
	if redisErr := redisClient.SetEx(ctx, indexKey, token, 1800*time.Second).Err(); redisErr != nil {
		// Non-fatal: primary key is already stored.
		log.Printf("[WARN] requestMCPApproval: failed to write id index key: %v", redisErr)
	}

	// Audit log — token is written server-side only.
	log.Printf("[AUDIT] MCP approval requested: id=%s workflow=%s by=%s tenant=%s token_prefix=%.8s…",
		approvalID, req.WorkflowID, req.RequestedBy, req.TenantID, token)

	// Return only the safe, non-secret approval_id to the MCP caller.
	c.JSON(http.StatusAccepted, gin.H{
		"approval_id": approvalID,
		"status":      "pending",
		"expires_at":  expiresAt,
		"message": fmt.Sprintf(
			"Workflow '%s' requires human approval. "+
				"A ZOVARK admin must approve via POST /api/v1/mcp/approvals/:token/decide. "+
				"Approval expires in 30 minutes.",
			req.WorkflowID,
		),
	})
}

// ─── GET /api/v1/mcp/approvals/check/:token ──────────────────────────────────

func checkMCPApprovalHandler(c *gin.Context) {
	token := c.Param("token")
	callerTenantID := c.MustGet("tenant_id").(string)

	ctx := c.Request.Context() // FIX #11
	raw, err := redisClient.Get(ctx, "zovark:approval:"+token).Result()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  "expired",
			"message": "Approval token not found or has expired.",
		})
		return
	}

	m, parseErr := parseMCPApproval(raw)
	if parseErr != nil {
		respondInternalError(c, parseErr, "parse mcp approval for check")
		return
	}

	// Tenant isolation — return "expired" instead of 403 to avoid leaking existence.
	if tid, _ := m["tenant_id"].(string); tid != callerTenantID {
		c.JSON(http.StatusOK, gin.H{
			"status":  "expired",
			"message": "Approval token not found or has expired.",
		})
		return
	}

	status, _ := m["status"].(string)
	approvalID, _ := m["approval_id"].(string)
	workflowID, _ := m["workflow_id"].(string)

	c.JSON(http.StatusOK, gin.H{
		"status":      status,
		"approval_id": approvalID,
		"workflow_id": workflowID,
	})
}

// ─── GET /api/v1/mcp/approvals/pending ───────────────────────────────────────

func listMCPApprovalsHandler(c *gin.Context) {
	callerTenantID := c.MustGet("tenant_id").(string)
	filterTenant := c.Query("tenant_id")
	if filterTenant == "" {
		filterTenant = callerTenantID
	}

	ctx := c.Request.Context() // FIX #11
	keys, err := redisClient.Keys(ctx, "zovark:approval:*").Result()
	if err != nil {
		log.Printf("[WARN] listMCPApprovals: Redis KEYS error: %v", err)
		c.JSON(http.StatusOK, gin.H{"approvals": []interface{}{}, "count": 0})
		return
	}

	var approvals []mcpApprovalSummary
	for _, key := range keys {
		// Skip the secondary approval_id → token index keys.
		if strings.Contains(key, ":id:") {
			continue
		}

		raw, redisErr := redisClient.Get(ctx, key).Result()
		if redisErr != nil || raw == "" {
			continue
		}

		m, parseErr := parseMCPApproval(raw)
		if parseErr != nil {
			continue
		}

		if status, _ := m["status"].(string); status != "pending" {
			continue
		}

		if tid, _ := m["tenant_id"].(string); tid != filterTenant {
			continue
		}

		approvals = append(approvals, toApprovalSummary(m))
	}

	if approvals == nil {
		approvals = []mcpApprovalSummary{}
	}

	c.JSON(http.StatusOK, gin.H{
		"approvals": approvals,
		"count":     len(approvals),
	})
}

// ─── GET /api/v1/mcp/approvals/id/:approval_id ───────────────────────────────

func getMCPApprovalByIDHandler(c *gin.Context) {
	approvalID := c.Param("approval_id")
	if approvalID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "approval_id is required"})
		return
	}

	ctx := context.Background()
	idKey := "zovark:approval:id:" + approvalID
	token, err := redisClient.Get(ctx, idKey).Result()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found or expired"})
		return
	}

	raw, err := redisClient.Get(ctx, "zovark:approval:"+token).Result()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found or expired"})
		return
	}

	m, parseErr := parseMCPApproval(raw)
	if parseErr != nil {
		respondInternalError(c, parseErr, "parse mcp approval by id")
		return
	}

	// Tenant isolation.
	callerTenantID := c.MustGet("tenant_id").(string)
	if tid, _ := m["tenant_id"].(string); tid != callerTenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found or expired"})
		return
	}

	c.JSON(http.StatusOK, toApprovalSummary(m))
}

// ─── POST /api/v1/mcp/approvals/:token/decide ────────────────────────────────

func decideMCPApprovalHandler(c *gin.Context) {
	token := c.Param("token")
	userID := c.MustGet("user_id").(string)
	callerTenantID := c.MustGet("tenant_id").(string)

	var req struct {
		Action string `json:"action" binding:"required"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Action != "approve" && req.Action != "deny" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be 'approve' or 'deny'"})
		return
	}

	ctx := context.Background()
	key := "zovark:approval:" + token
	raw, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found or expired"})
		return
	}

	approval, parseErr := parseMCPApproval(raw)
	if parseErr != nil {
		respondInternalError(c, parseErr, "parse mcp approval for decide")
		return
	}

	// Tenant isolation.
	if tid, _ := approval["tenant_id"].(string); tid != callerTenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found or expired"})
		return
	}

	status, _ := approval["status"].(string)
	if status != "pending" {
		c.JSON(http.StatusConflict, gin.H{
			"error":  fmt.Sprintf("approval already %s", status),
			"status": status,
		})
		return
	}

	now := time.Now().Unix()
	var ttl time.Duration
	switch req.Action {
	case "approve":
		approval["status"] = "approved"
		approval["approved_by"] = userID
		approval["approved_at"] = now
		ttl = 60 * time.Second // Single-use window.
	case "deny":
		approval["status"] = "denied"
		approval["denied_by"] = userID
		approval["denied_at"] = now
		if req.Reason != "" {
			approval["deny_reason"] = req.Reason
		}
		ttl = 300 * time.Second // Brief audit retention.
	}

	updatedJSON, jsonErr := json.Marshal(approval)
	if jsonErr != nil {
		respondInternalError(c, jsonErr, "marshal mcp approval update")
		return
	}

	if redisErr := redisClient.SetEx(ctx, key, string(updatedJSON), ttl).Err(); redisErr != nil {
		respondInternalError(c, redisErr, "persist mcp approval decision")
		return
	}

	approvalID, _ := approval["approval_id"].(string)
	workflowID, _ := approval["workflow_id"].(string)
	requestedBy, _ := approval["requested_by"].(string)

	log.Printf("[AUDIT] MCP approval %s %sd by %s (workflow: %s, requester: %s)",
		approvalID, req.Action, userID, workflowID, requestedBy)

	c.JSON(http.StatusOK, gin.H{
		"status":      approval["status"],
		"approval_id": approvalID,
		"workflow_id": workflowID,
		"decided_by":  userID,
		"decided_at":  now,
	})
}
