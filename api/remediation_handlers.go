package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ── Deterministic remediation rules (mirrors worker/intelligence/remediation.py) ──

var remediationRules = map[string][]remediationRule{
	"brute_force": {
		{ActionType: "block", Description: "Block source IP at perimeter firewall", Priority: 90},
		{ActionType: "access_revoke", Description: "Reset credentials for targeted accounts", Priority: 85},
		{ActionType: "rule_update", Description: "Lower brute-force lockout threshold in SIEM", Priority: 60},
	},
	"phishing_investigation": {
		{ActionType: "block", Description: "Block sender domain and phishing URLs at email gateway", Priority: 90},
		{ActionType: "access_revoke", Description: "Reset credentials for recipients who clicked", Priority: 85},
		{ActionType: "investigate_further", Description: "Check mail logs for other recipients of same campaign", Priority: 70},
	},
	"ransomware_triage": {
		{ActionType: "isolate", Description: "Isolate affected host from network immediately", Priority: 95},
		{ActionType: "block", Description: "Block C2 IPs/domains at firewall", Priority: 90},
		{ActionType: "investigate_further", Description: "Check shadow copy status and lateral movement indicators", Priority: 80},
	},
	"data_exfiltration_detection": {
		{ActionType: "block", Description: "Block destination IPs/domains involved in data transfer", Priority: 90},
		{ActionType: "isolate", Description: "Isolate source host to prevent further exfiltration", Priority: 85},
		{ActionType: "access_revoke", Description: "Revoke cloud storage tokens used for exfil", Priority: 80},
	},
	"privilege_escalation_hunt": {
		{ActionType: "access_revoke", Description: "Revoke escalated privileges and reset account", Priority: 90},
		{ActionType: "config_change", Description: "Harden UAC/sudo configuration on affected host", Priority: 75},
		{ActionType: "investigate_further", Description: "Check for persistence mechanisms installed post-escalation", Priority: 70},
	},
	"c2_communication_hunt": {
		{ActionType: "isolate", Description: "Isolate beaconing host from network", Priority: 95},
		{ActionType: "block", Description: "Block C2 domains/IPs at DNS and firewall", Priority: 90},
		{ActionType: "investigate_further", Description: "Hunt for other hosts beaconing to same C2 infrastructure", Priority: 80},
	},
	"lateral_movement_detection": {
		{ActionType: "isolate", Description: "Isolate compromised host to stop lateral spread", Priority: 95},
		{ActionType: "access_revoke", Description: "Disable compromised service accounts used for movement", Priority: 90},
		{ActionType: "rule_update", Description: "Add detection for observed lateral movement technique", Priority: 65},
	},
	"kerberoasting": {
		{ActionType: "access_revoke", Description: "Reset service account passwords (use 25+ char random)", Priority: 90},
		{ActionType: "config_change", Description: "Migrate SPNs to AES-only (disable RC4)", Priority: 85},
		{ActionType: "rule_update", Description: "Alert on RC4 TGS requests for non-krbtgt SPNs", Priority: 70},
	},
	"golden_ticket": {
		{ActionType: "access_revoke", Description: "Reset krbtgt password TWICE to invalidate forged tickets", Priority: 95},
		{ActionType: "investigate_further", Description: "Audit all domain controller access for last 7 days", Priority: 85},
		{ActionType: "config_change", Description: "Enable Protected Users group for privileged accounts", Priority: 75},
	},
	"dcsync": {
		{ActionType: "access_revoke", Description: "Remove replication rights from compromised account", Priority: 95},
		{ActionType: "access_revoke", Description: "Reset krbtgt and all privileged account passwords", Priority: 90},
		{ActionType: "investigate_further", Description: "Check for persistence via DSRM password or AdminSDHolder", Priority: 80},
	},
	"dns_exfiltration": {
		{ActionType: "block", Description: "Block high-entropy DNS queries to identified exfil domain", Priority: 90},
		{ActionType: "config_change", Description: "Enable DNS query logging and entropy-based alerting", Priority: 75},
		{ActionType: "investigate_further", Description: "Quantify exfiltrated data volume from DNS query logs", Priority: 70},
	},
	"process_injection": {
		{ActionType: "isolate", Description: "Isolate host with active process injection", Priority: 95},
		{ActionType: "investigate_further", Description: "Memory dump target process for payload analysis", Priority: 85},
		{ActionType: "config_change", Description: "Enable Credential Guard to protect lsass", Priority: 75},
	},
	"powershell_obfuscation": {
		{ActionType: "block", Description: "Block encoded PowerShell execution via constrained language mode", Priority: 85},
		{ActionType: "investigate_further", Description: "Decode and analyze obfuscated payload", Priority: 80},
		{ActionType: "config_change", Description: "Enable PowerShell ScriptBlock logging and AMSI", Priority: 70},
	},
}

var defaultRules = []remediationRule{
	{ActionType: "investigate_further", Description: "Conduct deeper investigation into this alert type", Priority: 70},
	{ActionType: "rule_update", Description: "Review and update detection rules for this alert category", Priority: 50},
}

type remediationRule struct {
	ActionType  string `json:"action_type"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
}

// ── POST /api/v1/remediation/suggest ────────────────────────

func suggestRemediationHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	var req struct {
		InvestigationID string `json:"investigation_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Look up investigation + task data
	var taskType, verdict string
	var riskScore int
	var taskOutputRaw []byte
	err := dbPool.QueryRow(ctx, `
		SELECT t.task_type,
		       COALESCE(i.verdict, t.output->>'verdict', 'inconclusive'),
		       COALESCE(i.risk_score, (t.output->>'risk_score')::int, 50),
		       t.output
		FROM agent_tasks t
		LEFT JOIN investigations i ON i.task_id = t.id
		WHERE t.id = $1 AND t.tenant_id = $2
	`, req.InvestigationID, tenantID).Scan(&taskType, &verdict, &riskScore, &taskOutputRaw)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "investigation not found"})
		return
	}

	// Parse IOCs from task output
	var taskOutput struct {
		IOCs []map[string]interface{} `json:"iocs"`
	}
	_ = json.Unmarshal(taskOutputRaw, &taskOutput)
	iocCount := len(taskOutput.IOCs)

	// Apply deterministic rules
	rules, ok := remediationRules[taskType]
	if !ok {
		rules = defaultRules
	}

	// Check historical success rates for this attack type + tenant
	var successRate float64
	_ = dbPool.QueryRow(ctx, `
		SELECT CASE WHEN COUNT(*) = 0 THEN 0.0
		       ELSE COUNT(*) FILTER (WHERE status = 'verified')::float / COUNT(*)::float
		       END
		FROM remediation_actions r
		JOIN agent_tasks t ON r.investigation_id = t.id
		WHERE r.tenant_id = $1 AND t.task_type = $2
	`, tenantID, taskType).Scan(&successRate)

	// Build suggestions with priority adjustment
	suggestions := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		priority := rule.Priority

		if riskScore >= 90 {
			priority = min(100, priority+10)
		} else if riskScore >= 70 {
			priority = min(100, priority+5)
		} else if riskScore < 50 {
			priority = max(10, priority-15)
		}
		if iocCount >= 3 {
			priority = min(100, priority+5)
		}
		// Boost types with high historical success
		if successRate > 0.8 {
			priority = min(100, priority+5)
		}

		suggestions = append(suggestions, map[string]interface{}{
			"action_type":  rule.ActionType,
			"description":  rule.Description,
			"priority":     priority,
			"success_rate": successRate,
		})
	}

	// Insert suggestions into remediation_actions as 'open'
	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin remediation tx")
		return
	}
	defer tx.Rollback(ctx)

	var actionIDs []string
	for _, s := range suggestions {
		var actionID string
		err = tx.QueryRow(ctx, `
			INSERT INTO remediation_actions
			(investigation_id, action_type, description, priority, status, tenant_id)
			VALUES ($1, $2, $3, $4, 'open', $5)
			RETURNING id
		`, req.InvestigationID, s["action_type"], s["description"], s["priority"], tenantID).Scan(&actionID)
		if err != nil {
			respondInternalError(c, err, "insert remediation action")
			return
		}
		actionIDs = append(actionIDs, actionID)
		s["id"] = actionID
	}

	// Audit event (resource_id is UUID, use first action ID)
	meta, _ := json.Marshal(map[string]interface{}{
		"investigation_id": req.InvestigationID,
		"action_count":     len(suggestions),
		"action_ids":       actionIDs,
		"attack_type":      taskType,
	})
	if len(actionIDs) > 0 {
		_, _ = tx.Exec(ctx, `
			INSERT INTO audit_events
			(tenant_id, event_type, actor_type, resource_type, resource_id, metadata)
			VALUES ($1, 'remediation_suggested', 'system', 'remediation_actions', $2, $3)
		`, tenantID, actionIDs[0], string(meta))
	}

	if err := tx.Commit(ctx); err != nil {
		respondInternalError(c, err, "commit remediation suggest")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"investigation_id": req.InvestigationID,
		"attack_type":      taskType,
		"verdict":          verdict,
		"risk_score":       riskScore,
		"suggestions":      suggestions,
	})
}

// ── POST /api/v1/remediation/verify ─────────────────────────

func verifyRemediationHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)
	ctx := c.Request.Context()

	var req struct {
		RemediationID string `json:"remediation_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check kill switch
	var killSwitch string
	err := dbPool.QueryRow(ctx, `
		SELECT COALESCE(config_value, 'false')
		FROM system_configs
		WHERE tenant_id = $1 AND config_key = 'remediation.auto_verify_enabled'
	`, tenantID).Scan(&killSwitch)
	if err != nil || killSwitch != "true" {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "auto-verify is disabled",
			"details": "Set system_configs key 'remediation.auto_verify_enabled' to 'true' to enable",
		})
		return
	}

	// Look up remediation action + original investigation
	var attackType, originalVerdict string
	var originalRisk, verificationAttempts int
	var investigationID string
	var rawLog, sourceIP string
	err = dbPool.QueryRow(ctx, `
		SELECT r.investigation_id, t.task_type,
		       COALESCE(t.output->>'verdict', 'inconclusive'),
		       COALESCE((t.output->>'risk_score')::int, 50),
		       r.verification_attempts,
		       COALESCE(t.input->'siem_event'->>'raw_log', ''),
		       COALESCE(t.input->'siem_event'->>'source_ip', '')
		FROM remediation_actions r
		JOIN agent_tasks t ON r.investigation_id = t.id
		WHERE r.id = $1 AND r.tenant_id = $2
	`, req.RemediationID, tenantID).Scan(
		&investigationID, &attackType, &originalVerdict,
		&originalRisk, &verificationAttempts, &rawLog, &sourceIP,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "remediation action not found"})
		return
	}

	// Circuit breaker: max 3 per type per 24h
	var recentAttempts int
	_ = dbPool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM remediation_actions r
		JOIN agent_tasks t ON r.investigation_id = t.id
		WHERE r.tenant_id = $1
		  AND t.task_type = $2
		  AND r.last_verification_at > NOW() - INTERVAL '24 hours'
		  AND r.verification_attempts > 0
	`, tenantID, attackType).Scan(&recentAttempts)

	if recentAttempts >= 3 {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":   "circuit breaker open",
			"details": fmt.Sprintf("%d/%d verification attempts for %s in 24h", recentAttempts, 3, attackType),
		})
		return
	}

	// Rate limiter: max 10 synthetic per hour per tenant
	var syntheticHour int
	_ = dbPool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM remediation_actions
		WHERE tenant_id = $1
		  AND verification_method = 'synthetic_alert'
		  AND last_verification_at > NOW() - INTERVAL '1 hour'
	`, tenantID).Scan(&syntheticHour)

	if syntheticHour >= 10 {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":   "rate limit exceeded",
			"details": fmt.Sprintf("%d/%d synthetic alerts this hour", syntheticHour, 10),
		})
		return
	}

	// Submit synthetic test alert of same type
	syntheticTraceID := uuid.New().String()
	syntheticInput := map[string]interface{}{
		"prompt":   fmt.Sprintf("Remediation verification for %s", attackType),
		"severity": "high",
		"siem_event": map[string]interface{}{
			"title":     fmt.Sprintf("[VERIFY] %s re-test", attackType),
			"source_ip": sourceIP,
			"raw_log":   rawLog,
			"rule_name": attackType,
		},
	}
	inputJSON, _ := json.Marshal(map[string]interface{}{
		"task_type": attackType,
		"input":     syntheticInput,
	})

	// Create the synthetic task via DB insert (same path as createTaskHandler)
	var syntheticTaskID string
	err = dbPool.QueryRow(ctx, `
		INSERT INTO agent_tasks (task_type, input, severity, tenant_id, trace_id, status)
		VALUES ($1, $2, 'high', $3, $4, 'pending')
		RETURNING id
	`, attackType, string(inputJSON), tenantID, syntheticTraceID).Scan(&syntheticTaskID)
	if err != nil {
		respondInternalError(c, err, "create synthetic task")
		return
	}

	// Update remediation action with verification attempt
	_, err = dbPool.Exec(ctx, `
		UPDATE remediation_actions
		SET verification_attempts = verification_attempts + 1,
		    last_verification_at = NOW(),
		    verification_method = 'synthetic_alert',
		    verification_result = $1,
		    status = 'in_progress'
		WHERE id = $2 AND tenant_id = $3
	`, fmt.Sprintf(`{"synthetic_task_id":"%s","original_risk":%d,"original_verdict":"%s","initiated_by":"%s"}`,
		syntheticTaskID, originalRisk, originalVerdict, userID),
		req.RemediationID, tenantID)
	if err != nil {
		respondInternalError(c, err, "update remediation verification")
		return
	}

	// Audit event
	_, _ = dbPool.Exec(ctx, `
		INSERT INTO audit_events
		(tenant_id, event_type, actor_type, resource_type, resource_id, metadata, trace_id)
		VALUES ($1, 'remediation_verification_started', 'user', 'remediation_actions', $2, $3, $4)
	`, tenantID, req.RemediationID,
		fmt.Sprintf(`{"synthetic_task_id":"%s","attack_type":"%s","user":"%s"}`, syntheticTaskID, attackType, userID),
		syntheticTraceID)

	c.JSON(http.StatusAccepted, gin.H{
		"remediation_id":   req.RemediationID,
		"synthetic_task_id": syntheticTaskID,
		"trace_id":         syntheticTraceID,
		"attack_type":      attackType,
		"original_verdict":  originalVerdict,
		"original_risk":     originalRisk,
		"message":          "Verification started — poll synthetic task for result, then compare verdict",
	})
}

// ── GET /api/v1/remediation/actions ─────────────────────────

func listRemediationActionsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	// Optional filters
	statusFilter := c.DefaultQuery("status", "")
	investigationFilter := c.DefaultQuery("investigation_id", "")

	query := `
		SELECT r.id, r.investigation_id, r.attack_path_id,
		       r.action_type, r.description, r.assigned_to,
		       r.status, r.priority, r.verification_attempts,
		       r.last_verification_at, r.created_at, r.completed_at,
		       r.verified_at, r.verification_method, r.verification_result,
		       t.task_type
		FROM remediation_actions r
		JOIN agent_tasks t ON r.investigation_id = t.id
		WHERE r.tenant_id = $1
	`
	args := []interface{}{tenantID}
	argIdx := 2

	if statusFilter != "" {
		query += fmt.Sprintf(" AND r.status = $%d", argIdx)
		args = append(args, statusFilter)
		argIdx++
	}
	if investigationFilter != "" {
		query += fmt.Sprintf(" AND r.investigation_id = $%d", argIdx)
		args = append(args, investigationFilter)
		argIdx++
	}

	query += " ORDER BY r.priority DESC, r.created_at DESC LIMIT 100"

	rows, err := dbPool.Query(ctx, query, args...)
	if err != nil {
		respondInternalError(c, err, "list remediation actions")
		return
	}
	defer rows.Close()

	var actions []map[string]interface{}
	for rows.Next() {
		var (
			id, investigationID, actionType, description, status, taskType string
			priority, verificationAttempts                                 int
			createdAt                                                      time.Time
			attackPathID, assignedTo, verificationMethod                   *string
			lastVerificationAt, completedAt, verifiedAt                    *time.Time
			verificationResult                                             *string
		)

		if err := rows.Scan(
			&id, &investigationID, &attackPathID,
			&actionType, &description, &assignedTo,
			&status, &priority, &verificationAttempts,
			&lastVerificationAt, &createdAt, &completedAt,
			&verifiedAt, &verificationMethod, &verificationResult,
			&taskType,
		); err != nil {
			log.Printf("Error scanning remediation row: %v", err)
			continue
		}

		action := map[string]interface{}{
			"id":                    id,
			"investigation_id":      investigationID,
			"attack_path_id":        attackPathID,
			"action_type":           actionType,
			"description":           description,
			"assigned_to":           assignedTo,
			"status":                status,
			"priority":              priority,
			"verification_attempts": verificationAttempts,
			"last_verification_at":  lastVerificationAt,
			"created_at":            createdAt,
			"completed_at":          completedAt,
			"verified_at":           verifiedAt,
			"verification_method":   verificationMethod,
			"verification_result":   verificationResult,
			"task_type":             taskType,
		}
		actions = append(actions, action)
	}

	if actions == nil {
		actions = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"actions": actions, "count": len(actions)})
}

// ── PATCH /api/v1/remediation/actions/:id ───────────────────

func updateRemediationActionHandler(c *gin.Context) {
	actionID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)
	ctx := c.Request.Context()

	var req struct {
		Status     *string `json:"status"`
		AssignedTo *string `json:"assigned_to"`
		Priority   *int    `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify action exists and belongs to tenant
	var currentStatus string
	err := dbPool.QueryRow(ctx, `
		SELECT status FROM remediation_actions
		WHERE id = $1 AND tenant_id = $2
	`, actionID, tenantID).Scan(&currentStatus)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "remediation action not found"})
		return
	}

	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin remediation update tx")
		return
	}
	defer tx.Rollback(ctx)

	if req.Status != nil {
		completedClause := ""
		if *req.Status == "completed" || *req.Status == "verified" || *req.Status == "failed" || *req.Status == "wont_fix" {
			completedClause = ", completed_at = NOW()"
		}
		if *req.Status == "verified" {
			completedClause += ", verified_at = NOW()"
		}
		_, err = tx.Exec(ctx, fmt.Sprintf(`
			UPDATE remediation_actions SET status = $1%s WHERE id = $2 AND tenant_id = $3
		`, completedClause), *req.Status, actionID, tenantID)
		if err != nil {
			respondInternalError(c, err, "update remediation status")
			return
		}
	}
	if req.AssignedTo != nil {
		_, _ = tx.Exec(ctx, `
			UPDATE remediation_actions SET assigned_to = $1 WHERE id = $2 AND tenant_id = $3
		`, *req.AssignedTo, actionID, tenantID)
	}
	if req.Priority != nil {
		_, _ = tx.Exec(ctx, `
			UPDATE remediation_actions SET priority = $1 WHERE id = $2 AND tenant_id = $3
		`, *req.Priority, actionID, tenantID)
	}

	// Audit event
	meta, _ := json.Marshal(map[string]interface{}{
		"previous_status": currentStatus,
		"new_status":      req.Status,
		"updated_by":      userID,
	})
	_, _ = tx.Exec(ctx, `
		INSERT INTO audit_events
		(tenant_id, event_type, actor_type, resource_type, resource_id, metadata)
		VALUES ($1, 'remediation_action_updated', 'user', 'remediation_actions', $2, $3)
	`, tenantID, actionID, string(meta))

	if err := tx.Commit(ctx); err != nil {
		respondInternalError(c, err, "commit remediation update")
		return
	}

	c.JSON(http.StatusOK, gin.H{"id": actionID, "status": "updated"})
}

// ── Helpers ─────────────────────────────────────────────────

func actionTypesFromRules(rules []remediationRule) []string {
	types := make([]string, len(rules))
	for i, r := range rules {
		types[i] = r.ActionType
	}
	return types
}

