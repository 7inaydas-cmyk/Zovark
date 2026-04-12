package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.temporal.io/sdk/client"
)

// ============================================================
// SIEM INGEST ENDPOINTS — Splunk HEC + Elastic SIEM
// ============================================================

// mapAlertToTaskType maps a SIEM alert signature/rule name to a ZOVARK task type
// using regex patterns. Falls back to a sanitized version of the signature.
func mapAlertToTaskType(signature string) string {
	sig := strings.ToLower(signature)
	patterns := map[string]string{
		`brute.?force|failed.?password|multiple.?login`:  "brute_force",
		`malware|trojan|ransomware`:                      "ransomware_triage",
		`beacon|c2|command.?and.?control`:                "network_beaconing",
		`phish|credential.?harvest`:                      "phishing",
		`lateral.?movement|pass.?the.?hash|pth`:          "lateral_movement",
		`exfil|large.?transfer|dns.?tunnel`:              "data_exfiltration",
		`privilege.?escalat|sudo|uac`:                    "privilege_escalation",
		`insider|unauthorized.?access`:                   "insider_threat",
		`sql.?inject|xss|cross.?site|command.?inject`:    "web_attack",
		`denial.?of.?service|ddos|dos`:                   "dos_attack",
		`suspicious.?process|fileless|powershell.?abuse`: "endpoint_anomaly",
	}
	for pattern, taskType := range patterns {
		if matched, _ := regexp.MatchString(pattern, sig); matched {
			return taskType
		}
	}
	// Default: sanitize the signature as task_type
	sanitized := strings.ToLower(strings.ReplaceAll(signature, " ", "_"))
	sanitized = regexp.MustCompile(`[^a-z0-9_]`).ReplaceAllString(sanitized, "")
	if sanitized == "" {
		return "log_analysis"
	}
	// Truncate to reasonable length
	if len(sanitized) > 60 {
		sanitized = sanitized[:60]
	}
	return sanitized
}

// createIngestTask is the shared task-creation logic for SIEM ingest endpoints.
// It inserts the task into agent_tasks, commits the transaction, then starts the
// Temporal workflow. Returns (taskID, error).
func createIngestTask(ctx context.Context, tenantID, taskType, prompt, source string, input map[string]interface{}) (string, error) {
	taskID := uuid.New().String()
	traceID := uuid.New().String()

	// Ensure required input fields
	input["prompt"] = prompt
	input["ingest_source"] = source
	input["trace_id"] = traceID

	severity := "medium"
	if s, ok := input["severity"].(string); ok && s != "" {
		severity = s
	}

	// --- Layer 1: Pre-Temporal Redis Dedup ---
	if isDup, existingID := checkPreDedup(ctx, taskType, input); isDup {
		// Insert with deduplicated status for audit trail, but skip workflow
		dbCtx, dbCancel := dbContextWithTimeout(ctx)
		defer dbCancel()
		_, _ = dbPool.Exec(dbCtx,
			"INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at, trace_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
			taskID, tenantID, taskType, input, "deduplicated", time.Now(), traceID,
		)
		log.Printf("[INGEST] Dedup: task %s is duplicate of %s", taskID, existingID)
		return existingID, nil
	}

	// --- Layer 2: Pre-Temporal Batch Buffer ---
	sourceIP := ""
	if se, ok := input["siem_event"].(map[string]interface{}); ok {
		if v, ok := se["source_ip"].(string); ok {
			sourceIP = v
		}
	}
	if v, ok := input["source_ip"].(string); ok && sourceIP == "" {
		sourceIP = v
	}

	destIP := ""
	if se, ok := input["siem_event"].(map[string]interface{}); ok {
		if v, ok := se["destination_ip"].(string); ok {
			destIP = v
		} else if v, ok := se["dest_ip"].(string); ok {
			destIP = v
		}
	}
	if v, ok := input["dest_ip"].(string); ok && destIP == "" {
		destIP = v
	}

	if shouldSkip, batchParentID := tryBatchAlert(ctx, taskType, sourceIP, destIP, severity, taskID); shouldSkip {
		// Insert with batched status for audit trail, but skip workflow
		dbCtx, dbCancel := dbContextWithTimeout(ctx)
		defer dbCancel()
		_, _ = dbPool.Exec(dbCtx,
			"INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at, trace_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
			taskID, tenantID, taskType, input, "batched", time.Now(), traceID,
		)
		log.Printf("[INGEST] Batched: task %s absorbed into batch parent %s", taskID, batchParentID)
		return batchParentID, nil
	}

	// Insert task inside explicit transaction
	// CRITICAL: tx.Commit() MUST happen BEFORE ExecuteWorkflow() to avoid race condition
	dbCtx, dbCancel := dbContextWithTimeout(ctx)
	tx, err := beginTenantTx(dbCtx, tenantID)
	if err != nil {
		dbCancel()
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(dbCtx) // no-op after commit

	_, err = tx.Exec(dbCtx,
		"INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at, trace_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		taskID, tenantID, taskType, input, "pending", time.Now(), traceID,
	)
	if err != nil {
		dbCancel()
		if isLockTimeout(err) {
			HandlePostgresLock(nil, tenantID, taskID, severity, "INSERT", "agent_tasks", 5000)
		}
		return "", fmt.Errorf("failed to create task: %w", err)
	}

	// Audit log (inside same transaction)
	auditDetails, _ := json.Marshal(map[string]string{
		"task_id":       taskID,
		"ingest_source": source,
		"task_type":     taskType,
	})
	_, _ = tx.Exec(dbCtx,
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
		tenantID, "task_created", "task", taskID,
		string(auditDetails),
	)

	// COMMIT — data now visible to all connections (including worker's fetch_task)
	if err := tx.Commit(dbCtx); err != nil {
		dbCancel()
		return "", fmt.Errorf("failed to commit task transaction: %w", err)
	}
	dbCancel()

	// Register dedup hash AFTER commit so subsequent alerts get deduplicated
	registerPreDedup(ctx, taskType, input, taskID, severity)

	// --- Layer 3: Temporal Backpressure ---
	allowed, depth := checkBackpressure(ctx)
	if !allowed {
		if isHardLimitReached(depth) {
			// Hard limit — mark as failed, caller should return 503
			_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
			return "", fmt.Errorf("backpressure hard limit reached (depth=%d)", depth)
		}
		// Soft limit — queue for later processing by drain goroutine
		_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'queued' WHERE id = $1", taskID)
		log.Printf("[INGEST] Backpressure: task %s queued (depth=%d)", taskID, depth)
		return taskID, nil
	}

	// Start Temporal workflow AFTER commit
	workflowOptions := client.StartWorkflowOptions{
		ID:        "task-" + taskID,
		TaskQueue: "zovark-tasks",
	}

	wfStart := time.Now()
	_, err = tc.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, TaskRequest{
		TaskType: taskType,
		Input:    input,
	})
	wfLatency := int(time.Since(wfStart).Milliseconds())
	if err != nil {
		if isTemporalTimeout(err) {
			HandleModelTimeout(ctx, tenantID, taskID, severity, wfLatency, "temporal/llm", "zovark-fast")
		}
		_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
		return "", fmt.Errorf("failed to start workflow: %w", err)
	}

	// Track workflow for backpressure
	recordWorkflowStart(ctx, "task-"+taskID)

	return taskID, nil
}

// ============================================================
// POST /api/v1/ingest/splunk — Splunk HEC format receiver
// ============================================================
//
// Accepts Splunk HTTP Event Collector (HEC) format:
//
//	{
//	  "time": 1234567890,
//	  "event": {"signature": "...", "src_ip": "...", "dest_ip": "...", "user": "...", "raw": "..."},
//	  "sourcetype": "linux:syslog",
//	  "source": "syslog",
//	  "host": "web01"
//	}
func splunkIngestHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var payload struct {
		Time       float64                `json:"time"`
		Event      map[string]interface{} `json:"event"`
		SourceType string                 `json:"sourcetype"`
		Source     string                 `json:"source"`
		Host       string                 `json:"host"`
		Index      string                 `json:"index"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON payload: " + err.Error()})
		return
	}

	if payload.Event == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required field: event"})
		return
	}

	// Extract alert signature for task_type mapping
	signature := ""
	if sig, ok := payload.Event["signature"].(string); ok {
		signature = sig
	} else if sig, ok := payload.Event["alert_name"].(string); ok {
		signature = sig
	} else if sig, ok := payload.Event["name"].(string); ok {
		signature = sig
	} else {
		// Fall back to sourcetype
		signature = payload.SourceType
	}

	taskType := mapAlertToTaskType(sanitizeSIEMField(signature, 200))

	// Extract IPs
	sourceIP := ""
	if v, ok := payload.Event["src_ip"].(string); ok {
		sourceIP = v
	} else if v, ok := payload.Event["source_ip"].(string); ok {
		sourceIP = v
	}
	destIP := ""
	if v, ok := payload.Event["dest_ip"].(string); ok {
		destIP = v
	} else if v, ok := payload.Event["destination_ip"].(string); ok {
		destIP = v
	}

	// Extract severity
	severity := "medium"
	if v, ok := payload.Event["severity"].(string); ok && v != "" {
		severity = v
	}

	// Extract user
	user := ""
	if v, ok := payload.Event["user"].(string); ok {
		user = v
	}

	// Build sanitized prompt
	prompt := fmt.Sprintf(
		"Investigate Splunk alert: %s. Source: %s, Dest: %s. User: %s. Sourcetype: %s. Severity: %s.",
		sanitizeSIEMField(signature, 200),
		sanitizeSIEMField(sourceIP, 45),
		sanitizeSIEMField(destIP, 45),
		sanitizeSIEMField(user, 100),
		sanitizeSIEMField(payload.SourceType, 100),
		sanitizeSIEMField(severity, 20),
	)

	// Build input map for the investigation
	// FIX #5: sanitize all string values in siem_event before storing
	input := map[string]interface{}{
		"severity":    severity,
		"source_ip":   sourceIP,
		"dest_ip":     destIP,
		"user":        user,
		"sourcetype":  payload.SourceType,
		"host":        payload.Host,
		"siem_vendor": "splunk",
		"siem_event":  sanitizeSIEMMap(payload.Event),
	}

	// Include raw event data if present
	if raw, ok := payload.Event["raw"].(string); ok {
		input["log_data"] = sanitizeSIEMField(raw, 10000)
	}

	taskID, err := createIngestTask(c.Request.Context(), tenantID, taskType, prompt, "splunk_hec", input)
	if err != nil {
		log.Printf("[INGEST] Splunk ingest failed for tenant %s: %v", tenantID, err)
		respondInternalError(c, err, "splunk ingest task creation")
		return
	}

	// Set trace ID from input (populated by createIngestTask)
	if tid, ok := input["trace_id"].(string); ok {
		c.Header("X-Zovark-Trace-ID", tid)
	}

	c.JSON(http.StatusOK, gin.H{
		"task_id": taskID,
		"status":  "queued",
		"source":  "splunk_hec",
	})
}

// ============================================================
// POST /api/v1/ingest/elastic — Elastic SIEM alert format
// ============================================================
//
// Accepts Elastic Security alert format:
//
//	{
//	  "rule": {"name": "...", "severity": "...", "id": "...", "description": "..."},
//	  "source": {"ip": "..."},
//	  "destination": {"ip": "..."},
//	  "user": {"name": "..."},
//	  "message": "...",
//	  "host": {"name": "..."},
//	  "event": {"action": "...", "category": "..."}
//	}
func elasticIngestHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var payload map[string]interface{}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON payload: " + err.Error()})
		return
	}

	// Extract rule info
	ruleName := ""
	severity := "medium"
	ruleDescription := ""
	if ruleObj, ok := payload["rule"].(map[string]interface{}); ok {
		if v, ok := ruleObj["name"].(string); ok {
			ruleName = v
		}
		if v, ok := ruleObj["severity"].(string); ok && v != "" {
			severity = v
		}
		if v, ok := ruleObj["description"].(string); ok {
			ruleDescription = v
		}
	}

	if ruleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required field: rule.name"})
		return
	}

	taskType := mapAlertToTaskType(sanitizeSIEMField(ruleName, 200))

	// Extract source/dest IPs (Elastic nests under source.ip / destination.ip)
	sourceIP := ""
	if srcObj, ok := payload["source"].(map[string]interface{}); ok {
		if v, ok := srcObj["ip"].(string); ok {
			sourceIP = v
		}
	}
	destIP := ""
	if dstObj, ok := payload["destination"].(map[string]interface{}); ok {
		if v, ok := dstObj["ip"].(string); ok {
			destIP = v
		}
	}

	// Extract user
	user := ""
	if userObj, ok := payload["user"].(map[string]interface{}); ok {
		if v, ok := userObj["name"].(string); ok {
			user = v
		}
	}

	// Extract host
	host := ""
	if hostObj, ok := payload["host"].(map[string]interface{}); ok {
		if v, ok := hostObj["name"].(string); ok {
			host = v
		}
	}

	// Extract message (raw event context)
	message := ""
	if v, ok := payload["message"].(string); ok {
		message = v
	}

	// Build sanitized prompt
	prompt := fmt.Sprintf(
		"Investigate Elastic SIEM alert: %s. Source: %s, Dest: %s. User: %s. Host: %s. Severity: %s. %s",
		sanitizeSIEMField(ruleName, 200),
		sanitizeSIEMField(sourceIP, 45),
		sanitizeSIEMField(destIP, 45),
		sanitizeSIEMField(user, 100),
		sanitizeSIEMField(host, 100),
		sanitizeSIEMField(severity, 20),
		sanitizeSIEMField(ruleDescription, 300),
	)

	// Build input map
	// FIX #5: sanitize all string values in siem_event before storing
	input := map[string]interface{}{
		"severity":         severity,
		"source_ip":        sourceIP,
		"dest_ip":          destIP,
		"user":             user,
		"host":             host,
		"rule_name":        ruleName,
		"rule_description": ruleDescription,
		"siem_vendor":      "elastic",
		"siem_event":       sanitizeSIEMMap(payload),
	}

	if message != "" {
		input["log_data"] = sanitizeSIEMField(message, 10000)
	}

	taskID, err := createIngestTask(c.Request.Context(), tenantID, taskType, prompt, "elastic_siem", input)
	if err != nil {
		log.Printf("[INGEST] Elastic ingest failed for tenant %s: %v", tenantID, err)
		respondInternalError(c, err, "elastic ingest task creation")
		return
	}

	if tid, ok := input["trace_id"].(string); ok {
		c.Header("X-Zovark-Trace-ID", tid)
	}

	c.JSON(http.StatusOK, gin.H{
		"task_id": taskID,
		"status":  "queued",
		"source":  "elastic_siem",
	})
}

// ============================================================
// GET /api/v1/ingest/health — Connector health check
// ============================================================

func ingestHealthHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Count recent ingested tasks by source
	type sourceCount struct {
		Source string
		Count  int
		Last   *time.Time
	}

	var splunkCount, elasticCount int
	var splunkLast, elasticLast *time.Time

	// Splunk ingest stats
	_ = dbPool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*), MAX(created_at) FROM agent_tasks
		 WHERE tenant_id = $1 AND input->>'ingest_source' = 'splunk_hec'
		 AND created_at > NOW() - INTERVAL '24 hours'`,
		tenantID,
	).Scan(&splunkCount, &splunkLast)

	// Elastic ingest stats
	_ = dbPool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*), MAX(created_at) FROM agent_tasks
		 WHERE tenant_id = $1 AND input->>'ingest_source' = 'elastic_siem'
		 AND created_at > NOW() - INTERVAL '24 hours'`,
		tenantID,
	).Scan(&elasticCount, &elasticLast)

	// Last 5 ingested alerts
	rows, err := dbPool.Query(c.Request.Context(),
		`SELECT id, task_type, status, input->>'ingest_source' AS source, created_at
		 FROM agent_tasks
		 WHERE tenant_id = $1 AND input->>'ingest_source' IS NOT NULL
		 ORDER BY created_at DESC LIMIT 5`,
		tenantID,
	)

	var recentAlerts []map[string]interface{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, taskType, status string
			var source *string
			var createdAt time.Time
			if err := rows.Scan(&id, &taskType, &status, &source, &createdAt); err != nil {
				log.Printf("Error scanning ingest health row: %v", err)
				continue
			}
			recentAlerts = append(recentAlerts, map[string]interface{}{
				"task_id":    id,
				"task_type":  taskType,
				"status":     status,
				"source":     source,
				"created_at": createdAt,
			})
		}
	}

	if recentAlerts == nil {
		recentAlerts = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"connectors": gin.H{
			"splunk_hec": gin.H{
				"endpoint":      "/api/v1/ingest/splunk",
				"alerts_24h":    splunkCount,
				"last_received": splunkLast,
				"status":        connectorStatus(splunkCount, splunkLast),
			},
			"elastic_siem": gin.H{
				"endpoint":      "/api/v1/ingest/elastic",
				"alerts_24h":    elasticCount,
				"last_received": elasticLast,
				"status":        connectorStatus(elasticCount, elasticLast),
			},
		},
		"recent_alerts": recentAlerts,
	})
}

// connectorStatus returns a status string based on recent activity.
func connectorStatus(count24h int, lastReceived *time.Time) string {
	if count24h == 0 {
		return "idle"
	}
	if lastReceived != nil && time.Since(*lastReceived) < 1*time.Hour {
		return "active"
	}
	return "stale"
}
