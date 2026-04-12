package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.temporal.io/sdk/client"
)

// Workflow version toggle — set ZOVARK_WORKFLOW_VERSION=InvestigationWorkflowV2 for V2 pipeline
var workflowName = getWorkflowName()

func getWorkflowName() string {
	if v := os.Getenv("ZOVARK_WORKFLOW_VERSION"); v != "" {
		return v
	}
	return "InvestigationWorkflowV2" // FIX #1: default to V2 pipeline
}

// Types
type TaskRequest struct {
	TaskType string                 `json:"task_type"`
	Input    map[string]interface{} `json:"input" binding:"required"`
}

func createTaskHandler(c *gin.Context) {
	var req TaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. Get tenant_id from authenticated context
	tenantID := c.MustGet("tenant_id").(string)

	// Playbook resolution
	if pid, ok := req.Input["playbook_id"].(string); ok && pid != "" {
		var playbookTaskType string
		var playbookStepsJSON []byte
		var playbookSystemPrompt *string
		err := dbPool.QueryRow(c.Request.Context(),
			"SELECT task_type, steps, system_prompt_override FROM playbooks WHERE id = $1 AND (tenant_id = $2 OR is_template = true)",
			pid, tenantID,
		).Scan(&playbookTaskType, &playbookStepsJSON, &playbookSystemPrompt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or inaccessible playbook_id"})
			return
		}

		var playbookSteps []string
		if err := json.Unmarshal(playbookStepsJSON, &playbookSteps); err == nil {
			req.Input["playbook_steps"] = playbookSteps
			if prompt, hasPrompt := req.Input["prompt"].(string); (!hasPrompt || prompt == "") && len(playbookSteps) > 0 {
				req.Input["prompt"] = playbookSteps[0]
			}
		}

		req.TaskType = playbookTaskType
		if playbookSystemPrompt != nil {
			req.Input["playbook_system_prompt_override"] = *playbookSystemPrompt
		}
	}

	if req.TaskType == "" {
		req.TaskType = "log_analysis"
	}

	// --- ALERT DEDUPLICATION (Sprint 5) ---
	// Compute SHA-256 fingerprint of normalized alert fields
	fpFields := []string{tenantID, req.TaskType}
	if prompt, ok := req.Input["prompt"].(string); ok {
		fpFields = append(fpFields, strings.ToLower(strings.TrimSpace(prompt)))
	}
	if srcIP, ok := req.Input["source_ip"].(string); ok {
		fpFields = append(fpFields, strings.TrimSpace(srcIP))
	}
	if dstIP, ok := req.Input["dest_ip"].(string); ok {
		fpFields = append(fpFields, strings.TrimSpace(dstIP))
	}
	sort.Strings(fpFields[2:]) // Sort fields after tenant_id and task_type
	fpHash := sha256.Sum256([]byte(strings.Join(fpFields, "|")))
	fingerprint := hex.EncodeToString(fpHash[:])

	// Check for existing fingerprint within dedup window
	var existingInvID *string
	var existingCount int
	dedupErr := dbPool.QueryRow(c.Request.Context(),
		`SELECT investigation_id, alert_count FROM alert_fingerprints
		 WHERE tenant_id = $1 AND fingerprint = $2
		 AND last_seen > NOW() - (dedup_window_seconds * interval '1 second')`,
		tenantID, fingerprint,
	).Scan(&existingInvID, &existingCount)

	if dedupErr == nil && existingInvID != nil {
		// Duplicate alert — increment count and return existing
		_, _ = dbPool.Exec(c.Request.Context(),
			`UPDATE alert_fingerprints SET last_seen = NOW(), alert_count = alert_count + 1
			 WHERE tenant_id = $1 AND fingerprint = $2`,
			tenantID, fingerprint,
		)
		c.JSON(http.StatusOK, gin.H{
			"status":           "deduplicated",
			"investigation_id": *existingInvID,
			"alert_count":      existingCount + 1,
			"fingerprint":      fingerprint,
		})
		return
	}

	// --- Force reinvestigate bypass (analyst-triggered) ---
	forceReinvestigate := false
	if v, ok := req.Input["force_reinvestigate"]; ok {
		forceReinvestigate = v == true || v == "true"
	}
	if forceReinvestigate {
		log.Printf("[DEDUP] Force reinvestigate bypass for task_type=%s", req.TaskType)
		clearDedupEntry(c.Request.Context(), req.Input)
	}

	// --- Layer 1: Pre-Temporal Redis Dedup (fast path before DB dedup) ---
	if !forceReinvestigate {
		if isDup, existingID := checkPreDedup(c.Request.Context(), req.TaskType, req.Input); isDup {
			// Increment dedup counter on the original task
			var dedupCount int
			_ = dbPool.QueryRow(c.Request.Context(),
				`UPDATE agent_tasks SET dedup_count = COALESCE(dedup_count, 0) + 1 WHERE id = $1 RETURNING dedup_count`,
				existingID,
			).Scan(&dedupCount)
			c.JSON(http.StatusOK, gin.H{
				"status":           "deduplicated",
				"existing_task_id": existingID,
				"dedup_layer":      "api_redis",
				"dedup_count":      dedupCount,
			})
			return
		}
	}

	// --- Layer 2: Pre-Temporal Batch Buffer ---
	sourceIP := ""
	if se, ok := req.Input["siem_event"].(map[string]interface{}); ok {
		if v, ok := se["source_ip"].(string); ok {
			sourceIP = v
		}
	}
	if v, ok := req.Input["source_ip"].(string); ok && sourceIP == "" {
		sourceIP = v
	}

	destIP := ""
	if se, ok := req.Input["siem_event"].(map[string]interface{}); ok {
		if v, ok := se["destination_ip"].(string); ok {
			destIP = v
		} else if v, ok := se["dest_ip"].(string); ok {
			destIP = v
		}
	}
	if v, ok := req.Input["dest_ip"].(string); ok && destIP == "" {
		destIP = v
	}

	severity := extractPriority(req.Input)
	taskID := uuid.New().String()

	if shouldSkip, batchParentID := tryBatchAlert(c.Request.Context(), req.TaskType, sourceIP, destIP, severity, taskID); shouldSkip {
		c.JSON(http.StatusOK, gin.H{
			"status":          "batched",
			"batch_parent_id": batchParentID,
			"task_id":         taskID,
		})
		return
	}

	// 2. Generate trace ID
	traceID := uuid.New().String()
	c.Header("X-Zovark-Trace-ID", traceID)

	// Insert new fingerprint record (investigation_id will be updated later)
	rawSample, _ := json.Marshal(req.Input)
	_, _ = dbPool.Exec(c.Request.Context(),
		`INSERT INTO alert_fingerprints (tenant_id, fingerprint, alert_type, raw_sample)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT DO NOTHING`,
		tenantID, fingerprint, req.TaskType, rawSample,
	)

	// 3. Insert into agent_tasks inside explicit transaction
	// CRITICAL: tx.Commit() MUST happen BEFORE ExecuteWorkflow() to avoid
	// race condition where the worker's fetch_task can't find the row.
	priority := severity
	dbCtx, dbCancel := dbContextWithTimeout(c.Request.Context())
	defer dbCancel()

	tx, err := beginTenantTx(dbCtx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin task transaction")
		return
	}
	defer tx.Rollback(dbCtx) // no-op after commit

	_, err = tx.Exec(dbCtx,
		"INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at, trace_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		taskID, tenantID, req.TaskType, req.Input, "pending", time.Now(), traceID,
	)
	if err != nil {
		if isLockTimeout(err) {
			HandlePostgresLock(c, tenantID, taskID, priority, "INSERT", "agent_tasks", 5000)
			return
		}
		respondInternalError(c, err, "create task record")
		return
	}

	// 4. Log to agent_audit_log (inside same transaction)
	_, _ = tx.Exec(dbCtx,
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id) VALUES ($1, $2, $3, $4)",
		tenantID, "task_created", "task", taskID,
	)

	// 5. COMMIT — data now visible to all connections (including worker's fetch_task)
	if err := tx.Commit(dbCtx); err != nil {
		respondInternalError(c, err, "commit task transaction")
		return
	}

	// Register dedup hash after commit
	registerPreDedup(c.Request.Context(), req.TaskType, req.Input, taskID, severity)

	// --- Layer 3: Temporal Backpressure ---
	allowed, depth := checkBackpressure(c.Request.Context())
	if !allowed {
		if isHardLimitReached(depth) {
			_, _ = dbPool.Exec(c.Request.Context(), "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":       "system at capacity, please retry",
				"retry_after": 30,
			})
			c.Header("Retry-After", "30")
			return
		}
		// Soft limit — queue for drain goroutine
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE agent_tasks SET status = 'queued' WHERE id = $1", taskID)
		c.JSON(http.StatusAccepted, gin.H{
			"task_id":  taskID,
			"status":   "queued",
			"trace_id": traceID,
		})
		return
	}

	// 6. Start Temporal Workflow AFTER commit (with timeout detection for model failover)
	workflowOptions := client.StartWorkflowOptions{
		ID:        "task-" + taskID,
		TaskQueue: "zovark-tasks",
	}

	wfStart := time.Now()
	we, err := tc.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, req)
	wfLatency := int(time.Since(wfStart).Milliseconds())

	if err != nil {
		if isTemporalTimeout(err) {
			fallbackModel := HandleModelTimeout(c.Request.Context(), tenantID, taskID, priority,
				wfLatency, "temporal/llm", "zovark-fast")
			log.Printf("Model timeout on task %s, fallback to %s", taskID, fallbackModel)
		}
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
		respondInternalError(c, err, "start workflow")
		return
	}

	// Track workflow for backpressure
	recordWorkflowStart(c.Request.Context(), "task-"+taskID)

	c.JSON(http.StatusAccepted, gin.H{
		"task_id":     taskID,
		"workflow_id": we.GetID(),
		"status":      "pending",
		"trace_id":    traceID,
	})
}

func getTaskHandler(c *gin.Context) {
	taskID := c.Param("id")

	var status, taskType string
	var input, output map[string]interface{}
	var createdAt, completedAt *time.Time
	var tokensInput, tokensOutput *int
	var executionMs *int
	var severity *string

	tenantID := c.MustGet("tenant_id").(string)

	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT status, task_type, input, output, created_at, completed_at, tokens_used_input, tokens_used_output, execution_ms, severity FROM agent_tasks WHERE id = $1 AND tenant_id = $2", taskID, tenantID,
	).Scan(&status, &taskType, &input, &output, &createdAt, &completedAt, &tokensInput, &tokensOutput, &executionMs, &severity)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	// Get step count and current step
	var stepCount int
	var currentStep *int
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*), MAX(step_number) FROM agent_task_steps WHERE task_id = $1", taskID,
	).Scan(&stepCount, &currentStep)

	// Get pending approval info
	var approvalStatus *string
	var pendingApprovalID *string
	var approvalRiskLevel *string
	var approvalReason *string
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT id, status, risk_level, action_summary FROM approval_requests WHERE task_id = $1 ORDER BY requested_at DESC LIMIT 1", taskID,
	).Scan(&pendingApprovalID, &approvalStatus, &approvalRiskLevel, &approvalReason)

	c.JSON(http.StatusOK, gin.H{
		"task_id":             taskID,
		"status":              status,
		"task_type":           taskType,
		"input":               input,
		"output":              output,
		"created_at":          createdAt,
		"completed_at":        completedAt,
		"tokens_used_input":   tokensInput,
		"tokens_used_output":  tokensOutput,
		"execution_ms":        executionMs,
		"severity":            severity,
		"step_count":          stepCount,
		"current_step":        currentStep,
		"approval_status":     approvalStatus,
		"pending_approval_id": pendingApprovalID,
		"approval_risk_level": approvalRiskLevel,
		"approval_reason":     approvalReason,
	})
}

func listTasksHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Parse query params
	search := c.Query("search")
	status := c.Query("status")
	severity := c.Query("severity")
	taskType := c.Query("task_type")
	dateFrom := c.Query("date_from")
	dateTo := c.Query("date_to")
	sortField := c.DefaultQuery("sort", "created_at")
	sortOrder := c.DefaultQuery("order", "desc")
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "20")

	page := 1
	limit := 20
	if v, err := fmt.Sscanf(pageStr, "%d", &page); v == 0 || err != nil || page < 1 {
		page = 1
	}
	if v, err := fmt.Sscanf(limitStr, "%d", &limit); v == 0 || err != nil || limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	// Whitelist sort fields
	allowedSorts := map[string]string{
		"created_at": "created_at",
		"status":     "status",
		"severity":   "task_type", // proxy sort
	}
	sortCol, ok := allowedSorts[sortField]
	if !ok {
		sortCol = "created_at"
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	// Build WHERE clauses
	where := "WHERE tenant_id = $1"
	args := []interface{}{tenantID}
	argN := 2

	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argN)
		args = append(args, status)
		argN++
	}
	if taskType != "" {
		where += fmt.Sprintf(" AND task_type = $%d", argN)
		args = append(args, taskType)
		argN++
	}
	if severity != "" {
		where += fmt.Sprintf(" AND input->>'severity' = $%d", argN)
		args = append(args, severity)
		argN++
	}
	if dateFrom != "" {
		where += fmt.Sprintf(" AND created_at >= $%d", argN)
		args = append(args, dateFrom)
		argN++
	}
	if dateTo != "" {
		where += fmt.Sprintf(" AND created_at <= ($%d::date + interval '1 day')", argN)
		args = append(args, dateTo)
		argN++
	}
	if search != "" {
		where += fmt.Sprintf(" AND (input->>'prompt' ILIKE $%d OR task_type ILIKE $%d)", argN, argN)
		args = append(args, "%"+search+"%")
		argN++
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM agent_tasks " + where
	err := dbPool.QueryRow(c.Request.Context(), countQuery, args...).Scan(&total)
	if err != nil {
		respondInternalError(c, err, "count tasks")
		return
	}

	// Fetch page
	dataArgs := make([]interface{}, len(args))
	copy(dataArgs, args)
	dataArgs = append(dataArgs, limit, offset)

	query := fmt.Sprintf(
		"SELECT id, status, COALESCE(task_type, 'code_gen'), created_at, execution_ms, input->>'prompt', output->>'verdict', (output->>'risk_score')::int, COALESCE(path_taken, '') FROM agent_tasks %s ORDER BY %s %s LIMIT $%d OFFSET $%d",
		where, sortCol, sortOrder, argN, argN+1,
	)

	rows, err := dbPool.Query(c.Request.Context(), query, dataArgs...)
	if err != nil {
		respondInternalError(c, err, "query tasks")
		return
	}
	defer rows.Close()

	var tasks []map[string]interface{}
	for rows.Next() {
		var id, statusVal, taskTypeVal string
		var createdAt time.Time
		var executionMs *int
		var prompt, verdict *string
		var riskScore *int
		var pathTaken string

		if err := rows.Scan(&id, &statusVal, &taskTypeVal, &createdAt, &executionMs, &prompt, &verdict, &riskScore, &pathTaken); err != nil {
			log.Printf("Error scanning task row: %v", err)
			continue
		}

		task := map[string]interface{}{
			"id":           id,
			"status":       statusVal,
			"task_type":    taskTypeVal,
			"created_at":   createdAt,
			"execution_ms": executionMs,
			"prompt":       prompt,
			"verdict":      verdict,
			"risk_score":   riskScore,
			"path_taken":   pathTaken,
		}
		tasks = append(tasks, task)
	}

	if tasks == nil {
		tasks = []map[string]interface{}{}
	}

	pages := (total + limit - 1) / limit

	c.JSON(http.StatusOK, gin.H{
		"tasks": tasks,
		"total": total,
		"page":  page,
		"limit": limit,
		"pages": pages,
	})
}

func getTaskAuditHandler(c *gin.Context) {
	taskID := c.Param("id")

	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT action, created_at, details FROM agent_audit_log WHERE resource_id = $1 AND tenant_id = $2 ORDER BY created_at ASC", taskID, tenantID)
	if err != nil {
		respondInternalError(c, err, "query task audit log")
		return
	}
	defer rows.Close()

	var audits []map[string]interface{}
	for rows.Next() {
		var action string
		var timestamp time.Time
		var details map[string]interface{}

		if err := rows.Scan(&action, &timestamp, &details); err != nil {
			respondInternalError(c, err, "parse task audit log row")
			return
		}

		audit := map[string]interface{}{
			"action":    action,
			"timestamp": timestamp,
			"details":   details,
		}
		audits = append(audits, audit)
	}

	if audits == nil {
		audits = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"audit_trail": audits})
}

func uploadTaskHandler(c *gin.Context) {
	const maxFileSize = 10 << 20 // 10MB
	const maxLogData = 50 * 1024 // 50KB for LLM context

	allowedExts := map[string]bool{".csv": true, ".json": true, ".txt": true, ".log": true}

	// Parse multipart form
	if err := c.Request.ParseMultipartForm(maxFileSize); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("File too large or bad form: %v", err)})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File field 'file' is required"})
		return
	}
	defer file.Close()

	// Validate extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !allowedExts[ext] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Allowed: .csv, .json, .txt, .log"})
		return
	}

	// Validate size
	if header.Size > int64(maxFileSize) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File exceeds 10MB limit"})
		return
	}

	// Read file content (cap at 50KB)
	readSize := header.Size
	if readSize > int64(maxLogData) {
		readSize = int64(maxLogData)
	}
	buf := make([]byte, readSize)
	n, err := io.ReadFull(file, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		respondInternalError(c, err, "read uploaded file")
		return
	}
	logData := string(buf[:n])

	// Get optional form fields
	taskType := c.PostForm("task_type")
	if taskType == "" {
		taskType = "Log Analysis"
	}
	prompt := c.PostForm("prompt")
	if prompt == "" {
		prompt = "Analyze this log file for security anomalies and threats"
	}

	// Get tenant_id from JWT
	tenantID := c.MustGet("tenant_id").(string)

	// Build input JSON
	inputMap := map[string]interface{}{
		"prompt":    prompt,
		"log_data":  logData,
		"filename":  header.Filename,
		"file_size": header.Size,
	}

	inputJSON, err := json.Marshal(inputMap)
	if err != nil {
		respondInternalError(c, err, "serialize upload task input")
		return
	}

	// Generate task ID
	taskID := uuid.New().String()

	// Insert into agent_tasks inside explicit transaction
	// CRITICAL: tx.Commit() MUST happen BEFORE ExecuteWorkflow() to avoid race condition
	// FIX RLS-001: use beginTenantTx so SET LOCAL app.current_tenant is applied before any INSERT
	dbCtx, dbCancel := dbContextWithTimeout(c.Request.Context())
	defer dbCancel()

	tx, err := beginTenantTx(dbCtx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin upload task transaction")
		return
	}
	defer tx.Rollback(dbCtx) // no-op after commit

	_, err = tx.Exec(dbCtx,
		"INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
		taskID, tenantID, taskType, inputJSON, "pending", time.Now(),
	)
	if err != nil {
		respondInternalError(c, err, "create upload task record")
		return
	}

	// Audit log (inside same transaction)
	_, _ = tx.Exec(dbCtx,
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id) VALUES ($1, $2, $3, $4)",
		tenantID, "task_created", "task", taskID,
	)

	// COMMIT — data now visible to all connections (including worker's fetch_task)
	if err := tx.Commit(dbCtx); err != nil {
		respondInternalError(c, err, "commit upload task transaction")
		return
	}

	// Start Temporal workflow AFTER commit
	workflowOptions := client.StartWorkflowOptions{
		ID:        "task-" + taskID,
		TaskQueue: "zovark-tasks",
	}

	req := TaskRequest{
		TaskType: taskType,
		Input:    inputMap,
	}

	we, err := tc.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, req)
	if err != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
		respondInternalError(c, err, "start upload workflow")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"task_id":     taskID,
		"workflow_id": we.GetID(),
		"status":      "pending",
		"filename":    header.Filename,
		"file_size":   header.Size,
	})
}

func getTaskStepsHandler(c *gin.Context) {
	taskID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	// Verify the task belongs to this tenant
	var exists bool
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM agent_tasks WHERE id = $1 AND tenant_id = $2)", taskID, tenantID,
	).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, step_number, step_type, prompt, generated_code, output, status, tokens_used_input, tokens_used_output, execution_ms, created_at, completed_at, execution_mode, parameters_used FROM investigation_steps WHERE task_id = $1 ORDER BY step_number ASC", taskID)
	if err != nil {
		respondInternalError(c, err, "query task steps")
		return
	}
	defer rows.Close()

	var steps []map[string]interface{}
	for rows.Next() {
		var stepID, stepType, prompt, status string
		var stepNumber, tokensIn, tokensOut int
		var generatedCode, output *string
		var executionMs *int
		var createdAt time.Time
		var completedAt *time.Time
		var executionMode *string
		var parametersUsed *string

		if err := rows.Scan(&stepID, &stepNumber, &stepType, &prompt, &generatedCode, &output, &status, &tokensIn, &tokensOut, &executionMs, &createdAt, &completedAt, &executionMode, &parametersUsed); err != nil {
			log.Printf("Error scanning step row: %v", err)
			continue
		}

		// Handle parameter deserialization safely
		var parsedParams map[string]interface{}
		if parametersUsed != nil {
			_ = json.Unmarshal([]byte(*parametersUsed), &parsedParams)
		}

		step := map[string]interface{}{
			"id":                 stepID,
			"step_number":        stepNumber,
			"step_type":          stepType,
			"prompt":             prompt,
			"generated_code":     generatedCode,
			"output":             output,
			"status":             status,
			"tokens_used_input":  tokensIn,
			"tokens_used_output": tokensOut,
			"execution_ms":       executionMs,
			"created_at":         createdAt,
			"completed_at":       completedAt,
			"execution_mode":     executionMode,
			"parameters_used":    parsedParams,
		}
		steps = append(steps, step)
	}

	if steps == nil {
		steps = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"steps": steps})
}

func getTaskTimelineHandler(c *gin.Context) {
	taskID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	var timeline []map[string]interface{}

	// 1. Fetch task creation and completion info
	var createdAt, completedAt *time.Time
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT created_at, completed_at FROM agent_tasks WHERE id = $1 AND tenant_id = $2", taskID, tenantID,
	).Scan(&createdAt, &completedAt)
	if err == nil && createdAt != nil {
		timeline = append(timeline, map[string]interface{}{
			"id":          "task-created",
			"timestamp":   *createdAt,
			"type":        "task_created",
			"icon":        "created",
			"description": "Investigation created",
		})
	}
	if err == nil && completedAt != nil {
		timeline = append(timeline, map[string]interface{}{
			"id":          "task-completed",
			"timestamp":   *completedAt,
			"type":        "task_completed",
			"icon":        "check",
			"description": "Investigation completed",
		})
	}

	// 2. Fetch steps
	stepRows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, step_number, step_type, summary_prompt, status, execution_ms, created_at
		FROM investigation_steps WHERE task_id = $1 ORDER BY created_at ASC
	`, taskID)
	if err == nil {
		defer stepRows.Close()
		for stepRows.Next() {
			var id, stepType, status string
			var stepNum int
			var prompt *string
			var execMs *int
			var ts time.Time
			stepRows.Scan(&id, &stepNum, &stepType, &prompt, &status, &execMs, &ts)

			desc := fmt.Sprintf("Step %d started: %s", stepNum, stepType)
			if prompt != nil && *prompt != "" {
				desc = fmt.Sprintf("Step %d started: %s", stepNum, *prompt)
			}

			timeline = append(timeline, map[string]interface{}{
				"id":          fmt.Sprintf("step-start-%s", id),
				"timestamp":   ts,
				"type":        "step_started",
				"icon":        "play",
				"description": desc,
			})

			if status == "completed" && execMs != nil {
				endTs := ts.Add(time.Duration(*execMs) * time.Millisecond)
				timeline = append(timeline, map[string]interface{}{
					"id":          fmt.Sprintf("step-end-%s", id),
					"timestamp":   endTs,
					"type":        "step_completed",
					"icon":        "check",
					"description": fmt.Sprintf("Step %d completed", stepNum),
					"duration_ms": *execMs,
				})
			} else if status == "failed" {
				timeline = append(timeline, map[string]interface{}{
					"id":          fmt.Sprintf("step-fail-%s", id),
					"timestamp":   ts,
					"type":        "step_failed",
					"icon":        "error",
					"description": fmt.Sprintf("Step %d failed", stepNum),
				})
			}
		}
	}

	// 3. Fetch audit logs (approvals, memory, skills)
	auditRows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, action, details, created_at
		FROM agent_audit_log WHERE tenant_id = $1 AND resource_type = 'task' AND resource_id = $2
	`, tenantID, taskID)
	if err == nil {
		defer auditRows.Close()
		for auditRows.Next() {
			var id, action string
			var details map[string]interface{}
			var ts time.Time
			auditRows.Scan(&id, &action, &details, &ts)

			// Only include specific actions in timeline
			if action == "approval_requested" || action == "approval_approved" || action == "approval_rejected" {
				desc := "Approval requested"
				icon := "alert"
				if action == "approval_approved" {
					desc = "Approval granted"
					icon = "check"
				} else if action == "approval_rejected" {
					desc = "Approval rejected"
					icon = "error"
				}
				if comment, ok := details["comment"].(string); ok {
					desc += fmt.Sprintf(": %s", comment)
				}
				timeline = append(timeline, map[string]interface{}{
					"id":          fmt.Sprintf("audit-%s", id),
					"timestamp":   ts,
					"type":        action,
					"icon":        icon,
					"description": desc,
				})
			} else if action == "skill_retrieved" {
				skillName := "unknown skill"
				if sn, ok := details["skill_name"].(string); ok {
					skillName = sn
				}
				timeline = append(timeline, map[string]interface{}{
					"id":          fmt.Sprintf("audit-%s", id),
					"timestamp":   ts,
					"type":        action,
					"icon":        "tool",
					"description": fmt.Sprintf("Retrieved skill: %s", skillName),
				})
			}
		}
	}

	if timeline == nil {
		timeline = []map[string]interface{}{}
	} else {
		sort.Slice(timeline, func(i, j int) bool {
			return timeline[i]["timestamp"].(time.Time).Before(timeline[j]["timestamp"].(time.Time))
		})
	}

	c.JSON(http.StatusOK, gin.H{"timeline": timeline})
}

// ============================================================
// BULK TASK CREATION (Issue #12)
// ============================================================

// BulkTaskRequest represents a single task in a bulk creation request.
type BulkTaskRequest struct {
	TaskType string                 `json:"task_type"`
	Input    map[string]interface{} `json:"input" binding:"required"`
}

// bulkCreateTasksHandler creates multiple tasks in a single request.
// POST /api/v1/tasks/bulk
func bulkCreateTasksHandler(c *gin.Context) {
	var req struct {
		Tasks []BulkTaskRequest `json:"tasks" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.Tasks) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one task is required"})
		return
	}
	if len(req.Tasks) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "maximum 50 tasks per bulk request"})
		return
	}

	tenantID := c.MustGet("tenant_id").(string)

	// Validate all tasks first
	for i, task := range req.Tasks {
		if task.Input == nil || len(task.Input) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("task %d: input is required", i)})
			return
		}
		if task.TaskType == "" {
			req.Tasks[i].TaskType = "log_analysis"
		}
	}

	// Create all tasks in a transaction
	// FIX RLS-001: use beginTenantTx so SET LOCAL app.current_tenant is applied before any INSERT
	ctx := c.Request.Context()
	dbCtx, dbCancel := dbContextWithTimeout(ctx)
	defer dbCancel()

	tx, err := beginTenantTx(dbCtx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin bulk task transaction")
		return
	}
	defer tx.Rollback(dbCtx)

	var taskIDs []string
	var workflowIDs []string

	for _, task := range req.Tasks {
		taskID := uuid.New().String()
		taskIDs = append(taskIDs, taskID)

		_, err := tx.Exec(dbCtx,
			"INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
			taskID, tenantID, task.TaskType, task.Input, "pending", time.Now(),
		)
		if err != nil {
			respondInternalError(c, err, "bulk create task")
			return
		}

		// Audit log
		_, _ = tx.Exec(dbCtx,
			"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id) VALUES ($1, $2, $3, $4)",
			tenantID, "task_created", "task", taskID,
		)
	}

	if err := tx.Commit(dbCtx); err != nil {
		respondInternalError(c, err, "commit bulk task transaction")
		return
	}

	// Start workflows for all tasks (outside transaction)
	for i, task := range req.Tasks {
		taskID := taskIDs[i]
		workflowOptions := client.StartWorkflowOptions{
			ID:        "task-" + taskID,
			TaskQueue: "zovark-tasks",
		}

		we, err := tc.ExecuteWorkflow(context.Background(), workflowOptions, workflowName,
			TaskRequest{TaskType: task.TaskType, Input: task.Input})
		if err != nil {
			log.Printf("Failed to start workflow for bulk task %s: %v", taskID, err)
			_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
			workflowIDs = append(workflowIDs, "")
			continue
		}
		workflowIDs = append(workflowIDs, we.GetID())
	}

	// Build response
	var results []map[string]interface{}
	for i, taskID := range taskIDs {
		wfID := ""
		if i < len(workflowIDs) {
			wfID = workflowIDs[i]
		}
		status := "pending"
		if wfID == "" {
			status = "failed"
		}
		results = append(results, map[string]interface{}{
			"task_id":     taskID,
			"workflow_id": wfID,
			"status":      status,
		})
	}

	c.JSON(http.StatusCreated, gin.H{
		"tasks":   results,
		"created": len(taskIDs),
	})
}
