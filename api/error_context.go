package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// FAILURE MODE CONSTANTS
// ============================================================

const (
	FailureModelTimeout      = "model_timeout"
	FailureTelemetryDenied   = "telemetry_access_denied"
	FailureSchemaValidation  = "schema_validation_error"
	FailurePostgresLock      = "postgres_lock"
	StatusBlockedCredentials = "blocked_credentials"
)

// ============================================================
// STRUCTURED FAILURE CONTEXT
// ============================================================

// FailureContext captures enriched error context for investigation failures.
type FailureContext struct {
	FailureMode    string                 `json:"failure_mode"`
	MSSPID         string                 `json:"mssp_id"`
	AlertID        string                 `json:"alert_id"`
	AlertPriority  string                 `json:"alert_priority"`
	Details        map[string]interface{} `json:"details"`
	RecoveryAction string                 `json:"recovery_action"`
	Recovered      bool                   `json:"recovered"`
}

// logFailureContext writes a structured audit event and emits a structured log line.
func logFailureContext(ctx context.Context, fc FailureContext) {
	metadata, _ := json.Marshal(fc)

	_, err := dbPool.Exec(ctx,
		`INSERT INTO audit_events (tenant_id, event_type, actor_type, resource_type, resource_id, metadata)
		 VALUES ($1, $2, 'system', 'task', $3::uuid, $4)`,
		fc.MSSPID, fc.FailureMode, fc.AlertID, metadata,
	)
	if err != nil {
		log.Printf("[FAILURE_CONTEXT] audit insert failed for %s task=%s: %v", fc.FailureMode, fc.AlertID, err)
	}

	log.Printf("[FAILURE_CONTEXT] mode=%s mssp_id=%s alert_id=%s priority=%s recovered=%v action=%s",
		fc.FailureMode, fc.MSSPID, fc.AlertID, fc.AlertPriority, fc.Recovered, fc.RecoveryAction)
}

// ============================================================
// MODE 1: MODEL LATENCY / TIMEOUT
// ============================================================

// HandleModelTimeout logs a model timeout and records the fallback in usage_records.
// Returns the fallback model name for the caller to use.
func HandleModelTimeout(ctx context.Context, tenantID, taskID, priority string, latencyMs int, modelProvider, tierAttempted string) string {
	fc := FailureContext{
		FailureMode:   FailureModelTimeout,
		MSSPID:        tenantID,
		AlertID:       taskID,
		AlertPriority: priority,
		Details: map[string]interface{}{
			"model_provider": modelProvider,
			"latency_ms":     latencyMs,
			"tier_attempted": tierAttempted,
		},
		RecoveryAction: "failover_to_local_vllm",
		Recovered:      true,
	}
	logFailureContext(ctx, fc)

	fallbackMeta, _ := json.Marshal(map[string]interface{}{
		"fallback":          true,
		"original_provider": modelProvider,
		"original_tier":     tierAttempted,
		"timeout_ms":        latencyMs,
	})
	_, _ = dbPool.Exec(ctx,
		`INSERT INTO usage_records (tenant_id, task_id, record_type, model_name, metadata)
		 VALUES ($1, $2, 'llm_call', 'gemma-4-e4b-it', $3)`,
		tenantID, taskID, fallbackMeta,
	)

	return "gemma-4-e4b-it"
}

// ============================================================
// MODE 2: TELEMETRY ACCESS DENIED
// ============================================================

// HandleTelemetryAccessDenied logs a credential failure, marks the task blocked,
// and dispatches a webhook alert for credential rotation.
func HandleTelemetryAccessDenied(ctx context.Context, tenantID, taskID, priority string, siemEndpoint string, httpStatus int, tokenExpiry string) {
	fc := FailureContext{
		FailureMode:   FailureTelemetryDenied,
		MSSPID:        tenantID,
		AlertID:       taskID,
		AlertPriority: priority,
		Details: map[string]interface{}{
			"siem_endpoint":       siemEndpoint,
			"http_status":         httpStatus,
			"client_token_expiry": tokenExpiry,
		},
		RecoveryAction: "webhook_credential_rotation_alert",
		Recovered:      false,
	}
	logFailureContext(ctx, fc)

	_, _ = dbPool.Exec(ctx,
		`UPDATE agent_tasks SET status = 'blocked_credentials',
		 error_message = $1 WHERE id = $2`,
		fmt.Sprintf("Telemetry access denied: %s returned HTTP %d. Credentials need rotation (expiry: %s).",
			siemEndpoint, httpStatus, tokenExpiry),
		taskID,
	)

	// Fire webhook to MSSP for credential rotation via existing delivery engine
	go DispatchWebhook(tenantID, "credential_rotation_required", map[string]interface{}{
		"task_id":       taskID,
		"siem_endpoint": siemEndpoint,
		"http_status":   httpStatus,
		"token_expiry":  tokenExpiry,
		"message":       "SIEM credentials need rotation. Investigation blocked until resolved.",
	})
}

// ============================================================
// MODE 3: SCHEMA VALIDATION ERROR
// ============================================================

// HandleSchemaValidationError logs a schema validation failure.
// The caller (worker) is responsible for the reasoning-tier retry.
func HandleSchemaValidationError(ctx context.Context, tenantID, taskID, priority string, rawOutput string, targetSchema string, alertType string, validationErrors []string) {
	snippet := rawOutput
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	fc := FailureContext{
		FailureMode:   FailureSchemaValidation,
		MSSPID:        tenantID,
		AlertID:       taskID,
		AlertPriority: priority,
		Details: map[string]interface{}{
			"raw_llm_output_snippet": snippet,
			"target_schema":          targetSchema,
			"alert_type":             alertType,
			"validation_errors":      validationErrors,
		},
		RecoveryAction: "reroute_reasoning_tier_json_repair",
		Recovered:      false,
	}
	logFailureContext(ctx, fc)
}

// ============================================================
// MODE 4: POSTGRESQL LOCK (5s limit)
// ============================================================

// HandlePostgresLock logs a database lock timeout and sends a 503 with Retry-After.
// If c is nil (called from background context), only logs without sending HTTP response.
func HandlePostgresLock(c *gin.Context, tenantID, taskID, priority string, queryType, tableName string, lockWaitMs int) {
	var activeTransactions int
	_ = dbPool.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND datname = 'zovark'`,
	).Scan(&activeTransactions)

	fc := FailureContext{
		FailureMode:   FailurePostgresLock,
		MSSPID:        tenantID,
		AlertID:       taskID,
		AlertPriority: priority,
		Details: map[string]interface{}{
			"query_type":          queryType,
			"table_name":          tableName,
			"lock_wait_ms":        lockWaitMs,
			"active_transactions": activeTransactions,
		},
		RecoveryAction: "cancel_query_revert_to_memory",
		Recovered:      false,
	}
	logFailureContext(context.Background(), fc)

	if c != nil {
		c.Header("Retry-After", "5")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":        "Database contention detected. Please retry.",
			"failure_mode": FailurePostgresLock,
			"retry_after":  5,
			"alert_id":     taskID,
		})
	}
}

// ============================================================
// HELPERS
// ============================================================

// dbContextWithTimeout wraps a parent context with a 5-second deadline for lock detection.
func dbContextWithTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 5*time.Second)
}

// isLockTimeout returns true if the error indicates a PostgreSQL lock or context deadline.
func isLockTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return err == context.DeadlineExceeded ||
		strings.Contains(s, "lock timeout") ||
		strings.Contains(s, "canceling statement due to") ||
		strings.Contains(s, "context deadline exceeded")
}

// extractPriority pulls severity/priority from a task input map, defaulting to "medium".
func extractPriority(input map[string]interface{}) string {
	if sev, ok := input["severity"].(string); ok && sev != "" {
		return sev
	}
	if pri, ok := input["priority"].(string); ok && pri != "" {
		return pri
	}
	return "medium"
}

// isTemporalTimeout returns true if the error indicates a workflow start timeout.
func isTemporalTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "timeout") ||
		strings.Contains(s, "deadline exceeded") ||
		strings.Contains(s, "context canceled")
}
