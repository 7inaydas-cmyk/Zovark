package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ── POST /api/v1/copilot/explain ────────────────────────────

func handleCopilotExplain(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	var req struct {
		InvestigationID string `json:"investigation_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := uuid.Parse(req.InvestigationID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid investigation_id"})
		return
	}

	// Verify investigation exists and belongs to tenant
	var taskType, verdict, rawLog string
	var riskScore int
	var outputRaw, inputRaw []byte
	err := dbPool.QueryRow(ctx, `
		SELECT task_type,
		       COALESCE(output->>'verdict', 'unknown'),
		       COALESCE((output->>'risk_score')::int, 0),
		       COALESCE(output::text, '{}'),
		       COALESCE(input::text, '{}'),
		       COALESCE(input->'siem_event'->>'raw_log', '')
		FROM agent_tasks
		WHERE id = $1 AND tenant_id = $2
	`, req.InvestigationID, tenantID).Scan(&taskType, &verdict, &riskScore, &outputRaw, &inputRaw, &rawLog)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	// Parse output for findings, IOCs, MITRE
	var output map[string]interface{}
	_ = json.Unmarshal(outputRaw, &output)

	findings := output["findings"]
	iocs := output["iocs"]
	mitre := output["mitre_attack"]

	// Build deterministic explanation (LLM would be called via Temporal activity in production)
	explanation := buildExplanation(taskType, verdict, riskScore, findings, iocs, mitre, rawLog)

	c.JSON(http.StatusOK, gin.H{
		"explanation":      explanation,
		"investigation_id": req.InvestigationID,
		"task_type":        taskType,
		"verdict":          verdict,
		"risk_score":       riskScore,
	})
}

func buildExplanation(taskType, verdict string, risk int, findings, iocs, mitre interface{}, rawLog string) string {
	findingsList := "No specific findings recorded"
	if f, ok := findings.([]interface{}); ok && len(f) > 0 {
		parts := make([]string, 0, 3)
		for i, item := range f {
			if i >= 3 {
				break
			}
			if s, ok := item.(string); ok {
				if len(s) > 80 {
					s = s[:80]
				}
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			findingsList = ""
			for i, p := range parts {
				if i > 0 {
					findingsList += "; "
				}
				findingsList += p
			}
		}
	}

	severity := "low-priority"
	if risk >= 70 {
		severity = "high-priority and warrants immediate attention"
	} else if risk >= 40 {
		severity = "moderate-priority and should be reviewed"
	}

	return "This " + taskType + " investigation was classified as " + verdict +
		" with a risk score of " + copilotItoa(risk) + "/100. " +
		"Key findings: " + findingsList + ". " +
		"This is " + severity + "."
}

func copilotItoa(n int) string {
	return strconv.Itoa(n)
}

// ── POST /api/v1/copilot/suggest ────────────────────────────

func handleCopilotSuggest(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	var req struct {
		InvestigationID string `json:"investigation_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := uuid.Parse(req.InvestigationID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid investigation_id"})
		return
	}

	var taskType, verdict string
	var riskScore int
	err := dbPool.QueryRow(ctx, `
		SELECT task_type,
		       COALESCE(output->>'verdict', 'unknown'),
		       COALESCE((output->>'risk_score')::int, 0)
		FROM agent_tasks
		WHERE id = $1 AND tenant_id = $2
	`, req.InvestigationID, tenantID).Scan(&taskType, &verdict, &riskScore)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	// Use the same remediation rules from the remediation engine
	suggestions := getSuggestionsForType(taskType, verdict, riskScore)

	c.JSON(http.StatusOK, gin.H{
		"suggestions":      suggestions,
		"narrative":        nil,
		"investigation_id": req.InvestigationID,
		"task_type":        taskType,
		"verdict":          verdict,
	})
}

func getSuggestionsForType(taskType, verdict string, riskScore int) []map[string]interface{} {
	if verdict == "benign" {
		return []map[string]interface{}{
			{"action_type": "false_positive", "description": "Investigation concluded benign — no action required", "priority": 10},
		}
	}
	if verdict == "inconclusive" {
		return []map[string]interface{}{
			{"action_type": "investigate_further", "description": "Verdict inconclusive — requires analyst deep-dive", "priority": 80},
		}
	}

	rules, ok := remediationRules[taskType]
	if !ok {
		rules = defaultRules
	}

	result := make([]map[string]interface{}, 0, len(rules))
	for _, r := range rules {
		priority := r.Priority
		if riskScore >= 90 {
			priority = min(100, priority+10)
		} else if riskScore >= 70 {
			priority = min(100, priority+5)
		} else if riskScore < 50 {
			priority = max(10, priority-15)
		}
		result = append(result, map[string]interface{}{
			"action_type": r.ActionType,
			"description": r.Description,
			"priority":    priority,
		})
	}
	return result
}

// ── POST /api/v1/copilot/correlate ──────────────────────────

func handleCopilotCorrelate(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	var req struct {
		InvestigationID string `json:"investigation_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := uuid.Parse(req.InvestigationID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid investigation_id"})
		return
	}

	// Fetch the investigation
	var taskType, sourceIP, username string
	err := dbPool.QueryRow(ctx, `
		SELECT task_type,
		       COALESCE(input->'siem_event'->>'source_ip', ''),
		       COALESCE(input->'siem_event'->>'username', '')
		FROM agent_tasks
		WHERE id = $1 AND tenant_id = $2
	`, req.InvestigationID, tenantID).Scan(&taskType, &sourceIP, &username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	// Find related investigations
	rows, err := dbPool.Query(ctx, `
		SELECT id::text, task_type,
		       COALESCE(output->>'verdict', 'pending') as verdict,
		       COALESCE((output->>'risk_score')::int, 0) as risk_score,
		       created_at,
		       COALESCE(input->'siem_event'->>'source_ip', '') as source_ip
		FROM agent_tasks
		WHERE tenant_id = $1
		  AND id != $2
		  AND (
		      ($3 != '' AND input->'siem_event'->>'source_ip' = $3)
		      OR ($4 != '' AND input->'siem_event'->>'username' = $4)
		      OR task_type = $5
		  )
		  AND created_at > NOW() - INTERVAL '7 days'
		ORDER BY created_at DESC
		LIMIT 20
	`, tenantID, req.InvestigationID, sourceIP, username, taskType)
	if err != nil {
		respondInternalError(c, err, "copilot correlate query")
		return
	}
	defer rows.Close()

	var related []map[string]interface{}
	for rows.Next() {
		var id, tt, v, srcIP string
		var risk int
		var createdAt time.Time
		if err := rows.Scan(&id, &tt, &v, &risk, &createdAt, &srcIP); err != nil {
			log.Printf("Error scanning correlate row: %v", err)
			continue
		}
		related = append(related, map[string]interface{}{
			"id":         id,
			"task_type":  tt,
			"verdict":    v,
			"risk_score": risk,
			"created_at": createdAt.Format(time.RFC3339),
			"source_ip":  srcIP,
		})
	}
	if related == nil {
		related = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"related":          related,
		"investigation_id": req.InvestigationID,
		"search_criteria": gin.H{
			"source_ip": sourceIP,
			"username":  username,
			"task_type": taskType,
		},
	})
}

// ── POST /api/v1/copilot/brief ──────────────────────────────

type attackCount struct {
	Type  string `json:"task_type"`
	Count int    `json:"count"`
}

func handleCopilotBrief(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	var req struct {
		Hours int `json:"hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Hours <= 0 {
		req.Hours = 8
	}
	if req.Hours > 168 {
		req.Hours = 168
	}

	interval := copilotItoa(req.Hours)

	// Aggregate stats
	var total, attacks, benignCount, suspicious, critical int
	var avgRisk float64
	_ = dbPool.QueryRow(ctx, `
		SELECT
			COUNT(*)::int,
			COUNT(*) FILTER (WHERE output->>'verdict' = 'true_positive')::int,
			COUNT(*) FILTER (WHERE output->>'verdict' = 'benign')::int,
			COUNT(*) FILTER (WHERE output->>'verdict' = 'suspicious')::int,
			COUNT(*) FILTER (WHERE (output->>'risk_score')::int >= 85)::int,
			COALESCE(ROUND(AVG((output->>'risk_score')::numeric) FILTER (WHERE output->>'verdict' != 'benign'), 1), 0)
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed'
		  AND created_at > NOW() - ($2 || ' hours')::interval
	`, tenantID, interval).Scan(&total, &attacks, &benignCount, &suspicious, &critical, &avgRisk)

	// Top attack types
	var topAttacks []attackCount
	tRows, tErr := dbPool.Query(ctx, `
		SELECT task_type, COUNT(*)::int as cnt
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed'
		  AND output->>'verdict' IN ('true_positive', 'suspicious')
		  AND created_at > NOW() - ($2 || ' hours')::interval
		GROUP BY task_type ORDER BY cnt DESC LIMIT 5
	`, tenantID, interval)
	if tErr == nil {
		defer tRows.Close()
		for tRows.Next() {
			var ac attackCount
			if err := tRows.Scan(&ac.Type, &ac.Count); err == nil {
				topAttacks = append(topAttacks, ac)
			}
		}
	}
	if topAttacks == nil {
		topAttacks = []attackCount{}
	}

	// Build deterministic brief
	briefText := buildBrief(req.Hours, total, attacks, benignCount, critical, avgRisk, topAttacks)

	c.JSON(http.StatusOK, gin.H{
		"brief": briefText,
		"stats": gin.H{
			"total":          total,
			"attacks":        attacks,
			"benign":         benignCount,
			"suspicious":     suspicious,
			"critical":       critical,
			"avg_attack_risk": avgRisk,
		},
		"top_attacks": topAttacks,
		"hours":       req.Hours,
	})
}

func buildBrief(hours, total, attacks, benign, critical int, avgRisk float64, topAttacks []attackCount) string {
	topStr := ""
	for i, a := range topAttacks {
		if i >= 3 {
			break
		}
		if i > 0 {
			topStr += ", "
		}
		topStr += a.Type + " (" + copilotItoa(a.Count) + ")"
	}

	brief := "Shift brief for the last " + copilotItoa(hours) + " hours: " +
		copilotItoa(total) + " investigations processed — " +
		copilotItoa(attacks) + " attacks detected, " +
		copilotItoa(benign) + " benign, " +
		copilotItoa(critical) + " critical (risk>=85). "
	if topStr != "" {
		brief += "Top attack types: " + topStr + ". "
	}
	if critical > 0 {
		brief += "Immediate action required on critical findings."
	} else {
		brief += "No critical findings requiring immediate action."
	}
	return brief
}
