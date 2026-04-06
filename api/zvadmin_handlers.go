package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// ZVADMIN DIAGNOSTIC ENDPOINTS
// In-process equivalents of zvadmin CLI commands.
// All endpoints are admin-only (POST /api/v1/admin/*).
// ============================================================

// ---------- POST /api/v1/admin/diagnose ----------

type diagnoseCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass" or "fail"
	Detail string `json:"detail"`
}

func handleAdminDiagnose(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	var checks []diagnoseCheck

	// 1. PostgreSQL
	pgCheck := diagnoseCheck{Name: "postgresql", Status: "fail", Detail: "not initialized"}
	if dbPool != nil {
		var one int
		if err := dbPool.QueryRow(ctx, "SELECT 1").Scan(&one); err == nil && one == 1 {
			pgCheck.Status = "pass"
			pgCheck.Detail = "SELECT 1 OK"
		} else if err != nil {
			pgCheck.Detail = "query failed"
		}
	}
	checks = append(checks, pgCheck)

	// 2. Redis (Valkey)
	redisCheck := diagnoseCheck{Name: "redis", Status: "fail", Detail: "not initialized"}
	if redisClient != nil {
		if err := redisClient.Ping(ctx).Err(); err == nil {
			redisCheck.Status = "pass"
			redisCheck.Detail = "PONG"
		} else {
			redisCheck.Detail = "ping failed"
		}
	}
	checks = append(checks, redisCheck)

	// 3. Temporal
	temporalCheck := diagnoseCheck{Name: "temporal", Status: "fail", Detail: "not initialized"}
	if tc != nil {
		temporalCheck.Status = "pass"
		temporalCheck.Detail = "client connected"
	}
	checks = append(checks, temporalCheck)

	// 4. LLM Inference
	inferenceCheck := diagnoseCheck{Name: "inference", Status: "fail", Detail: "unreachable"}
	llmEndpoint := getEnvOrDefault("ZOVARK_LLM_ENDPOINT_FAST",
		getEnvOrDefault("ZOVARK_LLM_ENDPOINT", "http://zovark-inference:8080/v1/chat/completions"))
	llmHealthURL := strings.TrimSuffix(llmEndpoint, "/v1/chat/completions") + "/health"
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get(llmHealthURL)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			inferenceCheck.Status = "pass"
			inferenceCheck.Detail = "healthy"
		} else {
			inferenceCheck.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
	}
	checks = append(checks, inferenceCheck)

	// 5. Worker container (check via healer API)
	workerCheck := diagnoseCheck{Name: "worker", Status: "fail", Detail: "unknown"}
	wResp, wErr := httpClient.Get("http://zovark-healer:8081/api/health")
	if wErr == nil {
		wResp.Body.Close()
		if wResp.StatusCode == 200 {
			workerCheck.Status = "pass"
			workerCheck.Detail = "healer reports healthy"
		} else {
			workerCheck.Detail = fmt.Sprintf("healer HTTP %d", wResp.StatusCode)
		}
	} else {
		workerCheck.Detail = "healer unreachable"
	}
	checks = append(checks, workerCheck)

	// 6. Healer
	healerCheck := diagnoseCheck{Name: "healer", Status: "fail", Detail: "unreachable"}
	if wErr == nil {
		healerCheck.Status = "pass"
		healerCheck.Detail = "reachable on :8081"
	}
	checks = append(checks, healerCheck)

	// 7. Queue depth (Temporal pending workflows via Redis backpressure counter)
	queueCheck := diagnoseCheck{Name: "queue_depth", Status: "pass", Detail: "unknown"}
	if redisClient != nil {
		depth, qErr := redisClient.ZCard(ctx, "zovark:backpressure:pending").Result()
		if qErr == nil {
			queueCheck.Detail = fmt.Sprintf("%d pending workflows", depth)
			if depth > 200 {
				queueCheck.Status = "fail"
				queueCheck.Detail = fmt.Sprintf("%d pending workflows (above soft limit 200)", depth)
			}
		} else {
			queueCheck.Detail = "backpressure key not found (OK if idle)"
		}
	}
	checks = append(checks, queueCheck)

	// 8. Disk (check DB size as a proxy)
	diskCheck := diagnoseCheck{Name: "disk", Status: "pass", Detail: "unknown"}
	if dbPool != nil {
		var dbSizeMB float64
		if err := dbPool.QueryRow(ctx, "SELECT pg_database_size(current_database()) / (1024.0 * 1024.0)").Scan(&dbSizeMB); err == nil {
			diskCheck.Detail = fmt.Sprintf("DB size: %.1f MB", dbSizeMB)
			if dbSizeMB > 10000 {
				diskCheck.Status = "fail"
				diskCheck.Detail = fmt.Sprintf("DB size: %.1f MB (>10 GB)", dbSizeMB)
			}
		}
	}
	checks = append(checks, diskCheck)

	// Overall
	overall := "healthy"
	failCount := 0
	for _, ch := range checks {
		if ch.Status == "fail" {
			failCount++
		}
	}
	if failCount >= 3 {
		overall = "unhealthy"
	} else if failCount >= 1 {
		overall = "degraded"
	}

	c.JSON(http.StatusOK, gin.H{
		"checks":  checks,
		"overall": overall,
	})
}

// ---------- POST /api/v1/admin/alerts ----------

type adminAlertsRequest struct {
	Hours int `json:"hours"`
}

func handleAdminAlerts(c *gin.Context) {
	var req adminAlertsRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Hours <= 0 {
		req.Hours = 24
	}

	tenantID := c.MustGet("tenant_id").(string)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Verdict distribution
	verdicts := make(map[string]int)
	rows, err := dbPool.Query(ctx, `
		SELECT COALESCE(output->>'verdict', 'pending'), COUNT(*)
		FROM agent_tasks
		WHERE tenant_id = $1 AND created_at > NOW() - ($2 || ' hours')::interval
		GROUP BY output->>'verdict'
	`, tenantID, strconv.Itoa(req.Hours))
	if err != nil {
		respondInternalError(c, err, "query verdict distribution")
		return
	}
	defer rows.Close()
	var total int
	for rows.Next() {
		var verdict string
		var count int
		if err := rows.Scan(&verdict, &count); err != nil {
			continue
		}
		verdicts[verdict] = count
		total += count
	}

	// Top task types
	type taskTypeCount struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	var topTypes []taskTypeCount
	tRows, tErr := dbPool.Query(ctx, `
		SELECT task_type, COUNT(*) as cnt
		FROM agent_tasks
		WHERE tenant_id = $1 AND created_at > NOW() - ($2 || ' hours')::interval
		GROUP BY task_type
		ORDER BY cnt DESC
		LIMIT 10
	`, tenantID, strconv.Itoa(req.Hours))
	if tErr == nil {
		defer tRows.Close()
		for tRows.Next() {
			var tt taskTypeCount
			if err := tRows.Scan(&tt.Name, &tt.Count); err != nil {
				continue
			}
			topTypes = append(topTypes, tt)
		}
	}

	// Average latency (completed tasks only, in milliseconds)
	var avgLatencyMs float64
	_ = dbPool.QueryRow(ctx, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at - created_at)) * 1000), 0)
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed'
		  AND created_at > NOW() - ($2 || ' hours')::interval
	`, tenantID, strconv.Itoa(req.Hours)).Scan(&avgLatencyMs)

	c.JSON(http.StatusOK, gin.H{
		"verdicts":       verdicts,
		"top_types":      topTypes,
		"avg_latency_ms": avgLatencyMs,
		"total":          total,
		"hours":          req.Hours,
	})
}

// ---------- POST /api/v1/admin/model-check ----------

func handleAdminModelCheck(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	type typeStats struct {
		Name         string  `json:"name"`
		AvgRisk      float64 `json:"avg_risk"`
		AttackCount  int     `json:"attack_count"`
		BenignCount  int     `json:"benign_count"`
		TotalCount   int     `json:"total_count"`
	}

	rows, err := dbPool.Query(ctx, `
		SELECT task_type,
		       COALESCE(AVG((output->>'risk_score')::numeric), 0) as avg_risk,
		       COUNT(*) FILTER (WHERE output->>'verdict' IN ('true_positive', 'needs_analyst_review', 'needs_manual_review')) as attack_count,
		       COUNT(*) FILTER (WHERE output->>'verdict' = 'benign') as benign_count,
		       COUNT(*) as total
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed' AND output IS NOT NULL
		GROUP BY task_type
		ORDER BY total DESC
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "query model check")
		return
	}
	defer rows.Close()

	var types []typeStats
	var totalAttackRisk, totalBenignRisk float64
	var totalAttacks, totalBenign int

	for rows.Next() {
		var ts typeStats
		if err := rows.Scan(&ts.Name, &ts.AvgRisk, &ts.AttackCount, &ts.BenignCount, &ts.TotalCount); err != nil {
			continue
		}
		types = append(types, ts)
		// Approximate separation by accumulating weighted risk
		if ts.AttackCount > 0 {
			totalAttackRisk += ts.AvgRisk * float64(ts.AttackCount)
			totalAttacks += ts.AttackCount
		}
		if ts.BenignCount > 0 {
			totalBenignRisk += ts.AvgRisk * float64(ts.BenignCount)
			totalBenign += ts.BenignCount
		}
	}

	// Separation gap: avg attack risk - avg benign risk (higher = better calibration)
	var separationGap float64
	if totalAttacks > 0 && totalBenign > 0 {
		separationGap = (totalAttackRisk / float64(totalAttacks)) - (totalBenignRisk / float64(totalBenign))
	}

	c.JSON(http.StatusOK, gin.H{
		"types":          types,
		"separation_gap": separationGap,
	})
}

// ---------- POST /api/v1/admin/dedup-health ----------

func handleAdminDedupHealth(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	decisions := make(map[string]int)
	counters := []string{"new_alert", "deduplicated", "severity_escalation", "retry_after_failure"}

	var total int
	if redisClient == nil {
		c.JSON(http.StatusOK, gin.H{
			"decisions":  decisions,
			"total":      0,
			"efficiency": 0.0,
			"error":      "redis not initialized",
		})
		return
	}
	for _, name := range counters {
		key := "dedup:stats:" + name
		val, err := redisClient.Get(ctx, key).Int()
		if err != nil {
			val = 0
		}
		decisions[name] = val
		total += val
	}

	// Efficiency: deduplicated / total submissions
	var efficiency float64
	if total > 0 {
		efficiency = float64(decisions["deduplicated"]) / float64(total)
	}

	c.JSON(http.StatusOK, gin.H{
		"decisions":  decisions,
		"total":      total,
		"efficiency": efficiency,
	})
}

// ---------- GET /api/v1/admin/system-stats ----------

func handleAdminSystemStats(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	result := gin.H{}

	// Task count from DB
	var taskCount int
	if dbPool != nil {
		_ = dbPool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_tasks WHERE tenant_id = $1`, tenantID).Scan(&taskCount)
	}
	result["task_count"] = taskCount

	// Redis memory
	var redisMemoryMB float64
	if redisClient != nil {
		info, err := redisClient.Info(ctx, "memory").Result()
		if err == nil {
			for _, line := range strings.Split(info, "\r\n") {
				if strings.HasPrefix(line, "used_memory:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						if bytes, pErr := strconv.ParseFloat(parts[1], 64); pErr == nil {
							redisMemoryMB = bytes / (1024 * 1024)
						}
					}
				}
			}
		}
	}
	result["redis_memory_mb"] = redisMemoryMB

	// Uptime
	result["uptime_seconds"] = int(time.Since(startTime).Seconds())

	// Pending tasks
	var pendingCount int
	if dbPool != nil {
		_ = dbPool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_tasks WHERE tenant_id = $1 AND status = 'pending'`, tenantID).Scan(&pendingCount)
	}
	result["pending_tasks"] = pendingCount

	// Completed tasks (last 24h)
	var completedLast24h int
	if dbPool != nil {
		_ = dbPool.QueryRow(ctx, `
			SELECT COUNT(*) FROM agent_tasks
			WHERE tenant_id = $1 AND status = 'completed' AND created_at > NOW() - interval '24 hours'
		`, tenantID).Scan(&completedLast24h)
	}
	result["completed_last_24h"] = completedLast24h

	// Error count (last 24h)
	var errorCount int
	if dbPool != nil {
		_ = dbPool.QueryRow(ctx, `
			SELECT COUNT(*) FROM agent_tasks
			WHERE tenant_id = $1 AND status IN ('failed', 'error') AND created_at > NOW() - interval '24 hours'
		`, tenantID).Scan(&errorCount)
	}
	result["errors_last_24h"] = errorCount

	c.JSON(http.StatusOK, result)
}

// ---------- GET /api/v1/admin/pipeline/status ----------

type recentInvestigation struct {
	TaskType  string  `json:"task_type"`
	Verdict   string  `json:"verdict"`
	RiskScore int     `json:"risk_score"`
	LatencyS  float64 `json:"latency_s"`
	Completed string  `json:"completed_at"`
}

func handlePipelineStatus(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	minutesStr := c.DefaultQuery("minutes", "5")
	minutes, err := strconv.Atoi(minutesStr)
	if err != nil || minutes <= 0 || minutes > 1440 {
		minutes = 5
	}
	interval := strconv.Itoa(minutes)

	// Active (pending + processing)
	var active int
	_ = dbPool.QueryRow(ctx, `
		SELECT COUNT(*) FROM agent_tasks
		WHERE tenant_id = $1 AND status IN ('pending', 'processing', 'running')
	`, tenantID).Scan(&active)

	// Completed + errors in window
	var completed, errors int
	sRows, sErr := dbPool.Query(ctx, `
		SELECT status, COUNT(*) FROM agent_tasks
		WHERE tenant_id = $1 AND completed_at > NOW() - ($2 || ' minutes')::interval
		  AND status IN ('completed', 'error', 'failed')
		GROUP BY status
	`, tenantID, interval)
	if sErr == nil {
		defer sRows.Close()
		for sRows.Next() {
			var st string
			var cnt int
			if err := sRows.Scan(&st, &cnt); err == nil {
				if st == "completed" {
					completed = cnt
				} else {
					errors += cnt
				}
			}
		}
	}

	// Total 24h
	var total24h int
	_ = dbPool.QueryRow(ctx, `
		SELECT COUNT(*) FROM agent_tasks
		WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
	`, tenantID).Scan(&total24h)

	// Throughput (last 60s extrapolated to per-minute)
	var throughputRaw int
	_ = dbPool.QueryRow(ctx, `
		SELECT COUNT(*) FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed' AND completed_at > NOW() - INTERVAL '60 seconds'
	`, tenantID).Scan(&throughputRaw)
	throughputPerMin := float64(throughputRaw)

	// Latency stats
	var avgLatencyMs, p95LatencyMs float64
	_ = dbPool.QueryRow(ctx, `
		SELECT
			COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (completed_at - created_at)) * 1000)), 0),
			COALESCE(ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - created_at)) * 1000)), 0)
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed' AND completed_at > NOW() - ($2 || ' minutes')::interval
	`, tenantID, interval).Scan(&avgLatencyMs, &p95LatencyMs)

	// Verdict distribution
	verdicts := make(map[string]int)
	vRows, vErr := dbPool.Query(ctx, `
		SELECT COALESCE(output->>'verdict', 'unknown'), COUNT(*)
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed' AND completed_at > NOW() - ($2 || ' minutes')::interval
		  AND output->>'verdict' IS NOT NULL
		GROUP BY output->>'verdict'
	`, tenantID, interval)
	if vErr == nil {
		defer vRows.Close()
		for vRows.Next() {
			var v string
			var cnt int
			if err := vRows.Scan(&v, &cnt); err == nil {
				verdicts[v] = cnt
			}
		}
	}

	// Risk distribution (attacks only)
	var rCritical, rHigh, rMedium, rLow int
	_ = dbPool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE (output->>'risk_score')::int >= 85),
			COUNT(*) FILTER (WHERE (output->>'risk_score')::int >= 65 AND (output->>'risk_score')::int < 85),
			COUNT(*) FILTER (WHERE (output->>'risk_score')::int >= 40 AND (output->>'risk_score')::int < 65),
			COUNT(*) FILTER (WHERE (output->>'risk_score')::int < 40)
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed'
		  AND output->>'verdict' != 'benign' AND output->>'risk_score' IS NOT NULL
		  AND completed_at > NOW() - ($2 || ' minutes')::interval
	`, tenantID, interval).Scan(&rCritical, &rHigh, &rMedium, &rLow)
	riskDist := map[string]int{"critical": rCritical, "high": rHigh, "medium": rMedium, "low": rLow}

	// Dedup stats from Redis
	dedupStats := map[string]interface{}{"total_deduped": 0, "dedup_rate": 0.0}
	if redisClient != nil {
		deduped, _ := redisClient.Get(ctx, "dedup:stats:deduplicated").Int()
		totalDedup, _ := redisClient.Get(ctx, "dedup:stats:new_alert").Int()
		dedupStats["total_deduped"] = deduped
		if totalDedup+deduped > 0 {
			dedupStats["dedup_rate"] = float64(deduped) / float64(totalDedup+deduped)
		}
	}

	// Recent investigations
	var recent []recentInvestigation
	rRows, rErr := dbPool.Query(ctx, `
		SELECT task_type,
			COALESCE(output->>'verdict', 'pending'),
			COALESCE((output->>'risk_score')::int, 0),
			ROUND(EXTRACT(EPOCH FROM (completed_at - created_at))::numeric, 1),
			completed_at
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed' AND completed_at IS NOT NULL
		ORDER BY completed_at DESC LIMIT 10
	`, tenantID)
	if rErr == nil {
		defer rRows.Close()
		for rRows.Next() {
			var ri recentInvestigation
			var completedAt time.Time
			if err := rRows.Scan(&ri.TaskType, &ri.Verdict, &ri.RiskScore, &ri.LatencyS, &completedAt); err == nil {
				ri.Completed = completedAt.Format(time.RFC3339)
				recent = append(recent, ri)
			}
		}
	}
	if recent == nil {
		recent = []recentInvestigation{}
	}

	c.JSON(http.StatusOK, gin.H{
		"active":              active,
		"completed":           completed,
		"errors":              errors,
		"total_24h":           total24h,
		"throughput_per_min":  throughputPerMin,
		"avg_latency_ms":     avgLatencyMs,
		"p95_latency_ms":     p95LatencyMs,
		"verdict_distribution": verdicts,
		"risk_distribution":  riskDist,
		"dedup_stats":        dedupStats,
		"recent":             recent,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------- POST /api/v1/analytics/summary ----------

type analyticsSummaryRequest struct {
	Hours        int  `json:"hours"`
	ExcludeForge bool `json:"exclude_forge"`
}

func handleAnalyticsSummary(c *gin.Context) {
	var req analyticsSummaryRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Hours <= 0 {
		req.Hours = 24
	}

	tenantID := c.MustGet("tenant_id").(string)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	hoursStr := strconv.Itoa(req.Hours)

	// Build WHERE clause
	baseWhere := "tenant_id = $1 AND created_at > NOW() - ($2 || ' hours')::interval"
	if req.ExcludeForge {
		baseWhere += " AND NOT (input ? 'is_forge')"
	}

	// Verdict distribution
	verdicts := make(map[string]int)
	rows, err := dbPool.Query(ctx, fmt.Sprintf(`
		SELECT COALESCE(output->>'verdict', 'pending'), COUNT(*)
		FROM agent_tasks
		WHERE %s
		GROUP BY output->>'verdict'
	`, baseWhere), tenantID, hoursStr)
	if err != nil {
		respondInternalError(c, err, "query analytics verdicts")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var verdict string
		var count int
		if err := rows.Scan(&verdict, &count); err != nil {
			continue
		}
		verdicts[verdict] = count
	}

	// Risk distribution (buckets: 0-20, 21-40, 41-60, 61-80, 81-100)
	riskBuckets := map[string]int{
		"0-20":   0,
		"21-40":  0,
		"41-60":  0,
		"61-80":  0,
		"81-100": 0,
	}
	rRows, rErr := dbPool.Query(ctx, fmt.Sprintf(`
		SELECT
			CASE
				WHEN (output->>'risk_score')::int <= 20 THEN '0-20'
				WHEN (output->>'risk_score')::int <= 40 THEN '21-40'
				WHEN (output->>'risk_score')::int <= 60 THEN '41-60'
				WHEN (output->>'risk_score')::int <= 80 THEN '61-80'
				ELSE '81-100'
			END as bucket,
			COUNT(*)
		FROM agent_tasks
		WHERE %s AND status = 'completed' AND output->>'risk_score' IS NOT NULL
		GROUP BY bucket
	`, baseWhere), tenantID, hoursStr)
	if rErr == nil {
		defer rRows.Close()
		for rRows.Next() {
			var bucket string
			var count int
			if err := rRows.Scan(&bucket, &count); err != nil {
				continue
			}
			riskBuckets[bucket] = count
		}
	}

	// Top attack types (non-benign)
	type attackType struct {
		Name    string  `json:"name"`
		Count   int     `json:"count"`
		AvgRisk float64 `json:"avg_risk"`
	}
	var topAttacks []attackType
	aRows, aErr := dbPool.Query(ctx, fmt.Sprintf(`
		SELECT task_type, COUNT(*) as cnt,
		       COALESCE(AVG((output->>'risk_score')::numeric), 0) as avg_risk
		FROM agent_tasks
		WHERE %s AND status = 'completed'
		  AND output->>'verdict' IN ('true_positive', 'needs_analyst_review', 'needs_manual_review')
		GROUP BY task_type
		ORDER BY cnt DESC
		LIMIT 10
	`, baseWhere), tenantID, hoursStr)
	if aErr == nil {
		defer aRows.Close()
		for aRows.Next() {
			var at attackType
			if err := aRows.Scan(&at.Name, &at.Count, &at.AvgRisk); err != nil {
				continue
			}
			topAttacks = append(topAttacks, at)
		}
	}

	// Separation gap
	var avgAttackRisk, avgBenignRisk float64
	_ = dbPool.QueryRow(ctx, fmt.Sprintf(`
		SELECT COALESCE(AVG((output->>'risk_score')::numeric), 0)
		FROM agent_tasks
		WHERE %s AND status = 'completed'
		  AND output->>'verdict' IN ('true_positive', 'needs_analyst_review', 'needs_manual_review')
	`, baseWhere), tenantID, hoursStr).Scan(&avgAttackRisk)

	_ = dbPool.QueryRow(ctx, fmt.Sprintf(`
		SELECT COALESCE(AVG((output->>'risk_score')::numeric), 0)
		FROM agent_tasks
		WHERE %s AND status = 'completed' AND output->>'verdict' = 'benign'
	`, baseWhere), tenantID, hoursStr).Scan(&avgBenignRisk)

	c.JSON(http.StatusOK, gin.H{
		"verdicts":        verdicts,
		"risk_buckets":    riskBuckets,
		"top_attacks":     topAttacks,
		"avg_attack_risk": avgAttackRisk,
		"avg_benign_risk": avgBenignRisk,
		"separation_gap":  avgAttackRisk - avgBenignRisk,
		"hours":           req.Hours,
		"exclude_forge":   req.ExcludeForge,
	})
}
