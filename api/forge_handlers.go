package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================
// ALERT FORGE — Synthetic Alert Generator & Pipeline Benchmark
// Submits controlled alert workloads through the full pipeline
// and measures detection accuracy, latency, and separation gap.
// ============================================================

// ---------- Types ----------

// ForgeConfig defines the parameters for a forge run.
type ForgeConfig struct {
	TotalAlerts   int     `json:"total_alerts" binding:"required,min=10,max=10000"`
	AttackRatio   float64 `json:"attack_ratio" binding:"min=0,max=1"`
	NoveltyRate   float64 `json:"novelty_rate" binding:"min=0,max=1"`
	CampaignMode  bool    `json:"campaign_mode"`
	RatePerSecond int     `json:"rate_per_second" binding:"min=1,max=10"`
	IncludeBenign bool    `json:"include_benign"`
}

// ForgeResults holds the final statistics of a forge run.
type ForgeResults struct {
	TotalSubmitted int            `json:"total_submitted"`
	TotalCompleted int            `json:"total_completed"`
	Verdicts       map[string]int `json:"verdicts"`
	AvgRiskAttack  float64        `json:"avg_risk_attack"`
	AvgRiskBenign  float64        `json:"avg_risk_benign"`
	SeparationGap  float64        `json:"separation_gap"`
	AvgLatencyMs   float64        `json:"avg_latency_ms"`
	P95LatencyMs   float64        `json:"p95_latency_ms"`
	NovelVariants  int            `json:"novel_variants"`
	DedupCount     int            `json:"dedup_count"`
	ErrorCount     int            `json:"error_count"`
	Errors         []string       `json:"errors,omitempty"`
	Duration       string         `json:"duration"`
}

// ForgeJob tracks a single forge run.
type ForgeJob struct {
	ID        string       `json:"id"`
	Config    ForgeConfig  `json:"config"`
	Status    string       `json:"status"` // running, collecting, completed, cancelled, error
	Progress  int          `json:"progress"`
	Results   ForgeResults `json:"results"`
	StartedAt time.Time   `json:"started_at"`

	mu      sync.Mutex
	cancel  context.CancelFunc
	taskIDs []string
	// Track which alerts are attack vs benign
	isAttack map[string]bool
	// Track novel variants
	isNovel map[string]bool
}

// In-memory job storage (no persistence needed — forge is ephemeral).
var forgeJobs sync.Map

// ---------- Handlers ----------

// handleForgeStart creates and starts a new forge job.
// POST /api/v1/admin/forge/start
func handleForgeStart(c *gin.Context) {
	var config ForgeConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Defaults
	if config.AttackRatio == 0 {
		config.AttackRatio = 0.7
	}
	if config.RatePerSecond == 0 {
		config.RatePerSecond = 2
	}

	jobID := uuid.New().String()
	ctx, cancel := context.WithCancel(context.Background())

	job := &ForgeJob{
		ID:        jobID,
		Config:    config,
		Status:    "running",
		StartedAt: time.Now(),
		cancel:    cancel,
		taskIDs:   make([]string, 0, config.TotalAlerts),
		isAttack:  make(map[string]bool),
		isNovel:   make(map[string]bool),
		Results: ForgeResults{
			Verdicts: make(map[string]int),
		},
	}

	forgeJobs.Store(jobID, job)

	// Get auth token from current request to reuse for internal submissions
	token := c.GetHeader("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	go runForgeJob(ctx, job, token)

	c.JSON(http.StatusOK, gin.H{
		"job_id": jobID,
		"status": "running",
		"config": config,
	})
}

// handleForgeStatus returns the current state of a forge job.
// GET /api/v1/admin/forge/:jobId
func handleForgeStatus(c *gin.Context) {
	jobID := c.Param("jobId")
	val, ok := forgeJobs.Load(jobID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "forge job not found"})
		return
	}
	job := val.(*ForgeJob)
	job.mu.Lock()
	defer job.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"id":         job.ID,
		"config":     job.Config,
		"status":     job.Status,
		"progress":   job.Progress,
		"results":    job.Results,
		"started_at": job.StartedAt,
		"task_count": len(job.taskIDs),
	})
}

// handleForgeStream provides SSE updates for a running forge job.
// GET /api/v1/admin/forge/:jobId/stream
func handleForgeStream(c *gin.Context) {
	jobID := c.Param("jobId")
	val, ok := forgeJobs.Load(jobID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "forge job not found"})
		return
	}
	job := val.(*ForgeJob)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Transfer-Encoding", "chunked")
	c.Header("X-Accel-Buffering", "no")

	c.Writer.WriteString("event: connected\n")
	c.Writer.WriteString(fmt.Sprintf("data: {\"job_id\":\"%s\",\"message\":\"forge stream connected\"}\n\n", jobID))
	c.Writer.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	clientGone := c.Request.Context().Done()

	for {
		select {
		case <-clientGone:
			return
		case <-ticker.C:
			job.mu.Lock()
			status := job.Status
			progress := job.Progress
			results := job.Results
			taskCount := len(job.taskIDs)
			job.mu.Unlock()

			data, _ := json.Marshal(gin.H{
				"status":     status,
				"progress":   progress,
				"task_count": taskCount,
				"results":    results,
			})
			c.Writer.WriteString("event: progress\n")
			c.Writer.WriteString(fmt.Sprintf("data: %s\n\n", string(data)))
			c.Writer.Flush()

			if status == "completed" || status == "cancelled" || status == "error" {
				c.Writer.WriteString("event: done\n")
				c.Writer.WriteString(fmt.Sprintf("data: {\"status\":\"%s\"}\n\n", status))
				c.Writer.Flush()
				return
			}
		case <-keepalive.C:
			c.Writer.WriteString(": keepalive\n\n")
			c.Writer.Flush()
		}
	}
}

// handleForgeStop cancels a running forge job.
// POST /api/v1/admin/forge/:jobId/stop
func handleForgeStop(c *gin.Context) {
	jobID := c.Param("jobId")
	val, ok := forgeJobs.Load(jobID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "forge job not found"})
		return
	}
	job := val.(*ForgeJob)
	job.mu.Lock()
	if job.Status == "running" || job.Status == "collecting" {
		job.Status = "cancelled"
		job.cancel()
	}
	job.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"status": "cancelled", "job_id": jobID})
}

// handleForgeHistory returns recent forge jobs.
// GET /api/v1/admin/forge/history
func handleForgeHistory(c *gin.Context) {
	type jobSummary struct {
		ID        string       `json:"id"`
		Config    ForgeConfig  `json:"config"`
		Status    string       `json:"status"`
		Results   ForgeResults `json:"results"`
		StartedAt time.Time   `json:"started_at"`
	}

	var jobs []jobSummary
	forgeJobs.Range(func(key, value interface{}) bool {
		job := value.(*ForgeJob)
		job.mu.Lock()
		jobs = append(jobs, jobSummary{
			ID:        job.ID,
			Config:    job.Config,
			Status:    job.Status,
			Results:   job.Results,
			StartedAt: job.StartedAt,
		})
		job.mu.Unlock()
		return true
	})

	// Sort by start time descending
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].StartedAt.After(jobs[j].StartedAt)
	})

	// Limit to 20
	if len(jobs) > 20 {
		jobs = jobs[:20]
	}

	c.JSON(http.StatusOK, gin.H{"jobs": jobs})
}

// ---------- Background Forge Execution ----------

// runForgeJob executes the forge workload in a background goroutine.
func runForgeJob(ctx context.Context, job *ForgeJob, token string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[FORGE] panic in job %s: %v", job.ID, r)
			job.mu.Lock()
			job.Status = "error"
			job.Results.Errors = append(job.Results.Errors, fmt.Sprintf("panic: %v", r))
			job.mu.Unlock()
		}
	}()

	cfg := job.Config
	attackCount := int(float64(cfg.TotalAlerts) * cfg.AttackRatio)
	benignCount := cfg.TotalAlerts - attackCount
	if !cfg.IncludeBenign {
		attackCount = cfg.TotalAlerts
		benignCount = 0
	}

	// Build alert queue: interleave attack and benign
	type alertEntry struct {
		scenario AlertTemplate
		attack   bool
		novel    bool
	}
	alertQueue := make([]alertEntry, 0, cfg.TotalAlerts)

	attackTypes := make([]string, 0, len(attackScenarios))
	for k := range attackScenarios {
		attackTypes = append(attackTypes, k)
	}
	benignTypes := make([]string, 0, len(benignScenarios))
	for k := range benignScenarios {
		benignTypes = append(benignTypes, k)
	}

	// Campaign state
	campaignStep := 0
	campaignIdx := 0
	campaignIP := randomExternalIP()

	for i := 0; i < attackCount; i++ {
		var scenario AlertTemplate
		isNovel := false

		if cfg.CampaignMode && len(campaigns) > 0 {
			// Campaign mode: cycle through campaign steps
			scenario = nextCampaignAlert(campaignIdx, campaignStep, campaignIP)
			campaignStep++
			if campaignStep >= len(campaigns[campaignIdx].Steps) {
				campaignStep = 0
				campaignIdx = (campaignIdx + 1) % len(campaigns)
				campaignIP = randomExternalIP()
			}
		} else if cfg.NoveltyRate > 0 && rand.Float64() < cfg.NoveltyRate {
			// Novel mutation — forces Path C
			base := attackScenarios[attackTypes[rand.Intn(len(attackTypes))]]
			scenario = novelMutation(base)
			isNovel = true
		} else {
			// Normal attack scenario
			scenario = attackScenarios[attackTypes[rand.Intn(len(attackTypes))]]
		}
		alertQueue = append(alertQueue, alertEntry{scenario: scenario, attack: true, novel: isNovel})
	}

	for i := 0; i < benignCount; i++ {
		scenario := benignScenarios[benignTypes[rand.Intn(len(benignTypes))]]
		alertQueue = append(alertQueue, alertEntry{scenario: scenario, attack: false})
	}

	// Shuffle to interleave
	rand.Shuffle(len(alertQueue), func(i, j int) {
		alertQueue[i], alertQueue[j] = alertQueue[j], alertQueue[i]
	})

	// Submit at configured rate
	interval := time.Duration(float64(time.Second) / float64(cfg.RatePerSecond))
	httpClient := &http.Client{Timeout: 30 * time.Second}
	apiBase := fmt.Sprintf("http://localhost:%s", appConfig.Port)
	submitted := 0
	dedupCount := 0

	for alertIdx, entry := range alertQueue {
		select {
		case <-ctx.Done():
			log.Printf("[FORGE] Job %s cancelled during submission at %d/%d", job.ID, submitted, cfg.TotalAlerts)
			return
		default:
		}

		alert := generateAlert(entry.scenario, job.ID, alertIdx+1)
		body, _ := json.Marshal(alert)

		req, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/api/v1/tasks", bytes.NewReader(body))
		if err != nil {
			job.mu.Lock()
			job.Results.ErrorCount++
			if len(job.Results.Errors) < 10 {
				job.Results.Errors = append(job.Results.Errors, fmt.Sprintf("request create error: %v", err))
			}
			job.mu.Unlock()
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		// Bypass tenant rate limiter — internal load generator
		req.Header.Set("X-Zovark-Internal", "forge")

		resp, err := httpClient.Do(req)
		if err != nil {
			job.mu.Lock()
			job.Results.ErrorCount++
			if len(job.Results.Errors) < 10 {
				job.Results.Errors = append(job.Results.Errors, fmt.Sprintf("submit error: %v", err))
			}
			job.mu.Unlock()
			continue
		}

		var result map[string]interface{}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		json.Unmarshal(respBody, &result)

		// Non-2xx responses are errors (rate limit 429, backpressure 503,
		// validation 400, etc.). Without this check, the old code silently
		// treated rate-limited alerts as "submitted" but never tracked them.
		if resp.StatusCode >= 400 {
			job.mu.Lock()
			job.Results.ErrorCount++
			if len(job.Results.Errors) < 10 {
				job.Results.Errors = append(job.Results.Errors,
					fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBody)[:min(200, len(respBody))]))
			}
			job.mu.Unlock()
			time.Sleep(interval)
			continue
		}

		// Extract task ID from various response formats
		taskID := ""
		if id, ok := result["task_id"].(string); ok {
			taskID = id
		} else if id, ok := result["id"].(string); ok {
			taskID = id
		} else if id, ok := result["existing_task_id"].(string); ok {
			taskID = id
			dedupCount++
		}

		// Check for dedup/batch responses
		wasBatched := false
		if status, ok := result["status"].(string); ok {
			if status == "deduplicated" || status == "batched" {
				dedupCount++
				wasBatched = true
				// Use parent ID for tracking — the batched/deduped ID has no DB row
				if pid, ok := result["batch_parent_id"].(string); ok && pid != "" {
					taskID = pid
				}
			}
		}

		if taskID != "" && !wasBatched {
			// Only track non-batched tasks for result collection
			job.mu.Lock()
			job.taskIDs = append(job.taskIDs, taskID)
			job.isAttack[taskID] = entry.attack
			job.isNovel[taskID] = entry.novel
			job.mu.Unlock()
		}

		submitted++
		job.mu.Lock()
		job.Progress = int(float64(submitted) / float64(cfg.TotalAlerts) * 50) // 0-50% for submission
		job.Results.TotalSubmitted = submitted
		job.Results.DedupCount = dedupCount
		job.mu.Unlock()

		time.Sleep(interval)
	}

	// Switch to collecting phase
	job.mu.Lock()
	job.Status = "collecting"
	job.mu.Unlock()

	log.Printf("[FORGE] Job %s: %d alerts submitted, collecting results...", job.ID, submitted)

	// Collect results with 10-minute timeout
	collectForgeResults(ctx, job, token, 10*time.Minute)

	job.mu.Lock()
	job.Status = "completed"
	job.Results.Duration = time.Since(job.StartedAt).Round(time.Second).String()
	job.mu.Unlock()

	log.Printf("[FORGE] Job %s completed: %d/%d collected, separation=%.1f",
		job.ID, job.Results.TotalCompleted, job.Results.TotalSubmitted, job.Results.SeparationGap)
}

// collectForgeResults queries the DB directly to collect task results.
// Avoids HTTP rate limiting by using dbPool instead of self-calling the API.
func collectForgeResults(ctx context.Context, job *ForgeJob, token string, timeout time.Duration) {
	job.mu.Lock()
	taskIDs := make([]string, len(job.taskIDs))
	copy(taskIDs, job.taskIDs)
	job.mu.Unlock()

	if len(taskIDs) == 0 {
		return
	}

	deadline := time.Now().Add(timeout)

	// Track per-task results
	type taskResult struct {
		verdict   string
		riskScore float64
		latencyMs float64
		completed bool
	}
	results := make(map[string]*taskResult)
	for _, id := range taskIDs {
		results[id] = &taskResult{}
	}

	// Poll DB in rounds until all complete or timeout
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Batch query all incomplete tasks at once
		incompleteIDs := []string{}
		for _, id := range taskIDs {
			if !results[id].completed {
				incompleteIDs = append(incompleteIDs, id)
			}
		}
		if len(incompleteIDs) == 0 {
			break
		}

		rows, err := dbPool.Query(ctx,
			`SELECT id, status, output, created_at, completed_at
			 FROM agent_tasks WHERE id = ANY($1::uuid[])`,
			incompleteIDs)
		if err != nil {
			log.Printf("[FORGE] DB query error in collector: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for rows.Next() {
			var id, status string
			var output interface{}
			var createdAt, completedAt interface{}
			if err := rows.Scan(&id, &status, &output, &createdAt, &completedAt); err != nil {
				continue
			}

			tr := results[id]
			if status == "completed" || status == "failed" || status == "error" {
				tr.completed = true

				// Extract verdict and risk from output JSONB
				if outputMap, ok := output.(map[string]interface{}); ok {
					if v, ok := outputMap["verdict"].(string); ok {
						tr.verdict = v
					}
					if r, ok := outputMap["risk_score"].(float64); ok {
						tr.riskScore = r
					}
				}

				// Calculate latency
				if ct, ok := createdAt.(time.Time); ok {
					if ca, ok := completedAt.(time.Time); ok {
						tr.latencyMs = float64(ca.Sub(ct).Milliseconds())
					}
				}
			}
		}
		rows.Close()

		// Update progress
		completed := 0
		for _, tr := range results {
			if tr.completed {
				completed++
			}
		}
		job.mu.Lock()
		job.Progress = 50 + int(float64(completed)/float64(len(taskIDs))*50) // 50-100%
		job.mu.Unlock()

		if completed == len(taskIDs) {
			break
		}

		time.Sleep(5 * time.Second)
	}

	// Aggregate statistics
	var attackRisks []float64
	var benignRisks []float64
	var latencies []float64
	verdicts := make(map[string]int)
	novelCount := 0
	totalCompleted := 0

	job.mu.Lock()
	for taskID, tr := range results {
		if !tr.completed {
			continue
		}
		totalCompleted++
		if tr.verdict != "" {
			verdicts[tr.verdict]++
		}

		isAttack := job.isAttack[taskID]
		if isAttack {
			attackRisks = append(attackRisks, tr.riskScore)
		} else {
			benignRisks = append(benignRisks, tr.riskScore)
		}

		if tr.latencyMs > 0 {
			latencies = append(latencies, tr.latencyMs)
		}

		if job.isNovel[taskID] {
			novelCount++
		}
	}

	// Calculate averages
	var avgAttack, avgBenign float64
	if len(attackRisks) > 0 {
		sum := 0.0
		for _, r := range attackRisks {
			sum += r
		}
		avgAttack = sum / float64(len(attackRisks))
	}
	if len(benignRisks) > 0 {
		sum := 0.0
		for _, r := range benignRisks {
			sum += r
		}
		avgBenign = sum / float64(len(benignRisks))
	}

	var avgLatency, p95Latency float64
	if len(latencies) > 0 {
		sum := 0.0
		for _, l := range latencies {
			sum += l
		}
		avgLatency = sum / float64(len(latencies))

		// P95 latency
		sort.Float64s(latencies)
		p95Idx := int(math.Ceil(float64(len(latencies))*0.95)) - 1
		if p95Idx < 0 {
			p95Idx = 0
		}
		if p95Idx >= len(latencies) {
			p95Idx = len(latencies) - 1
		}
		p95Latency = latencies[p95Idx]
	}

	job.Results.TotalCompleted = totalCompleted
	job.Results.Verdicts = verdicts
	job.Results.AvgRiskAttack = math.Round(avgAttack*100) / 100
	job.Results.AvgRiskBenign = math.Round(avgBenign*100) / 100
	job.Results.SeparationGap = math.Round((avgAttack-avgBenign)*100) / 100
	job.Results.AvgLatencyMs = math.Round(avgLatency*100) / 100
	job.Results.P95LatencyMs = math.Round(p95Latency*100) / 100
	job.Results.NovelVariants = novelCount
	job.mu.Unlock()
}
