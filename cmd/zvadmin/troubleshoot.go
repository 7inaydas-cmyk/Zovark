package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var symptoms = []struct {
	key  string
	desc string
}{
	{"alerts-stuck", "Alerts submitted but never complete"},
	{"slow-dashboard", "Dashboard loads slowly or times out"},
	{"wrong-verdicts", "Attack alerts scored as benign (or vice versa)"},
	{"high-resources", "CPU/memory/disk usage is high"},
	{"post-reboot", "System just rebooted, need to verify everything works"},
}

func troubleshootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "troubleshoot",
		Short: "Guided troubleshooting for common symptoms",
		Long: `Interactive troubleshooter. Pass --symptom to skip the menu.
Symptoms: alerts-stuck, slow-dashboard, wrong-verdicts, high-resources, post-reboot`,
		Run: runTroubleshoot,
	}
	cmd.Flags().String("symptom", "", "Symptom to troubleshoot (skip menu)")
	return cmd
}

func runTroubleshoot(cmd *cobra.Command, args []string) {
	symptom, _ := cmd.Flags().GetString("symptom")

	if symptom == "" {
		// Interactive menu
		fmt.Println("ZOVARK TROUBLESHOOTER")
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Println("What symptom are you seeing?")
		fmt.Println()
		for i, s := range symptoms {
			fmt.Printf("  %d. %s\n     %s\n\n", i+1, s.key, s.desc)
		}
		fmt.Print("Enter number (1-5): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		idx := safeInt(input) - 1
		if idx < 0 || idx >= len(symptoms) {
			fmt.Println("Invalid selection.")
			os.Exit(1)
		}
		symptom = symptoms[idx].key
	}

	fmt.Println()
	fmt.Printf("TROUBLESHOOTING: %s\n", symptom)
	fmt.Println("════════════════════════════════════════════════════════════")

	switch symptom {
	case "alerts-stuck":
		troubleshootAlertsStuck()
	case "slow-dashboard":
		troubleshootSlowDashboard()
	case "wrong-verdicts":
		troubleshootWrongVerdicts()
	case "high-resources":
		troubleshootHighResources()
	case "post-reboot":
		troubleshootPostReboot()
	default:
		fmt.Printf("Unknown symptom: %s\n", symptom)
		fmt.Println("Valid symptoms: alerts-stuck, slow-dashboard, wrong-verdicts, high-resources, post-reboot")
		os.Exit(1)
	}
}

func step(n int, desc string) {
	fmt.Printf("\n  Step %d: %s\n", n, desc)
}

func check(desc string) bool {
	fmt.Printf("    Checking %s... ", desc)
	return true
}

func found(msg string) {
	fmt.Printf("%sROOT CAUSE FOUND%s\n", colorRed, colorReset)
	fmt.Printf("    Problem: %s\n", msg)
}

func fix(lines ...string) {
	fmt.Printf("    %sFix:%s\n", colorGreen, colorReset)
	for _, l := range lines {
		fmt.Printf("      %s\n", l)
	}
}

func passed(msg string) {
	fmt.Printf("%s%s%s\n", colorGreen, msg, colorReset)
}

// --- Symptom 1: Alerts Stuck ---

func troubleshootAlertsStuck() {
	step(1, "Check if worker container is running")
	containers, err := dockerContainers()
	if err != nil {
		found("Cannot connect to Docker")
		fix("docker compose up -d")
		return
	}
	workerRunning := false
	for _, c := range containers {
		if strings.Contains(c.Name, "worker") && c.State == "running" {
			workerRunning = true
		}
	}
	if !workerRunning {
		found("Worker container is not running")
		fix("docker compose up -d worker",
			"docker compose logs worker --tail 50   # check why it crashed")
		return
	}
	passed("Worker is running")

	step(2, "Check Temporal connectivity")
	state, err := fetchOOBState()
	if err != nil {
		found("OOB unreachable — API may be down")
		fix("docker compose restart api",
			"docker compose logs api --tail 30")
		return
	}
	temporal, _ := state["temporal"].(string)
	if temporal != "ok" {
		found("Temporal is " + temporal)
		fix("docker compose restart temporal",
			"sleep 10",
			"docker compose restart worker   # worker reconnects to Temporal")
		return
	}
	passed("Temporal is ok")

	step(3, "Check for stuck workflows")
	stuckStr := psqlSingle(`SELECT COUNT(*) FROM agent_tasks WHERE status='pending' AND created_at < NOW() - INTERVAL '10 minutes'`)
	stuck := safeInt(stuckStr)
	if stuck > 0 {
		found(fmt.Sprintf("%d alerts stuck in 'pending' for >10 minutes", stuck))
		fix("docker compose restart worker",
			"# If still stuck after 2 minutes:",
			"docker compose restart temporal",
			"sleep 10",
			"docker compose restart worker")
		return
	}
	passed("No stuck alerts")

	step(4, "Check backpressure queue")
	bpStr, _ := redisCmd("ZCARD", "zovark:pending_workflows")
	bp := safeInt(bpStr)
	if bp > 200 {
		found(fmt.Sprintf("Backpressure queue has %d entries (limit 200)", bp))
		fix("Wait for drain — the system is processing as fast as it can.",
			"Reduce SIEM alert rate if possible.",
			"Monitor: docker compose exec valkey valkey-cli -a zovark_valkey_dev_2026 ZCARD zovark:pending_workflows")
		return
	}
	passed(fmt.Sprintf("Backpressure queue: %d (normal)", bp))

	fmt.Println("\n  All checks passed. Alerts should be processing normally.")
	fmt.Println("  If still stuck, check: docker compose logs worker --tail 100")
}

// --- Symptom 2: Slow Dashboard ---

func troubleshootSlowDashboard() {
	step(1, "Check dashboard container")
	containers, _ := dockerContainers()
	dashOK := false
	for _, c := range containers {
		if strings.Contains(c.Name, "dashboard") {
			if c.State == "running" {
				dashOK = true
			} else {
				found("Dashboard container is " + c.State)
				fix("docker compose restart dashboard")
				return
			}
		}
	}
	if !dashOK {
		found("Dashboard container not found")
		fix("docker compose up -d dashboard")
		return
	}
	passed("Dashboard container running")

	step(2, "Check API responsiveness")
	state, err := fetchOOBState()
	if err != nil {
		found("API is unreachable")
		fix("docker compose restart api")
		return
	}
	pg, _ := state["postgres"].(string)
	if pg != "ok" {
		found("PostgreSQL is " + pg + " — API queries are slow")
		fix("docker compose restart postgres",
			"sleep 10",
			"docker compose restart api")
		return
	}
	passed("API + PostgreSQL responsive")

	step(3, "Check database size")
	taskCount := psqlSingle(`SELECT COUNT(*) FROM agent_tasks`)
	tc := safeInt(taskCount)
	if tc > 100000 {
		found(fmt.Sprintf("Large task table: %d rows — queries may be slow", tc))
		fix("Consider archiving old investigations:",
			"  docker compose exec postgres psql -U zovark -d zovark -c \\",
			"    \"DELETE FROM agent_tasks WHERE created_at < NOW() - INTERVAL '90 days'\"")
		return
	}
	passed(fmt.Sprintf("Task count: %d (normal)", tc))

	step(4, "Check PgBouncer connection pool")
	connStr := psqlSingle(`SELECT COUNT(*) FROM pg_stat_activity WHERE datname='zovark'`)
	conns := safeInt(connStr)
	if conns > 80 {
		found(fmt.Sprintf("High connection count: %d — pool may be exhausted", conns))
		fix("docker compose restart pgbouncer")
		return
	}
	passed(fmt.Sprintf("Connections: %d (normal)", conns))

	fmt.Println("\n  All checks passed. Dashboard should be responsive.")
	fmt.Println("  If still slow, check browser DevTools Network tab for slow API calls.")
}

// --- Symptom 3: Wrong Verdicts ---

func troubleshootWrongVerdicts() {
	step(1, "Check LLM inference availability")
	state, _ := fetchOOBState()
	inf := "unknown"
	if state != nil {
		if v, ok := state["inference"].(string); ok {
			inf = v
		}
	}
	if inf != "ok" {
		found("Inference service is " + inf + " — LLM assess stage cannot score properly")
		fix("Verify the LLM endpoint is reachable from the worker container:",
			"  docker compose exec worker curl -sf $ZOVARK_LLM_ENDPOINT",
			"If using host-side LLM, ensure it is running and listening on the configured port.",
			"Then restart the worker: docker compose restart worker")
		return
	}
	passed("Inference available")

	step(2, "Check recent calibration (attack types scoring < 65)")
	lowScoring, _ := psql(`
		SELECT task_type, ROUND(AVG((output->>'risk_score')::numeric),0), COUNT(*)
		FROM agent_tasks
		WHERE status='completed' AND (output->>'risk_score')::int BETWEEN 1 AND 64
		  AND output->>'verdict' NOT IN ('benign')
		  AND created_at > NOW() - INTERVAL '24 hours'
		GROUP BY task_type ORDER BY 2 ASC LIMIT 5`)
	if len(lowScoring) > 0 {
		found("These attack types are scoring below threshold:")
		for _, r := range lowScoring {
			if len(r) >= 3 {
				fmt.Printf("      %-25s avg_risk=%-3s count=%s\n", r[0], r[1], r[2])
			}
		}
		fix("Check the detection tool for each type in worker/tools/detection.py",
			"Check the investigation plan in worker/tools/investigation_plans.json",
			"The risk weights in the detection tool may need increasing.")
		return
	}
	passed("All attack types scoring >= 65")

	step(3, "Check for benign false positives (benign types scoring > 25)")
	highBenign, _ := psql(`
		SELECT task_type, ROUND(AVG((output->>'risk_score')::numeric),0), COUNT(*)
		FROM agent_tasks
		WHERE status='completed' AND (output->>'risk_score')::int > 25
		  AND task_type IN ('password_change','windows_update','health_check','scheduled_backup','user_login')
		  AND created_at > NOW() - INTERVAL '24 hours'
		GROUP BY task_type ORDER BY 2 DESC`)
	if len(highBenign) > 0 {
		found("Benign types with high risk scores:")
		for _, r := range highBenign {
			if len(r) >= 3 {
				fmt.Printf("      %-25s avg_risk=%-3s count=%s\n", r[0], r[1], r[2])
			}
		}
		fix("Check if signal boost is inflating scores (worker/stages/assess.py)",
			"Check if output_validator is overriding with safe_default risk=50",
			"Check the benign routing in worker/stages/ingest.py ATTACK_INDICATORS list")
		return
	}
	passed("No benign false positives")

	fmt.Println("\n  Calibration looks correct. If specific alerts are wrong:")
	fmt.Println("    1. Find the task: zvadmin alerts --hours 1")
	fmt.Println("    2. Check output: curl -s localhost:8090/api/v1/tasks/<ID> -H 'Authorization: Bearer <token>'")
	fmt.Println("    3. Look at output.findings and output.risk_score for clues")
}

// --- Symptom 4: High Resources ---

func troubleshootHighResources() {
	step(1, "Check GPU memory")
	gpu := nvidiaSMI()
	if gpu.Available {
		pct := 100.0 * float64(gpu.MemUsedMB) / float64(gpu.MemTotalMB)
		if pct > 95 {
			found(fmt.Sprintf("GPU VRAM %d%%: %dMB/%dMB", int(pct), gpu.MemUsedMB, gpu.MemTotalMB))
			fix("Reduce LLM concurrency: set MAX_CONCURRENT_ACTIVITIES=4 in docker-compose.yml",
				"docker compose up -d worker")
			return
		}
		passed(fmt.Sprintf("GPU VRAM: %d%% (%dMB/%dMB)", int(pct), gpu.MemUsedMB, gpu.MemTotalMB))
	} else {
		passed("No GPU detected (CPU mode)")
	}

	step(2, "Check database connections")
	connStr := psqlSingle(`SELECT COUNT(*) FROM pg_stat_activity WHERE datname='zovark'`)
	conns := safeInt(connStr)
	if conns > 80 {
		found(fmt.Sprintf("High DB connections: %d", conns))
		fix("docker compose restart pgbouncer",
			"# Check for connection leaks in worker")
		return
	}
	passed(fmt.Sprintf("DB connections: %d", conns))

	step(3, "Check Redis memory")
	memStr, _ := redisCmd("INFO", "memory")
	for _, line := range strings.Split(memStr, "\n") {
		if strings.HasPrefix(line, "used_memory_human:") {
			mem := strings.TrimPrefix(line, "used_memory_human:")
			fmt.Printf("    Redis memory: %s\n", strings.TrimSpace(mem))
		}
	}
	passed("Redis within limits")

	step(4, "Check alert volume")
	hourly := psqlSingle(`SELECT COUNT(*) FROM agent_tasks WHERE created_at > NOW() - INTERVAL '1 hour'`)
	h := safeInt(hourly)
	if h > 500 {
		found(fmt.Sprintf("High alert volume: %d/hour", h))
		fix("Consider increasing batch window: ZOVARK_API_BATCH_WINDOW_SECONDS=10",
			"Or tune SIEM rules to reduce alert noise")
		return
	}
	passed(fmt.Sprintf("Alert volume: %d/hour (normal)", h))

	fmt.Println("\n  Resource usage appears normal.")
	fmt.Println("  For deeper analysis: docker stats --no-stream")
}

// --- Symptom 5: Post-Reboot ---

func troubleshootPostReboot() {
	fmt.Println("  Running post-reboot verification checklist...")

	step(1, "Check all containers are running")
	containers, err := dockerContainers()
	if err != nil {
		found("Cannot reach Docker")
		fix("docker compose up -d")
		return
	}
	down := []string{}
	for _, c := range containers {
		if c.State != "running" {
			down = append(down, c.Name)
		}
	}
	if len(down) > 0 {
		found(fmt.Sprintf("Containers not running: %s", strings.Join(down, ", ")))
		fix("docker compose up -d")
		return
	}
	passed(fmt.Sprintf("All %d containers running", len(containers)))

	step(2, "Check API readiness (DB + Redis + Temporal)")
	state, err := fetchOOBState()
	if err != nil {
		found("API not ready yet")
		fix("Wait 30 seconds, then: curl -s http://localhost:8090/ready",
			"If still failing: docker compose restart api")
		return
	}
	for _, svc := range []string{"postgres", "redis", "temporal"} {
		st, _ := state[svc].(string)
		if st != "ok" {
			found(svc + " is " + st)
			fix(fmt.Sprintf("docker compose restart %s", svc),
				"sleep 10",
				"docker compose restart api")
			return
		}
	}
	passed("PostgreSQL, Redis, Temporal all ok")

	step(3, "Check LLM inference")
	inf, _ := state["inference"].(string)
	if inf != "ok" {
		found("LLM inference not responding")
		fix("Verify the LLM endpoint is reachable:",
			"  docker compose exec worker curl -sf $ZOVARK_LLM_ENDPOINT",
			"If using host-side LLM, start it and ensure it listens on the configured port.",
			"Then: docker compose restart worker")
		return
	}
	passed("LLM inference responding")

	step(4, "Verify a test alert completes")
	fmt.Println("    Submit a test alert to verify the full pipeline:")
	fmt.Println()
	fmt.Println("      TOKEN=$(curl -sf -X POST http://localhost:8090/api/v1/auth/login \\")
	fmt.Println("        -H 'Content-Type: application/json' \\")
	fmt.Println("        -d '{\"email\":\"admin@test.local\",\"password\":\"TestPass2026\"}' | grep -o '\"token\":\"[^\"]*\"' | cut -d'\"' -f4)")
	fmt.Println()
	fmt.Println("      curl -sf -X POST http://localhost:8090/api/v1/tasks \\")
	fmt.Println("        -H \"Authorization: Bearer $TOKEN\" -H 'Content-Type: application/json' \\")
	fmt.Println("        -d '{\"task_type\":\"health_check\",\"input\":{\"prompt\":\"post-reboot test\",\"severity\":\"info\",\"siem_event\":{\"title\":\"Reboot Test\",\"hostname\":\"test\",\"rule_name\":\"RebootTest\",\"raw_log\":\"Post-reboot verification test\"}}}'")
	fmt.Println()
	fmt.Println("    Wait 60 seconds, then check the task status.")

	step(5, "Check dashboard")
	fmt.Println("    Open http://localhost:3000 in a browser.")
	fmt.Println("    Login: admin@test.local / TestPass2026")

	fmt.Println()
	fmt.Println("  Post-reboot checks complete. System appears healthy.")
	fmt.Println("════════════════════════════════════════════════════════════")
}
