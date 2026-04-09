package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ============================================================
// Shared telemetry data layer for zvadmin commands.
// All access from HOST side — no psycopg2, no redis-py.
//   OOB:    GET localhost:9091/debug/state
//   PG:     docker compose exec -T postgres psql …
//   Redis:  docker compose exec -T redis valkey-cli …
//   Docker: docker inspect / docker compose ps
//   GPU:    nvidia-smi (best-effort)
// ============================================================

// --- OOB ---

func oobURL() string {
	u := os.Getenv("ZOVARK_OOB_URL")
	if u == "" {
		u = "http://localhost:9091"
	}
	return u
}

func fetchOOBState() (map[string]interface{}, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(oobURL() + "/debug/state")
	if err != nil {
		return nil, fmt.Errorf("OOB unreachable: %w", err)
	}
	defer resp.Body.Close()
	var state map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return nil, fmt.Errorf("OOB parse error: %w", err)
	}
	return state, nil
}

// --- PostgreSQL via docker exec ---

func psql(query string) ([][]string, error) {
	cmd := exec.Command("docker", "compose", "exec", "-T", "postgres",
		"psql", "-U", "zovark", "-d", "zovark",
		"-t", "-A", "-F", "|", "-c", query)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("psql error: %s", strings.TrimSpace(stderr.String()))
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rows = append(rows, strings.Split(line, "|"))
	}
	return rows, nil
}

// psqlSingle runs a query that returns a single value.
func psqlSingle(query string) string {
	rows, err := psql(query)
	if err != nil || len(rows) == 0 || len(rows[0]) == 0 {
		return ""
	}
	return strings.TrimSpace(rows[0][0])
}

// --- Valkey via docker exec ---

func valkeyPW() string {
	// Check new VALKEY_* vars first, then legacy REDIS_*/ZOVARK_REDIS_*
	for _, key := range []string{
		"ZOVARK_VALKEY_PASSWORD", "VALKEY_PASSWORD",
		"ZOVARK_REDIS_PASSWORD", "REDIS_PASSWORD",
	} {
		if pw := os.Getenv(key); pw != "" {
			return pw
		}
	}
	return "zovark_valkey_dev_2026"
}

// Backwards-compat alias
func redisPW() string { return valkeyPW() }

func redisCmd(args ...string) (string, error) {
	all := append([]string{"compose", "exec", "-T", "valkey",
		"valkey-cli", "-a", valkeyPW(), "--no-auth-warning"}, args...)
	cmd := exec.Command("docker", all...)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("redis error: %s", strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func redisGet(key string) string {
	val, _ := redisCmd("GET", key)
	if val == "(nil)" || val == "" {
		return "0"
	}
	return val
}

func redisInt(key string) int {
	v, _ := strconv.Atoi(redisGet(key))
	return v
}

// --- Docker ---

type containerInfo struct {
	Name   string
	State  string
	Health string
	Uptime string
}

func dockerContainers() ([]containerInfo, error) {
	cmd := exec.Command("docker", "compose", "ps", "--format", "json")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	var containers []containerInfo
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var c struct {
			Name    string `json:"Name"`
			State   string `json:"State"`
			Health  string `json:"Health"`
			Status  string `json:"Status"`
			Service string `json:"Service"`
		}
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}
		name := c.Name
		if name == "" {
			name = c.Service
		}
		containers = append(containers, containerInfo{
			Name:   name,
			State:  c.State,
			Health: c.Health,
			Uptime: c.Status,
		})
	}
	return containers, nil
}

// --- nvidia-smi (best-effort) ---

type gpuInfo struct {
	Available  bool
	Name       string
	MemUsedMB  int
	MemTotalMB int
	TempC      int
	UtilPct    int
}

func nvidiaSMI() gpuInfo {
	cmd := exec.Command("nvidia-smi",
		"--query-gpu=name,memory.used,memory.total,temperature.gpu,utilization.gpu",
		"--format=csv,noheader,nounits")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return gpuInfo{Available: false}
	}
	parts := strings.Split(strings.TrimSpace(out.String()), ",")
	if len(parts) < 5 {
		return gpuInfo{Available: false}
	}
	memUsed, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
	memTotal, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
	temp, _ := strconv.Atoi(strings.TrimSpace(parts[3]))
	util, _ := strconv.Atoi(strings.TrimSpace(parts[4]))
	return gpuInfo{
		Available: true, Name: strings.TrimSpace(parts[0]),
		MemUsedMB: memUsed, MemTotalMB: memTotal,
		TempC: temp, UtilPct: util,
	}
}

// --- Helpers ---

func safeFloat(s string) float64 {
	s = strings.TrimSpace(s)
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func safeInt(s string) int {
	return int(safeFloat(s))
}

func colorize(s, color string) string {
	return color + s + colorReset
}

func ok(msg string) string   { return colorize("OK", colorGreen) + "  " + msg }
func warn(msg string) string { return colorize("WARN", colorYellow) + " " + msg }
func crit(msg string) string { return colorize("CRIT", colorRed) + " " + msg }

func bar(pct float64, width int) string {
	filled := int(pct / 100.0 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
