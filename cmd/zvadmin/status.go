package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show appliance health status",
		Run:   runStatus,
	}
}

func runStatus(cmd *cobra.Command, args []string) {
	oobURL := os.Getenv("ZOVARK_OOB_URL")
	if oobURL == "" {
		oobURL = "http://localhost:9091"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(oobURL + "/debug/state")
	if err != nil {
		fmt.Printf("%sAPI UNREACHABLE — cannot connect to %s%s\n", colorRed, oobURL, colorReset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var state map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		fmt.Printf("%sFailed to parse OOB response: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Println("ZOVARK APPLIANCE STATUS")
	fmt.Println("───────────────────────")
	fmt.Printf("%-20s %s\n", "Service", "Status")

	services := []struct{ name, key string }{
		{"API", "api"},
		{"PostgreSQL", "postgres"},
		{"Valkey", "redis"},
		{"Temporal", "temporal"},
	}

	// Check for single or dual inference
	if v, ok := state["inference"]; ok {
		services = append(services, struct{ name, key string }{"Inference", "inference"})
		_ = v
	} else {
		services = append(services,
			struct{ name, key string }{"Inference FAST", "inference_fast"},
			struct{ name, key string }{"Inference CODE", "inference_code"},
		)
	}

	anyDown := false
	anyDegraded := false
	for _, svc := range services {
		status, _ := state[svc.key].(string)
		if status == "" {
			status = "unknown"
		}

		var color, icon string
		switch status {
		case "ok":
			color, icon = colorGreen, "✓"
		case "degraded":
			color, icon = colorYellow, "~"
			anyDegraded = true
		default:
			color, icon = colorRed, "✗"
			anyDown = true
		}
		fmt.Printf("%-20s %s%s %s%s\n", svc.name, color, icon, status, colorReset)
	}

	fmt.Println("───────────────────────")

	version, _ := state["version"].(string)
	uptimeSec, _ := state["uptime_seconds"].(float64)
	goroutines, _ := state["goroutines"].(float64)
	heapMB, _ := state["heap_mb"].(float64)
	gpuTier, _ := state["gpu_tier"].(string)

	uptime := formatDuration(time.Duration(uptimeSec) * time.Second)
	fmt.Printf("Version: %s  Uptime: %s  Goroutines: %.0f  Heap: %.0f MB  Tier: %s\n",
		version, uptime, goroutines, heapMB, gpuTier)

	if anyDown {
		os.Exit(1)
	}
	if anyDegraded {
		os.Exit(2)
	}
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
