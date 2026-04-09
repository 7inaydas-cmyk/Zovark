package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ============================================================
// NATS ALERT PUBLISHER (Sprint v0.10.0)
// ============================================================
//
// Minimal NATS client using raw TCP connection to nats://zovark-nats:4222.
// Uses the NATS text protocol (no external dependencies).
// Subject pattern: ALERTS.{tenant-slug}
//
// If NATS_URL is not set, falls back to direct DB insertion (existing SIEM flow).

// NATSClient is a minimal NATS publisher using the text protocol.
type NATSClient struct {
	mu       sync.Mutex
	conn     net.Conn
	url      string
	connected bool
}

var natsClient *NATSClient

// initNATS initializes the NATS client connection.
// Returns nil if NATS_URL is not configured (fallback to DB insertion).
func initNATS() *NATSClient {
	natsURL := getEnvOrDefault("NATS_URL", "")
	if natsURL == "" {
		log.Println("[NATS] NATS_URL not set, alert publishing will use direct DB insertion")
		return nil
	}

	// Strip nats:// prefix if present
	addr := natsURL
	if strings.HasPrefix(addr, "nats://") {
		addr = addr[7:]
	}
	// Strip user:password@ prefix — this minimal client doesn't auth.
	// NATS itself isn't running in the dev stack; if NATS is enabled
	// later, replace this with a proper nats.go client.
	if at := strings.Index(addr, "@"); at >= 0 {
		addr = addr[at+1:]
	}

	client := &NATSClient{
		url: addr,
	}

	// Attempt initial connection (non-blocking)
	go client.connectWithRetry()

	return client
}

// connectWithRetry attempts to connect with exponential backoff.
func (nc *NATSClient) connectWithRetry() {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		err := nc.connect()
		if err == nil {
			log.Printf("[NATS] Connected to %s", nc.url)
			return
		}

		log.Printf("[NATS] Connection failed (%s), retrying in %v", err, backoff)
		time.Sleep(backoff)

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// connect establishes a TCP connection and performs NATS handshake.
func (nc *NATSClient) connect() error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	conn, err := net.DialTimeout("tcp", nc.url, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read server INFO line
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return fmt.Errorf("read INFO: %w", err)
	}

	info := string(buf[:n])
	if !strings.HasPrefix(info, "INFO") {
		conn.Close()
		return fmt.Errorf("unexpected server response: %s", info[:min(len(info), 50)])
	}

	// Send CONNECT command
	connectCmd := `CONNECT {"verbose":false,"pedantic":false,"name":"zovark-api","lang":"go","version":"1.0.0"}` + "\r\n"
	_, err = conn.Write([]byte(connectCmd))
	if err != nil {
		conn.Close()
		return fmt.Errorf("send CONNECT: %w", err)
	}

	// Send PING to verify
	_, err = conn.Write([]byte("PING\r\n"))
	if err != nil {
		conn.Close()
		return fmt.Errorf("send PING: %w", err)
	}

	// Read PONG response
	n, err = conn.Read(buf)
	if err != nil {
		conn.Close()
		return fmt.Errorf("read PONG: %w", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "PONG") {
		conn.Close()
		return fmt.Errorf("expected PONG, got: %s", resp[:min(len(resp), 50)])
	}

	// Clear deadline for ongoing use
	conn.SetDeadline(time.Time{})

	nc.conn = conn
	nc.connected = true

	return nil
}

// publish sends a message to a NATS subject using the PUB command.
func (nc *NATSClient) publish(subject string, data []byte) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if !nc.connected || nc.conn == nil {
		return fmt.Errorf("not connected")
	}

	// NATS PUB protocol: PUB <subject> <size>\r\n<payload>\r\n
	cmd := fmt.Sprintf("PUB %s %d\r\n%s\r\n", subject, len(data), string(data))

	nc.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := nc.conn.Write([]byte(cmd))
	if err != nil {
		// Mark disconnected for reconnection
		nc.connected = false
		nc.conn.Close()
		nc.conn = nil
		go nc.connectWithRetry()
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

// Close gracefully shuts down the NATS connection.
func (nc *NATSClient) Close() {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.conn != nil {
		nc.conn.Write([]byte("QUIT\r\n"))
		nc.conn.Close()
		nc.conn = nil
		nc.connected = false
	}
	log.Println("[NATS] Connection closed")
}

// publishAlert publishes an alert to NATS on subject ALERTS.{tenant-slug}.
// If NATS is not available, returns an error (caller should fall back to DB).
func publishAlert(tenantSlug string, alertData []byte) error {
	if natsClient == nil {
		return fmt.Errorf("NATS not configured")
	}

	subject := fmt.Sprintf("ALERTS.%s", tenantSlug)

	// Wrap alert data with metadata
	envelope := map[string]interface{}{
		"subject":   subject,
		"tenant":    tenantSlug,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}

	// Parse alert data to embed
	var alertPayload interface{}
	if err := json.Unmarshal(alertData, &alertPayload); err != nil {
		envelope["data_raw"] = string(alertData)
	} else {
		envelope["data"] = alertPayload
	}

	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	err = natsClient.publish(subject, envelopeBytes)
	if err != nil {
		log.Printf("[NATS] Failed to publish to %s: %v", subject, err)
		return err
	}

	log.Printf("[NATS] Published alert to %s (%d bytes)", subject, len(envelopeBytes))
	return nil
}

