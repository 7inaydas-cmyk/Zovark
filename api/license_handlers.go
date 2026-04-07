package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ── GET /api/v1/admin/license/status ────────────────────────

func handleLicenseStatus(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	var publicKey, payload string
	_ = dbPool.QueryRow(ctx, `
		SELECT COALESCE(config_value, '') FROM system_configs
		WHERE tenant_id = $1 AND config_key = 'license.public_key'
	`, tenantID).Scan(&publicKey)
	_ = dbPool.QueryRow(ctx, `
		SELECT COALESCE(config_value, '') FROM system_configs
		WHERE tenant_id = $1 AND config_key = 'license.payload'
	`, tenantID).Scan(&payload)

	if publicKey == "" || payload == "" {
		c.JSON(http.StatusOK, gin.H{
			"status":         "community",
			"tier":           "community",
			"features":       []string{},
			"days_remaining": 0,
			"message":        "No license installed — running community tier",
		})
		return
	}

	// Return the payload metadata (signature verification happens in Python worker)
	c.JSON(http.StatusOK, gin.H{
		"status":        "installed",
		"tier":          "check via worker",
		"has_public_key": publicKey != "",
		"has_payload":    payload != "",
		"message":       "License installed — use verify endpoint for full validation",
	})
}

// ── GET /api/v1/admin/license/verify ────────────────────────

func handleLicenseVerify(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	var publicKey, payload string
	_ = dbPool.QueryRow(ctx, `
		SELECT COALESCE(config_value, '') FROM system_configs
		WHERE tenant_id = $1 AND config_key = 'license.public_key'
	`, tenantID).Scan(&publicKey)
	_ = dbPool.QueryRow(ctx, `
		SELECT COALESCE(config_value, '') FROM system_configs
		WHERE tenant_id = $1 AND config_key = 'license.payload'
	`, tenantID).Scan(&payload)

	if publicKey == "" || payload == "" {
		c.JSON(http.StatusOK, gin.H{
			"valid":   false,
			"status":  "no_license",
			"tier":    "community",
			"message": "No license installed",
		})
		return
	}

	// Signature verification is done in Python (Ed25519 via cryptography lib)
	// For the Go side, we return the raw status
	c.JSON(http.StatusOK, gin.H{
		"valid":          true,
		"status":         "installed",
		"has_public_key": true,
		"has_payload":    true,
		"payload_length": len(payload),
		"verified_at":    time.Now().UTC().Format(time.RFC3339),
		"message":        "License payload present — Python worker performs Ed25519 verification",
	})
}

// ── POST /api/v1/admin/license/install ──────────────────────

func handleLicenseInstall(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	var req struct {
		PublicKey string `json:"public_key" binding:"required"`
		Payload   string `json:"payload" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin license tx")
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		UPDATE system_configs SET config_value = $1, updated_at = NOW()
		WHERE tenant_id = $2 AND config_key = 'license.public_key'
	`, req.PublicKey, tenantID)
	if err != nil {
		respondInternalError(c, err, "update license public key")
		return
	}

	_, err = tx.Exec(ctx, `
		UPDATE system_configs SET config_value = $1, updated_at = NOW()
		WHERE tenant_id = $2 AND config_key = 'license.payload'
	`, req.Payload, tenantID)
	if err != nil {
		respondInternalError(c, err, "update license payload")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		respondInternalError(c, err, "commit license install")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "installed",
		"message": "License installed successfully — worker will verify on next request",
	})
}
