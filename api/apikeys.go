package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================
// API KEY AUTHENTICATION FOR M2M (Issue #5)
// ============================================================

const apiKeyPrefix = "zovark_"

// generateAPIKey creates a new API key with the zovark_ prefix.
// Returns the raw key (shown once to the user) and its SHA-256 hash.
func generateAPIKey() (rawKey string, keyHash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	rawKey = apiKeyPrefix + base64.URLEncoding.EncodeToString(b)

	hash := sha256.Sum256([]byte(rawKey))
	keyHash = hex.EncodeToString(hash[:])
	return rawKey, keyHash
}

// hashAPIKey computes the SHA-256 hash of a raw API key.
func hashAPIKey(rawKey string) string {
	hash := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(hash[:])
}

// createAPIKeyHandler creates a new API key for the tenant.
// POST /api/v1/api-keys
func createAPIKeyHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		Name    string   `json:"name" binding:"required"`
		Scopes  []string `json:"scopes"`
		Expires *string  `json:"expires"` // RFC3339 format
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if len(req.Scopes) == 0 {
		req.Scopes = []string{"read"}
	}

	// Parse optional expiration
	var expiresAt *time.Time
	if req.Expires != nil && *req.Expires != "" {
		t, err := time.Parse(time.RFC3339, *req.Expires)
		if err != nil {
			respondError(c, http.StatusBadRequest, "INVALID_EXPIRY", "expires must be RFC3339 format")
			return
		}
		expiresAt = &t
	}

	rawKey, keyHash := generateAPIKey()
	keyID := uuid.New().String()

	_, err := dbPool.Exec(c.Request.Context(),
		`INSERT INTO api_keys (id, tenant_id, key_hash, name, scopes, expires_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		keyID, tenantID, keyHash, req.Name, req.Scopes, expiresAt, userID,
	)
	if err != nil {
		log.Printf("Failed to create API key: %v", err)
		respondError(c, http.StatusInternalServerError, "CREATE_FAILED", "failed to create API key")
		return
	}

	respondCreated(c, gin.H{
		"id":         keyID,
		"name":       req.Name,
		"key":        rawKey, // Only shown once
		"scopes":     req.Scopes,
		"expires_at": expiresAt,
		"created_at": time.Now(),
	})
}

// listAPIKeysHandler lists all API keys for the tenant (without raw keys).
// GET /api/v1/api-keys
func listAPIKeysHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(),
		`SELECT id, name, scopes, is_active, last_used_at, expires_at, created_at
		 FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "QUERY_FAILED", "failed to query API keys")
		return
	}
	defer rows.Close()

	var keys []map[string]interface{}
	for rows.Next() {
		var id, name string
		var scopes []string
		var isActive bool
		var lastUsedAt, expiresAt *time.Time
		var createdAt time.Time

		if err := rows.Scan(&id, &name, &scopes, &isActive, &lastUsedAt, &expiresAt, &createdAt); err != nil {
			log.Printf("Error scanning API key row: %v", err)
			continue
		}

		keys = append(keys, map[string]interface{}{
			"id":           id,
			"name":         name,
			"scopes":       scopes,
			"is_active":    isActive,
			"last_used_at": lastUsedAt,
			"expires_at":   expiresAt,
			"created_at":   createdAt,
		})
	}

	if keys == nil {
		keys = []map[string]interface{}{}
	}

	respondOK(c, gin.H{"api_keys": keys, "count": len(keys)})
}

// deleteAPIKeyHandler deactivates an API key.
// DELETE /api/v1/api-keys/:id
func deleteAPIKeyHandler(c *gin.Context) {
	keyID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	result, err := dbPool.Exec(c.Request.Context(),
		"UPDATE api_keys SET is_active = false WHERE id = $1 AND tenant_id = $2",
		keyID, tenantID,
	)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "DELETE_FAILED", "failed to deactivate API key")
		return
	}
	if result.RowsAffected() == 0 {
		respondError(c, http.StatusNotFound, "NOT_FOUND", "API key not found")
		return
	}

	respondOK(c, gin.H{"status": "deactivated", "id": keyID})
}

// authenticateAPIKey checks the X-API-Key header and sets context if valid.
// Returns true if an API key was found and authenticated.
func authenticateAPIKey(c *gin.Context) bool {
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		return false
	}

	keyHash := hashAPIKey(apiKey)

	var tenantID, keyID string
	var scopes []string
	var expiresAt *time.Time

	err := dbPool.QueryRow(c.Request.Context(), // FIX #11
		`SELECT ak.id, ak.tenant_id, ak.scopes, ak.expires_at
		 FROM api_keys ak
		 WHERE ak.key_hash = $1 AND ak.is_active = true`,
		keyHash,
	).Scan(&keyID, &tenantID, &scopes, &expiresAt)

	if err != nil {
		return false
	}

	// Check expiration
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return false
	}

	// Update last_used_at asynchronously
	go func() {
		_, _ = dbPool.Exec(context.Background(),
			"UPDATE api_keys SET last_used_at = NOW() WHERE id = $1", keyID)
	}()

	// Set context values for downstream handlers
	c.Set("tenant_id", tenantID)
	c.Set("user_id", keyID)       // API key ID as user_id
	c.Set("user_role", "api_key") // Special role for API keys
	c.Set("api_key_id", keyID)
	c.Set("api_key_scopes", scopes)

	return true
}
