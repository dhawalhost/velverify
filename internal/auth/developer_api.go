package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// DeveloperAPIHandler handles developer portal API requests.
type DeveloperAPIHandler struct {
	appStore DeveloperAppRepository
	db       *sqlx.DB
	logger   *zap.Logger
}

// NewDeveloperAPIHandler creates a new developer API handler.
func NewDeveloperAPIHandler(db *sqlx.DB, logger *zap.Logger) *DeveloperAPIHandler {
	return &DeveloperAPIHandler{
		appStore: NewDeveloperAppRepository(db),
		db:       db,
		logger:   logger,
	}
}

// RegisterRoutes registers developer API routes.
func (h *DeveloperAPIHandler) RegisterRoutes(rg *gin.RouterGroup) {
	apps := rg.Group("/apps")
	{
		apps.GET("", h.listApps)
		apps.POST("", h.createApp)
		apps.GET("/:id", h.getApp)
		apps.PUT("/:id", h.updateApp)
		apps.DELETE("/:id", h.deleteApp)
		apps.POST("/:id/rotate-secret", h.rotateSecret)
		apps.GET("/:id/logs", h.getAppLogs)

		// Assignment Routes
		apps.GET("/:id/assignments", h.listAssignedUsers)
		apps.POST("/:id/assignments", h.assignUserToApp)
		apps.DELETE("/:id/assignments/:user_id", h.unassignUserFromApp)
	}

	keys := rg.Group("/api-keys")
	{
		keys.GET("", h.listAPIKeys)
		keys.POST("", h.createAPIKey)
		keys.DELETE("/:id", h.revokeAPIKey)
		keys.GET("/:id/logs", h.getAPIKeyLogs)
	}

	analytics := rg.Group("/developer")
	{
		analytics.GET("/analytics", h.getDeveloperAnalytics)
	}
}

// CreateAppRequest is the request to create a developer app.
type CreateAppRequest struct {
	Name         string   `json:"name" binding:"required"`
	Description  *string  `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
	AppType      string   `json:"app_type"`
	HomepageURL  *string  `json:"homepage_url"`
}

// AppResponse includes the client secret (only on create).
type AppResponse struct {
	DeveloperApp
	ClientSecret string `json:"client_secret,omitempty"`
}

func (h *DeveloperAPIHandler) listApps(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	ownerID := c.GetHeader("X-User-ID")
	if tenantID == "" || ownerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID and X-User-ID headers required"})
		return
	}

	apps, err := h.appStore.ListByOwner(c.Request.Context(), tenantID, ownerID)
	if err != nil {
		h.logger.Error("Failed to list apps", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list apps"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"apps": apps})
}

func (h *DeveloperAPIHandler) createApp(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	ownerID := c.GetHeader("X-User-ID")
	if tenantID == "" || ownerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID and X-User-ID headers required"})
		return
	}

	var req CreateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	clientSecret := generateClientSecret()
	app := &DeveloperApp{
		TenantID:    tenantID,
		OwnerID:     ownerID,
		Name:        req.Name,
		Description: req.Description,
		AppType:     req.AppType,
		HomepageURL: req.HomepageURL,
	}

	if len(req.RedirectURIs) > 0 {
		uris, _ := json.Marshal(req.RedirectURIs)
		app.RedirectURIs = uris
	}
	if len(req.GrantTypes) > 0 {
		grantTypes, _ := json.Marshal(req.GrantTypes)
		app.GrantTypes = grantTypes
	}
	if len(req.Scopes) > 0 {
		scopes, _ := json.Marshal(req.Scopes)
		app.Scopes = scopes
	}

	if err := h.appStore.Create(c.Request.Context(), app, clientSecret); err != nil {
		h.logger.Error("Failed to create app", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create app"})
		return
	}

	if err := h.appStore.AssignUserToApp(c.Request.Context(), tenantID, app.ID, ownerID); err != nil {
		h.logger.Error("Failed to assign app owner", zap.Error(err), zap.String("tenantID", tenantID), zap.String("appID", app.ID), zap.String("ownerID", ownerID))
		_ = h.appStore.Delete(c.Request.Context(), tenantID, app.ID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initialize app assignment"})
		return
	}

	// Return app with secret (only shown once!)
	c.JSON(http.StatusCreated, AppResponse{
		DeveloperApp: *app,
		ClientSecret: clientSecret,
	})
}

func (h *DeveloperAPIHandler) getApp(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	appID := c.Param("id")

	app, err := h.appStore.Get(c.Request.Context(), tenantID, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get app"})
		return
	}
	if app == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	c.JSON(http.StatusOK, app)
}

func (h *DeveloperAPIHandler) updateApp(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	appID := c.Param("id")

	existing, _ := h.appStore.Get(c.Request.Context(), tenantID, appID)
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	var req CreateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existing.Name = req.Name
	existing.Description = req.Description
	existing.HomepageURL = req.HomepageURL
	if len(req.RedirectURIs) > 0 {
		uris, _ := json.Marshal(req.RedirectURIs)
		existing.RedirectURIs = uris
	}
	if len(req.GrantTypes) > 0 {
		grantTypes, _ := json.Marshal(req.GrantTypes)
		existing.GrantTypes = grantTypes
	}
	if len(req.Scopes) > 0 {
		scopes, _ := json.Marshal(req.Scopes)
		existing.Scopes = scopes
	}

	if err := h.appStore.Update(c.Request.Context(), existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update app"})
		return
	}

	c.JSON(http.StatusOK, existing)
}

func (h *DeveloperAPIHandler) deleteApp(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	appID := c.Param("id")

	if err := h.appStore.Delete(c.Request.Context(), tenantID, appID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete app"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "app deleted"})
}

func (h *DeveloperAPIHandler) rotateSecret(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	appID := c.Param("id")

	newSecret, err := h.appStore.RotateSecret(c.Request.Context(), tenantID, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate secret"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "secret rotated successfully",
		"client_secret": newSecret,
	})
}

// ========== API Keys ==========

type APIKey struct {
	ID         string  `db:"id" json:"id"`
	TenantID   string  `db:"tenant_id" json:"tenant_id"`
	OwnerID    string  `db:"owner_id" json:"owner_id"`
	Name       string  `db:"name" json:"name"`
	KeyPrefix  string  `db:"key_prefix" json:"key_prefix"`
	KeyHash    string  `db:"key_hash" json:"-"`
	Status     string  `db:"status" json:"status"`
	CreatedAt  string  `db:"created_at" json:"created_at"`
	LastUsedAt *string `db:"last_used_at" json:"last_used_at,omitempty"`
}

type CreateAPIKeyRequest struct {
	Name string `json:"name" binding:"required"`
}

func (h *DeveloperAPIHandler) listAPIKeys(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	ownerID := c.GetHeader("X-User-ID")
	if tenantID == "" || ownerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID and X-User-ID headers required"})
		return
	}

	var keys []APIKey
	query := `SELECT id, tenant_id, owner_id, name, key_prefix, status, created_at, last_used_at 
	          FROM api_keys WHERE tenant_id = $1 AND owner_id = $2 AND status = 'active' ORDER BY created_at DESC`
	if err := h.db.SelectContext(c.Request.Context(), &keys, query, tenantID, ownerID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list API keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"api_keys": keys})
}

func (h *DeveloperAPIHandler) createAPIKey(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	ownerID := c.GetHeader("X-User-ID")
	if tenantID == "" || ownerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID and X-User-ID headers required"})
		return
	}

	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate API key
	keyBytes := make([]byte, 32)
	_, _ = rand.Read(keyBytes)
	fullKey := "vv_live_" + hex.EncodeToString(keyBytes)
	keyPrefix := fullKey[:12] // "vv_live_xxxx"

	hash, _ := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)

	query := `INSERT INTO api_keys (tenant_id, owner_id, name, key_prefix, key_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id`
	var keyID string
	if err := h.db.QueryRowContext(c.Request.Context(), query, tenantID, ownerID, req.Name, keyPrefix, string(hash)).Scan(&keyID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create API key"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":         keyID,
		"name":       req.Name,
		"key":        fullKey, // Only shown once!
		"key_prefix": keyPrefix,
		"message":    "Save this key now - it won't be shown again!",
	})
}

func (h *DeveloperAPIHandler) revokeAPIKey(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	keyID := c.Param("id")

	query := `UPDATE api_keys SET status = 'revoked' WHERE tenant_id = $1 AND id = $2`
	if _, err := h.db.ExecContext(c.Request.Context(), query, tenantID, keyID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key revoked"})
}

// ========== API Logs & Analytics ==========

type APILog struct {
	ID              string `db:"id" json:"id"`
	TenantID        string `db:"tenant_id" json:"-"`
	ClientID        string `db:"client_id" json:"client_id"`
	Method          string `db:"method" json:"method"`
	Path            string `db:"path" json:"path"`
	StatusCode      int    `db:"status_code" json:"status_code"`
	LatencyMs       int    `db:"latency_ms" json:"latency_ms"`
	IPAddress       string `db:"ip_address" json:"ip_address"`
	RequestPayload  string `db:"request_payload" json:"request_payload"`
	ResponsePayload string `db:"response_payload" json:"response_payload"`
	CreatedAt       string `db:"created_at" json:"created_at"`
}

func (h *DeveloperAPIHandler) getAppLogs(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	appID := c.Param("id")

	app, err := h.appStore.Get(c.Request.Context(), tenantID, appID)
	if err != nil || app == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	var logs []APILog
	query := `SELECT id, client_id, method, path, status_code, latency_ms, ip_address, 
	          COALESCE(request_payload::text, '{}') as request_payload, 
			  COALESCE(response_payload::text, '{}') as response_payload, created_at
	          FROM api_logs WHERE tenant_id = $1 AND client_id = $2 ORDER BY created_at DESC LIMIT 50`
	if err := h.db.SelectContext(c.Request.Context(), &logs, query, tenantID, app.ClientID); err != nil {
		h.logger.Error("Failed to fetch app logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch app logs"})
		return
	}
	if logs == nil {
		logs = make([]APILog, 0)
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

func (h *DeveloperAPIHandler) getAPIKeyLogs(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	ownerID := c.GetHeader("X-User-ID")
	keyID := c.Param("id")

	var keyPrefix string
	queryCheck := `SELECT key_prefix FROM api_keys WHERE id = $1 AND tenant_id = $2 AND owner_id = $3`
	if err := h.db.GetContext(c.Request.Context(), &keyPrefix, queryCheck, keyID, tenantID, ownerID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
		return
	}

	var logs []APILog
	query := `SELECT id, client_id, method, path, status_code, latency_ms, ip_address, 
	          COALESCE(request_payload::text, '{}') as request_payload, 
			  COALESCE(response_payload::text, '{}') as response_payload, created_at
	          FROM api_logs WHERE tenant_id = $1 AND client_id = $2 ORDER BY created_at DESC LIMIT 50`
	if err := h.db.SelectContext(c.Request.Context(), &logs, query, tenantID, keyPrefix); err != nil {
		h.logger.Error("Failed to fetch api key logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs"})
		return
	}
	if logs == nil {
		logs = make([]APILog, 0)
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

func (h *DeveloperAPIHandler) getDeveloperAnalytics(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")

	// Global tenant-level analytics (for the frontend dashboard chart)
	type AnalyticPoint struct {
		Date       string `db:"log_date" json:"date"`
		TotalCalls int    `db:"total_calls" json:"total_calls"`
		AvgLatency int    `db:"avg_latency" json:"avg_latency"`
		Errors     int    `db:"errors" json:"errors"`
	}

	var data []AnalyticPoint
	query := `
		SELECT 
			DATE(created_at) as log_date,
			COUNT(*) as total_calls,
			COALESCE(AVG(latency_ms), 0)::int as avg_latency,
			SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
		FROM api_logs 
		WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '7 days'
		GROUP BY log_date
		ORDER BY log_date ASC
	`
	if err := h.db.SelectContext(c.Request.Context(), &data, query, tenantID); err != nil {
		h.logger.Error("Failed to fetch analytics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch analytics"})
		return
	}

	if data == nil {
		data = make([]AnalyticPoint, 0)
	}
	c.JSON(http.StatusOK, gin.H{"analytics": data})
}

func (h *DeveloperAPIHandler) listAssignedUsers(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	appID := c.Param("id")

	if tenantID == "" || appID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header and Application ID required"})
		return
	}

	users, err := h.appStore.ListAssignedUsers(c.Request.Context(), tenantID, appID)
	if err != nil {
		h.logger.Error("Failed to list assigned users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list assigned users"})
		return
	}

	if users == nil {
		users = make([]string, 0)
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// AssignUserRequest represents the payload to grant a user application access.
type AssignUserRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

func (h *DeveloperAPIHandler) assignUserToApp(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	appID := c.Param("id")

	if tenantID == "" || appID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header and Application ID required"})
		return
	}

	var req AssignUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.appStore.AssignUserToApp(c.Request.Context(), tenantID, appID, req.UserID)
	if err != nil {
		h.logger.Error("Failed to assign user to app", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User assigned to application"})
}

func (h *DeveloperAPIHandler) unassignUserFromApp(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	appID := c.Param("id")
	userID := c.Param("user_id")

	if tenantID == "" || appID == "" || userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header, Application ID, and User ID required"})
		return
	}

	err := h.appStore.UnassignUserFromApp(c.Request.Context(), tenantID, appID, userID)
	if err != nil {
		h.logger.Error("Failed to unassign user from app", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unassign user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User unassigned from application"})
}
