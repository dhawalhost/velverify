package chatops

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// HTTPHandler handles dashboard requests for Slack integration management.
type HTTPHandler struct {
	repo Repository
	log  *zap.Logger
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(repo Repository, log *zap.Logger) *HTTPHandler {
	return &HTTPHandler{
		repo: repo,
		log:  log,
	}
}

// RegisterRoutes registers the dashboard endpoints.
func (h *HTTPHandler) RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/integrations/slack")
	{
		group.GET("", h.GetStatus)
		group.PUT("", h.Configure)
		group.DELETE("", h.Disconnect)
	}
}

// GetStatus returns the current Slack integration status for a tenant.
func (h *HTTPHandler) GetStatus(c *gin.Context) {
	tenantID, _ := middleware.TenantIDFromGinContext(c)
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	integ, err := h.repo.GetByTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"status":  "not_configured",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled":     integ.IsEnabled,
		"team_id":     integ.TeamID,
		"app_id":      integ.AppID,
		"webhook_url": integ.WebhookURL,
		"status":      "ready",
	})
}

// Configure updates the Slack integration for a tenant.
func (h *HTTPHandler) Configure(c *gin.Context) {
	tenantID, _ := middleware.TenantIDFromGinContext(c)
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	var req struct {
		TeamID        string `json:"team_id" binding:"required"`
		AppID         string `json:"app_id" binding:"required"`
		BotToken      string `json:"bot_token"`      // Optional if already set
		SigningSecret string `json:"signing_secret"` // Optional if already set
		WebhookURL    string `json:"webhook_url"`
		Enabled       bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	si := SlackIntegration{
		TenantID:      tenantID,
		TeamID:        req.TeamID,
		AppID:         req.AppID,
		BotToken:      req.BotToken,
		SigningSecret: req.SigningSecret,
		WebhookURL:    req.WebhookURL,
		IsEnabled:     req.Enabled,
	}

	if err := h.repo.Upsert(c.Request.Context(), si); err != nil {
		h.log.Error("Failed to update slack integration", zap.String("tenant", tenantID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save configuration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Slack integration updated successfully"})
}

// Disconnect removes the Slack integration for a tenant.
func (h *HTTPHandler) Disconnect(c *gin.Context) {
	tenantID, _ := middleware.TenantIDFromGinContext(c)
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	if err := h.repo.Delete(c.Request.Context(), tenantID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disconnect"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Slack disconnected successfully"})
}
