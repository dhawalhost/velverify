package governance

import (
	"net/http"

	"github.com/dhawalhost/wardseal/internal/webhook"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// WebhookHTTPHandler handles webhook management requests.
type WebhookHTTPHandler struct {
	svc    webhook.Service
	logger *zap.Logger
}

func NewWebhookHTTPHandler(svc webhook.Service, logger *zap.Logger) *WebhookHTTPHandler {
	return &WebhookHTTPHandler{svc: svc, logger: logger}
}

func (h *WebhookHTTPHandler) RegisterRoutes(rg *gin.RouterGroup) {
	hooks := rg.Group("/webhooks")
	{
		hooks.POST("", h.createWebhook)
		hooks.GET("", h.listWebhooks)
		hooks.GET("/:id", h.getWebhook)
		hooks.DELETE("/:id", h.deleteWebhook)
	}
}

func (h *WebhookHTTPHandler) getWebhook(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	hook, err := h.svc.GetWebhook(c.Request.Context(), tenantID, id)
	if err != nil {
		h.logger.Error("Failed to get webhook", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get webhook"})
		return
	}

	if hook == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found"})
		return
	}

	c.JSON(http.StatusOK, hook)
}

func (h *WebhookHTTPHandler) tenantID(c *gin.Context) (string, bool) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil || tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return "", false
	}
	return tenantID, true
}

func (h *WebhookHTTPHandler) createWebhook(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var req struct {
		URL    string   `json:"url" binding:"required,url"`
		Secret string   `json:"secret" binding:"required,min=8"`
		Events []string `json:"events" binding:"required,min=1"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, err := h.svc.CreateWebhook(c.Request.Context(), tenantID, req.URL, req.Secret, req.Events)
	if err != nil {
		h.logger.Error("Failed to create webhook", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create webhook"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *WebhookHTTPHandler) listWebhooks(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	hooks, err := h.svc.ListWebhooks(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list webhooks", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list webhooks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"webhooks": hooks})
}

func (h *WebhookHTTPHandler) deleteWebhook(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	if err := h.svc.DeleteWebhook(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to delete webhook", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete webhook"})
		return
	}

	c.Status(http.StatusNoContent)
}
