package sso

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// HTTPHandler handles SSO provider HTTP requests.
type HTTPHandler struct {
	svc    Service
	logger *zap.Logger
}

// NewHTTPHandler creates a new SSO HTTP handler.
func NewHTTPHandler(svc Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger}
}

// RegisterRoutes registers SSO routes.
func (h *HTTPHandler) RegisterRoutes(rg *gin.RouterGroup) {
	sso := rg.Group("/saml/providers")
	{
		sso.GET("", h.listProviders)
		sso.POST("", h.createProvider)
		sso.GET("/:id", h.getProvider)
		sso.PUT("/:id", h.updateProvider)
		sso.DELETE("/:id", h.deleteProvider)
		sso.POST("/:id/toggle", h.toggleProvider)
	}
}

func (h *HTTPHandler) tenantID(c *gin.Context) (string, bool) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return "", false
	}
	return tenantID, true
}

func (h *HTTPHandler) listProviders(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var providerType *ProviderType
	if t := c.Query("type"); t != "" {
		pt := ProviderType(t)
		providerType = &pt
	}

	providers, err := h.svc.ListProviders(c.Request.Context(), tenantID, providerType)
	if err != nil {
		h.logger.Error("Failed to list providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

func (h *HTTPHandler) createProvider(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var p Provider
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, err := h.svc.CreateProvider(c.Request.Context(), tenantID, p)
	if err != nil {
		h.logger.Error("Failed to create provider", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *HTTPHandler) getProvider(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	p, err := h.svc.GetProvider(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	c.JSON(http.StatusOK, p)
}

func (h *HTTPHandler) updateProvider(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var p Provider
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.ID = c.Param("id")

	if err := h.svc.UpdateProvider(c.Request.Context(), tenantID, p); err != nil {
		h.logger.Error("Failed to update provider", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

func (h *HTTPHandler) deleteProvider(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	if err := h.svc.DeleteProvider(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to delete provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *HTTPHandler) toggleProvider(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := c.Param("id")
	if err := h.svc.ToggleProvider(c.Request.Context(), tenantID, id, req.Enabled); err != nil {
		h.logger.Error("Failed to toggle provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"enabled": req.Enabled})
}
