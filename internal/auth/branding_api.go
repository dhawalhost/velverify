package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// RegisterBrandingRoutes registers branding routes on the router.
func (h *HTTPHandler) RegisterBrandingRoutes(router *gin.RouterGroup) {
	// Public endpoint (no auth required, just tenant ID context or param)
	// We allow fetching public branding by tenant ID
	router.GET("/branding/public/:tenant", h.getPublicBranding)

	// Protected management endpoints
	mgmt := router.Group("/api/v1/branding")
	mgmt.Use(middleware.TenantExtractor(middleware.TenantConfig{
		SlugResolver: h.svc.ResolveTenantSlug,
	}))
	mgmt.GET("", h.getBranding)
	mgmt.PUT("", h.updateBranding)
}

func (h *HTTPHandler) getPublicBranding(c *gin.Context) {
	tenantID, _ := middleware.TenantIDFromGinContext(c)
	if tenantID == "" {
		tenantID = c.Param("tenant")
	}

	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant identifier required"})
		return
	}

	// Resolve slug if needed
	resolvedID, err := h.svc.ResolveTenantSlug(c.Request.Context(), tenantID)
	if err == nil && resolvedID != "" {
		tenantID = resolvedID
	}

	config, err := h.svc.GetBranding(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to fetch branding", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch branding"})
		return
	}

	c.JSON(http.StatusOK, config)
}

func (h *HTTPHandler) getBranding(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID required"})
		return
	}

	config, err := h.svc.GetBranding(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to fetch branding", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch branding"})
		return
	}

	c.JSON(http.StatusOK, config)
}

func (h *HTTPHandler) updateBranding(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID required"})
		return
	}

	var req BrandingConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.TenantID = tenantID

	if err := h.svc.UpdateBranding(c.Request.Context(), req); err != nil {
		h.logger.Error("Failed to update branding", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update branding"})
		return
	}

	c.JSON(http.StatusOK, req)
}
