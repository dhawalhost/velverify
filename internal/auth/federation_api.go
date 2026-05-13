package auth

import (
	"errors"
	"net/http"

	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func (h *HTTPHandler) RegisterFederationRoutes(router *gin.RouterGroup) {
	// Public endpoint to fetch enabled SSO providers for a tenant
	router.GET("/sso/public/:tenant", h.getPublicSSOProviders)
}

func (h *HTTPHandler) getPublicSSOProviders(c *gin.Context) {
	tenantID, _ := middleware.TenantIDFromGinContext(c)
	if tenantID == "" {
		tenantID = c.Param("tenant")
	}

	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant identifier required"})
		return
	}

	// Resolve slug to ID if needed
	resolvedID, err := h.svc.ResolveTenantSlug(c.Request.Context(), tenantID)
	if err == nil && resolvedID != "" {
		tenantID = resolvedID
	}

	providers, err := h.svc.ListSSOProviders(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to fetch SSO providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch SSO providers"})
		return
	}

	c.JSON(http.StatusOK, providers)
}

func (h *HTTPHandler) getSSOAuthorizeURL(c *gin.Context) {
	provider := c.Param("provider")
	tenantID, _ := middleware.TenantIDFromGinContext(c)
	if tenantID == "" {
		tenantID = c.Query("tenant_id")
	}

	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}

	// Resolve slug to ID if needed
	resolvedID, err := h.svc.ResolveTenantSlug(c.Request.Context(), tenantID)
	if err == nil && resolvedID != "" {
		tenantID = resolvedID
	}

	// We expect the frontend to handle the callback at /social/callback
	// We need to know the origin to construct the full redirect URI
	// For simplicity, we assume the same origin as the request
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "http://" + c.Request.Host // fallback
	}
	redirectURI := origin + "/social/callback"

	url, err := h.svc.GetSSOAuthorizeURL(c.Request.Context(), tenantID, provider, redirectURI)
	if err != nil {
		h.logger.Error("Failed to generate SSO authorize URL", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *HTTPHandler) socialLogin(c *gin.Context) {
	var req SocialLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind social login request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Social login request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// For MVP/Simulated flow, we assume the client might send email/external_id directly
	// In production, `Code` would be exchanged.

	resp, err := h.svc.SocialLogin(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, ErrMFARequired) {
			c.JSON(http.StatusOK, gin.H{
				"pending_token": resp.AccessToken,
				"error":         "mfa_required",
				"message":       "Additional authentication required",
			})
			return
		}
		h.logger.Error("Social login failed", zap.Error(err))
		svcErr := &Error{}
		if errors.As(err, &svcErr) {
			h.respondOAuthError(c, svcErr)
		} else {
			// Handle specific errors like "linking required" if we strictly enforced it
			// But we implemented auto-provision so generic error is fine.
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}
