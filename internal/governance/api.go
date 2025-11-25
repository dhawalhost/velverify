package governance

import (
	"errors"
	"net/http"

	"github.com/dhawalhost/velverify/internal/oauthclients"
	"github.com/dhawalhost/velverify/pkg/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// HTTPHandler represents the HTTP API handlers for the governance service.
type HTTPHandler struct {
	svc    Service
	logger *zap.Logger
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger}
}

// RegisterRoutes registers the governance routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	router.GET("/health", h.healthCheck)

	tenantGroup := router.Group("/api/v1")
	tenantGroup.Use(middleware.TenantExtractor(middleware.TenantConfig{}))
	clients := tenantGroup.Group("/oauth/clients")
	{
		clients.GET("", h.listOAuthClients)
		clients.POST("", h.createOAuthClient)
		clients.GET("/:clientID", h.getOAuthClient)
		clients.PUT("/:clientID", h.updateOAuthClient)
		clients.DELETE("/:clientID", h.deleteOAuthClient)
	}
}

func (h *HTTPHandler) healthCheck(c *gin.Context) {
	ok, err := h.svc.HealthCheck(c.Request.Context())
	if err != nil {
		h.logger.Error("Health check failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, HealthCheckResponse{Healthy: ok})
}

func (h *HTTPHandler) listOAuthClients(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	clients, err := h.svc.ListOAuthClients(c.Request.Context(), tenantID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	responses := make([]OAuthClientResponse, 0, len(clients))
	for _, client := range clients {
		responses = append(responses, newOAuthClientResponse(client))
	}
	c.JSON(http.StatusOK, gin.H{"clients": responses})
}

func (h *HTTPHandler) getOAuthClient(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	clientID := c.Param("clientID")
	client, err := h.svc.GetOAuthClient(c.Request.Context(), tenantID, clientID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, newOAuthClientResponse(client))
}

func (h *HTTPHandler) createOAuthClient(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	var req createOAuthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind create oauth client request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.svc.CreateOAuthClient(c.Request.Context(), tenantID, CreateOAuthClientInput{
		ClientID:      req.ClientID,
		Name:          req.Name,
		Description:   req.Description,
		ClientType:    req.ClientType,
		RedirectURIs:  req.RedirectURIs,
		AllowedScopes: req.AllowedScopes,
		ClientSecret:  req.ClientSecret,
	})
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusCreated, newOAuthClientResponse(client))
}

func (h *HTTPHandler) updateOAuthClient(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	clientID := c.Param("clientID")
	var req updateOAuthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind update oauth client request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.svc.UpdateOAuthClient(c.Request.Context(), tenantID, clientID, UpdateOAuthClientInput{
		Name:          req.Name,
		Description:   req.Description,
		ClientType:    req.ClientType,
		RedirectURIs:  req.RedirectURIs,
		AllowedScopes: req.AllowedScopes,
		ClientSecret:  req.ClientSecret,
	})
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, newOAuthClientResponse(client))
}

func (h *HTTPHandler) deleteOAuthClient(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	clientID := c.Param("clientID")
	if err := h.svc.DeleteOAuthClient(c.Request.Context(), tenantID, clientID); err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *HTTPHandler) tenantID(c *gin.Context) (string, bool) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		h.logger.Error("tenant id missing", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return "", false
	}
	return tenantID, true
}

func (h *HTTPHandler) handleServiceError(c *gin.Context, err error) {
	if IsValidationError(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if errors.Is(err, oauthclients.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	h.logger.Error("governance service error", zap.Error(err))
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
}
