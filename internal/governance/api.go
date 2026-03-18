package governance

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/webhook"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// HTTPHandler represents the HTTP API handlers for the governance service.
type HTTPHandler struct {
	svc             Service
	campaignHandler *CampaignHTTPHandler
	webhookHandler  *WebhookHTTPHandler
	orgHandler      *OrganizationHandler
	logger          *zap.Logger
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, campaignSvc CampaignService, webhookSvc webhook.Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{
		svc:             svc,
		campaignHandler: NewCampaignHTTPHandler(campaignSvc, logger),
		webhookHandler:  NewWebhookHTTPHandler(webhookSvc, logger),
		orgHandler:      NewOrganizationHandler(svc, logger),
		logger:          logger,
	}
}

// RegisterRoutes registers the governance routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	router.GET("/health", h.healthCheck)

	tenantGroup := router.Group("/api/v1")
	tenantGroup.Use(middleware.TenantExtractor(middleware.TenantConfig{
		SlugResolver: h.svc.ResolveTenantSlug,
	}))
	clients := tenantGroup.Group("/oauth/clients")
	{
		clients.GET("", h.listOAuthClients)
		clients.POST("", h.createOAuthClient)
		clients.GET("/:clientID", h.getOAuthClient)
		clients.PUT("/:clientID", h.updateOAuthClient)
		clients.DELETE("/:clientID", h.deleteOAuthClient)
	}

	requests := tenantGroup.Group("/governance/requests")
	{
		requests.POST("", h.createAccessRequest)
		requests.GET("", h.listAccessRequests)
		requests.POST("/:accessRequestID/approve", h.approveAccessRequest)
		requests.POST("/:accessRequestID/reject", h.rejectAccessRequest)
	}

	ipPolicies := tenantGroup.Group("/governance/ip-policies")
	{
		ipPolicies.GET("", h.listIPPolicies)
		ipPolicies.POST("", h.createIPPolicy)
		ipPolicies.DELETE("/:ipPolicyID", h.deleteIPPolicy)
	}

	// Registered combined routes
	h.orgHandler.RegisterRoutes(tenantGroup)
	h.campaignHandler.RegisterRoutes(tenantGroup)
	h.webhookHandler.RegisterRoutes(tenantGroup)
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
	client, err := h.svc.CreateOAuthClient(c.Request.Context(), tenantID, CreateOAuthClientInput(req))
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
	client, err := h.svc.UpdateOAuthClient(c.Request.Context(), tenantID, clientID, UpdateOAuthClientInput(req))
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
	c.Status(http.StatusNoContent)
}

func (h *HTTPHandler) createAccessRequest(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	var req CreateAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind create access request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.RequesterID == "" {
		req.RequesterID = actorIDFromRequest(c)
	}
	resp, err := h.svc.CreateAccessRequest(c.Request.Context(), tenantID, req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusCreated, resp)
}

func (h *HTTPHandler) listAccessRequests(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	status := c.Query("status")
	requests, err := h.svc.ListAccessRequests(c.Request.Context(), tenantID, status)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, AccessRequestList{Requests: requests})
}

func (h *HTTPHandler) approveAccessRequest(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	requestID := c.Param("accessRequestID")
	var body ApprovalDecision
	_ = c.ShouldBindJSON(&body) // Optional body - ignore error
	approverID := actorIDFromRequest(c)
	if approverID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "approver user id required"})
		return
	}

	if err := h.svc.ApproveAccessRequest(c.Request.Context(), tenantID, requestID, approverID, body.Comment); err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "approved"})
}

func (h *HTTPHandler) rejectAccessRequest(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	requestID := c.Param("accessRequestID")
	var body ApprovalDecision
	_ = c.ShouldBindJSON(&body) // Optional body - ignore error
	approverID := actorIDFromRequest(c)
	if approverID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "approver user id required"})
		return
	}

	if err := h.svc.RejectAccessRequest(c.Request.Context(), tenantID, requestID, approverID, body.Comment); err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "rejected"})
}

func (h *HTTPHandler) listIPPolicies(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	policies, err := h.svc.ListIPPolicies(c.Request.Context(), tenantID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

func (h *HTTPHandler) createIPPolicy(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	var req CreateIPPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind create ip policy request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy, err := h.svc.CreateIPPolicy(c.Request.Context(), tenantID, req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusCreated, policy)
}

func (h *HTTPHandler) deleteIPPolicy(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	id := c.Param("ipPolicyID")
	if err := h.svc.DeleteIPPolicy(c.Request.Context(), tenantID, id); err != nil {
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
	if errors.Is(err, oauthclient.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	h.logger.Error("governance service error", zap.Error(err))
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
}

func actorIDFromRequest(c *gin.Context) string {
	if userID := strings.TrimSpace(c.GetString("user_id")); userID != "" {
		return userID
	}
	if userID := strings.TrimSpace(c.GetHeader("X-User-ID")); userID != "" {
		return userID
	}
	return ""
}
