package governance

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/internal/auth"
	"github.com/dhawalhost/wardseal/internal/authz"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/webhook"
	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// HTTPHandler represents the HTTP API handlers for the governance service.
type HTTPHandler struct {
	svc             Service
	campaignHandler *CampaignHTTPHandler
	webhookHandler  *WebhookHTTPHandler
	orgHandler      *OrganizationHandler
	safetyHandler   *SafetyHandler
	endpointHandler *EndpointHandler
	logger          *zap.Logger
}

type HealthCheckResponse struct {
	Healthy bool `json:"healthy"`
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, campaignSvc CampaignService, webhookSvc webhook.Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{
		svc:             svc,
		campaignHandler: NewCampaignHTTPHandler(campaignSvc, logger),
		webhookHandler:  NewWebhookHTTPHandler(webhookSvc, logger),
		orgHandler:      NewOrganizationHandler(svc, logger),
		safetyHandler:   NewSafetyHandler(svc, logger),
		endpointHandler: NewEndpointHandler(svc, logger),
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
	tenantGroup.GET("/governance/stats", h.getDashboardStats)

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

	workloads := tenantGroup.Group("/governance/workloads")
	{
		workloads.GET("", h.listWorkloads)
		workloads.POST("", h.createWorkload)
	}

	relationships := tenantGroup.Group("/governance/relationships")
	{
		relationships.GET("", h.listRelationships)
	}

	graph := tenantGroup.Group("/governance/graph")
	{
		graph.GET("/traverse", h.traverseGraph)
	}

	// Registered combined routes
	h.orgHandler.RegisterRoutes(tenantGroup)
	h.campaignHandler.RegisterRoutes(tenantGroup)
	h.webhookHandler.RegisterRoutes(tenantGroup)
	h.safetyHandler.RegisterRoutes(tenantGroup)
	h.endpointHandler.RegisterRoutes(tenantGroup)
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
	if req.DeviceID == "" {
		req.DeviceID = c.GetHeader("X-Device-ID")
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

func (h *HTTPHandler) getDashboardStats(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	stats, err := h.svc.GetDashboardStats(c.Request.Context(), tenantID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, stats)
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

func (h *HTTPHandler) listWorkloads(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	workloads, err := h.svc.ListWorkloads(c.Request.Context(), tenantID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	responses := make([]WorkloadResponse, 0, len(workloads))
	for _, w := range workloads {
		resp := WorkloadResponse{
			ID:            w.ID,
			Name:          w.Name,
			ServiceHandle: w.ServiceHandle,
			Status:        w.Status,
		}
		if w.LastUsedAt != nil {
			resp.LastUsedAt = w.LastUsedAt.Format(time.RFC3339)
		}
		responses = append(responses, resp)
	}
	c.JSON(http.StatusOK, gin.H{"workloads": responses})
}

func (h *HTTPHandler) createWorkload(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	// Note: In a real scenario, we would use a specific request DTO
	var w auth.Workload
	if err := c.ShouldBindJSON(&w); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id, err := h.svc.CreateWorkload(c.Request.Context(), tenantID, w)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *HTTPHandler) listRelationships(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	query := authz.Query{
		Namespace:   c.Query("namespace"),
		ObjectID:    c.Query("object_id"),
		Relation:    c.Query("relation"),
		SubjectType: c.Query("subject_type"),
		SubjectID:   c.Query("subject_id"),
	}

	tuples, err := h.svc.ListRelationships(c.Request.Context(), tenantID, query)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"relationships": tuples})
}

func (h *HTTPHandler) traverseGraph(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	subjectID := c.Query("subject_id")
	if subjectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "subject_id required"})
		return
	}

	results, err := h.svc.TraverseGraph(c.Request.Context(), tenantID, subjectID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, results)
}
