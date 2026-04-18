package policy

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// HTTPHandler represents the HTTP API handlers for the policy service.
type HTTPHandler struct {
	svc    Service
	logger *zap.Logger
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger}
}

// RegisterRoutes registers the policy routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	router.GET("/health", h.healthCheck)
	
	api := router.Group("/api/v1/policies")
	{
		api.GET("", h.listPolicies)
		api.POST("", h.createPolicy)
		api.GET("/:id", h.getPolicy)
		api.PUT("/:id", h.updatePolicy)
		api.DELETE("/:id", h.deletePolicy)
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

// HealthCheckResponse represents a health check response.
type HealthCheckResponse struct {
	Healthy bool `json:"healthy"`
}

func (h *HTTPHandler) listPolicies(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header is required"})
		return
	}

	policies, err := h.svc.ListPolicies(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

func (h *HTTPHandler) createPolicy(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header is required"})
		return
	}

	var req Policy
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.TenantID = tenantID // Ensure tenant isolation

	id, err := h.svc.CreatePolicy(c.Request.Context(), req)
	if err != nil {
		h.logger.Error("Failed to create policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *HTTPHandler) getPolicy(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	id := c.Param("id")
	if tenantID == "" || id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID and policy ID are required"})
		return
	}

	policy, err := h.svc.GetPolicy(c.Request.Context(), tenantID, id)
	if err != nil {
		h.logger.Error("Failed to get policy", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get policy"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

func (h *HTTPHandler) updatePolicy(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	id := c.Param("id")
	if tenantID == "" || id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID and policy ID are required"})
		return
	}

	var req Policy
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.ID = id
	req.TenantID = tenantID

	if err := h.svc.UpdatePolicy(c.Request.Context(), req); err != nil {
		h.logger.Error("Failed to update policy", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *HTTPHandler) deletePolicy(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	id := c.Param("id")
	if tenantID == "" || id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID and policy ID are required"})
		return
	}

	if err := h.svc.DeletePolicy(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to delete policy", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}
