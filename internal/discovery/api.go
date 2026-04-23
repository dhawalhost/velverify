package discovery

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/eventbus"
	"github.com/dhawalhost/wardseal/pkg/middleware"
)

const (
	TopicDiscoveryScanRequested = "discovery.scan.requested"
)

// ScanRequestedEvent is the payload for the discovery.scan.requested topic.
type ScanRequestedEvent struct {
	JobID    string `json:"job_id"`
	TenantID string `json:"tenant_id"`
}

// HTTPHandler represents the HTTP API handlers for the discovery service.
type HTTPHandler struct {
	svc       Service
	repo      Repository
	jobs      JobStore
	publisher eventbus.Publisher
	logger    *zap.Logger
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, repo Repository, jobs JobStore, publisher eventbus.Publisher, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{
		svc:       svc,
		repo:      repo,
		jobs:      jobs,
		publisher: publisher,
		logger:    logger,
	}
}

// RegisterRoutes registers the discovery routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.RouterGroup) {
	api := router.Group("/governance/discovery")
	{
		api.GET("/resources", h.listResources)
		api.POST("/scan", h.triggerScan)
		api.GET("/jobs/:id", h.getScanStatus)
	}
}

func (h *HTTPHandler) listResources(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filter := c.Query("filter")
	resources, err := h.repo.List(c.Request.Context(), tenantID, filter)
	if err != nil {
		h.logger.Error("Failed to list discovered resources", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list resources"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"resources": resources})
}

func (h *HTTPHandler) triggerScan(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	jobID := uuid.New().String()

	// 1. Create job state in Redis
	if err := h.jobs.Create(c.Request.Context(), jobID, tenantID); err != nil {
		h.logger.Error("Failed to create discovery job", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize scan"})
		return
	}

	// 2. Publish event to EventBus
	event := ScanRequestedEvent{
		JobID:    jobID,
		TenantID: tenantID,
	}
	payload, _ := json.Marshal(event)

	if err := h.publisher.Publish(c.Request.Context(), TopicDiscoveryScanRequested, payload); err != nil {
		h.logger.Error("Failed to publish discovery event", zap.Error(err))

		// Cleanup the failed job state
		// (In a high-scale system, we'd rely on TTL, but here we can try to be clean)
		_ = h.jobs.Update(c.Request.Context(), jobID, func(s *JobState) {
			s.Status = JobStatusFailed
			s.Message = "Internal event bus failure"
		})

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to queue scan"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"job_id":  jobID,
		"message": "Discovery scan queued successfully",
	})
}

func (h *HTTPHandler) getScanStatus(c *gin.Context) {
	jobID := c.Param("id")
	if jobID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Job ID is required"})
		return
	}

	state, err := h.jobs.Get(c.Request.Context(), jobID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	// Security: Ensure the job belongs to the requesting tenant
	requestTenantID, _ := middleware.TenantIDFromGinContext(c)
	if requestTenantID != "" && state.TenantID != requestTenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to discovery job"})
		return
	}

	c.JSON(http.StatusOK, state)
}
