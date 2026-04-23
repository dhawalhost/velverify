package governance

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// EndpointHandler handles device registration and trust.
type EndpointHandler struct {
	svc    Service
	logger *zap.Logger
}

func NewEndpointHandler(svc Service, logger *zap.Logger) *EndpointHandler {
	return &EndpointHandler{svc: svc, logger: logger}
}

func (h *EndpointHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("/governance/endpoints/register", h.registerDevice)
	rg.GET("/governance/endpoints", h.listDevices)
	rg.GET("/governance/endpoints/:id", h.getDevice)
	rg.PUT("/governance/endpoints/:id/status", h.updateDeviceStatus)
}

func (h *EndpointHandler) registerDevice(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}

	var d Device
	if err := c.ShouldBindJSON(&d); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Associate with current user
	if userID := actorIDFromRequest(c); userID != "" {
		d.UserID = userID
	}

	id, err := h.svc.RegisterDevice(c.Request.Context(), tenantID, d)
	if err != nil {
		h.logger.Error("Failed to register device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register device"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "pending"})
}

func (h *EndpointHandler) listDevices(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}

	devices, err := h.svc.ListDevices(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"devices": devices})
}

func (h *EndpointHandler) getDevice(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}

	id := c.Param("id")
	device, err := h.svc.GetDevice(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	c.JSON(http.StatusOK, device)
}

func (h *EndpointHandler) updateDeviceStatus(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}

	id := c.Param("id")
	var req struct {
		Status string `json:"status" binding:"required,oneof=trusted untrusted pending"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.UpdateDeviceStatus(c.Request.Context(), tenantID, id, req.Status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": req.Status})
}

func tenantIDFromContext(c *gin.Context) (string, bool) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return "", false
	}
	return tenantID, true
}
