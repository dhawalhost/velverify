package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// RegisterDeviceRequest defines the payload for registering a device.
type RegisterDeviceRequest struct {
	DeviceIdentifier string `json:"device_identifier" binding:"required"`
	OS               string `json:"os" binding:"required"`
	OSVersion        string `json:"os_version"`
	IsManaged        bool   `json:"is_managed"`
}

// UpdatePostureRequest defines the payload for updating device posture.
type UpdatePostureRequest struct {
	IsCompliant bool `json:"is_compliant"`
	RiskScore   int  `json:"risk_score"`
}

// registerDevice handles the POST /api/v1/devices/register
func (h *HTTPHandler) registerDevice(c *gin.Context) {
	var req RegisterDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		h.logger.Error("Failed to extract tenant ID", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	userID := c.Request.Header.Get("X-User-ID")
	if userID == "" {
		userID = AnonymousUserID // Placeholder for unauthenticated device registration
	}

	device := &Device{
		TenantID:         tenantID,
		UserID:           userID,
		DeviceIdentifier: req.DeviceIdentifier,
		OS:               req.OS,
		OSVersion:        req.OSVersion,
		IsManaged:        req.IsManaged,
		IsCompliant:      true, // Default to compliant on registration
		LastSeenAt:       time.Now(),
	}

	if err := h.svc.Device().Register(c.Request.Context(), device); err != nil {
		h.logger.Error("Failed to register device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register device"})
		return
	}

	c.JSON(http.StatusCreated, device)
}

// updatePosture handles POST /api/v1/devices/{id}/posture
func (h *HTTPHandler) updatePosture(c *gin.Context) {
	id := c.Param("id")
	var req UpdatePostureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		h.logger.Error("Failed to extract tenant ID", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	device, err := h.svc.Device().GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to fetch device for posture update", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify device ownership"})
		return
	}

	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	if device.TenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "device does not belong to this tenant"})
		return
	}

	if err := h.svc.Device().UpdatePosture(c.Request.Context(), id, req.IsCompliant, req.RiskScore); err != nil {
		h.logger.Error("Failed to update posture", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update device posture"})
		return
	}

	c.Status(http.StatusOK)
}

// listDevices handles GET /api/v1/devices
func (h *HTTPHandler) listDevices(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		h.logger.Error("Failed to extract tenant ID", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	devices, err := h.svc.Device().List(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list devices", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list devices"})
		return
	}

	c.JSON(http.StatusOK, devices)
}

// deleteDevice handles DELETE /api/v1/devices/{id}
func (h *HTTPHandler) deleteDevice(c *gin.Context) {
	id := c.Param("id")

	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		h.logger.Error("Failed to extract tenant ID", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	device, err := h.svc.Device().GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to fetch device for deletion", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify device ownership"})
		return
	}

	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	if device.TenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "device does not belong to this tenant"})
		return
	}

	if err := h.svc.Device().Delete(c.Request.Context(), id); err != nil {
		h.logger.Error("Failed to delete device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete device"})
		return
	}

	c.Status(http.StatusNoContent)
}

// CrowdStrikeWebhook defines the payload for CrowdStrike ZTA.
type CrowdStrikeWebhook struct {
	DeviceID string  `json:"device_id"`
	ZTA      float64 `json:"zta_score"`
}

// JamfWebhook defines the payload for Jamf compliance.
type JamfWebhook struct {
	DeviceID         string `json:"device_id"`
	ComplianceStatus string `json:"compliance_status"`
}

// handleWebhook handles POST /api/v1/devices/webhooks/:provider
func (h *HTTPHandler) handleWebhook(c *gin.Context) {
	provider := c.Param("provider")
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		h.logger.Error("Failed to extract tenant ID", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	var isCompliant bool
	var riskScore int
	var deviceID string

	switch provider {
	case "crowdstrike":
		var req CrowdStrikeWebhook
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		deviceID = req.DeviceID
		isCompliant = req.ZTA >= 50
		riskScore = int(100 - req.ZTA)

	case "jamf":
		var req JamfWebhook
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		deviceID = req.DeviceID
		isCompliant = req.ComplianceStatus == "Compliant"
		if isCompliant {
			riskScore = 0
		} else {
			riskScore = 80
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider"})
		return
	}

	// Find device
	device, err := h.svc.Device().GetByID(c.Request.Context(), deviceID)
	if err != nil {
		h.logger.Error("Failed to fetch device for webhook", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify device"})
		return
	}
	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	if device.TenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "device does not belong to this tenant"})
		return
	}

	// Update Posture
	if err := h.svc.Device().UpdatePosture(c.Request.Context(), deviceID, isCompliant, riskScore); err != nil {
		h.logger.Error("Failed to update posture from webhook", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update device posture"})
		return
	}

	// Ingest Security Event if not compliant
	if !isCompliant {
		event := &SecurityEvent{
			SubjectID: device.UserID,
			TenantID:  tenantID,
			EventType: "device-posture-violation",
			EventTime: time.Now(),
			Reason:    fmt.Sprintf("EDR (%s) reported non-compliance", provider),
		}
		_ = h.svc.Signal().Ingest(c.Request.Context(), event)
	}

	c.Status(http.StatusOK)
}
