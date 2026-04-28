package governance

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

type SafetyHandler struct {
	svc Service
	log *zap.Logger
}

func NewSafetyHandler(svc Service, log *zap.Logger) *SafetyHandler {
	return &SafetyHandler{svc: svc, log: log}
}

func (h *SafetyHandler) RegisterRoutes(rg *gin.RouterGroup) {
	safety := rg.Group("/safety")
	{
		safety.GET("/actions", h.ListActions)
		safety.POST("/actions/:id/confirm", h.ConfirmAction)
		safety.POST("/actions/:id/reject", h.RejectAction)
	}
}

func (h *SafetyHandler) ListActions(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return
	}
	status := c.Query("status")

	actions, err := h.svc.ListSafetyActions(c.Request.Context(), tenantID, status)
	if err != nil {
		h.log.Error("Failed to list safety actions", zap.Error(err), zap.String("tenant_id", tenantID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"actions": actions})
}

func (h *SafetyHandler) ConfirmAction(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return
	}
	actionID := c.Param("id")
	approverID := actorIDFromRequest(c)
	if approverID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "approver user id required"})
		return
	}

	var req ConfirmSafetyActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.svc.ConfirmSafetyAction(c.Request.Context(), tenantID, actionID, approverID, req.Comment)
	if err != nil {
		h.log.Error("Failed to confirm safety action", zap.Error(err), zap.String("action_id", actionID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Action confirmed successfully"})
}

func (h *SafetyHandler) RejectAction(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return
	}
	actionID := c.Param("id")
	approverID := actorIDFromRequest(c)
	if approverID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "approver user id required"})
		return
	}

	var req ConfirmSafetyActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.svc.RejectSafetyAction(c.Request.Context(), tenantID, actionID, approverID, req.Comment)
	if err != nil {
		h.log.Error("Failed to reject safety action", zap.Error(err), zap.String("action_id", actionID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Action rejected successfully"})
}
