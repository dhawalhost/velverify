package auth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// IngestSignalRequest defines the payload for ingestion.
type IngestSignalRequest struct {
	SubjectID string `json:"subject_id" binding:"required"`
	EventType string `json:"event_type" binding:"required"`
	Reason    string `json:"reason"`
}

// ingestSignal handles the POST /api/v1/signals/ingest
func (h *HTTPHandler) ingestSignal(c *gin.Context) {
	var req IngestSignalRequest
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

	event := &SecurityEvent{
		TenantID:  tenantID,
		SubjectID: req.SubjectID,
		EventType: req.EventType,
		Reason:    req.Reason,
		EventTime: time.Now(),
	}

	if err := h.svc.Signal().Ingest(c.Request.Context(), event); err != nil {
		h.logger.Error("Failed to ingest signal", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to ingest signal"})
		return
	}

	c.Status(http.StatusAccepted)
}
