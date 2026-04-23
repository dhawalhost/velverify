package audit

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// HTTPHandler handles audit log HTTP requests.
type HTTPHandler struct {
	svc    Service
	logger *zap.Logger
}

// NewHTTPHandler creates a new audit HTTP handler.
func NewHTTPHandler(svc Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger}
}

// RegisterRoutes registers audit routes.
func (h *HTTPHandler) RegisterRoutes(rg *gin.RouterGroup) {
	audit := rg.Group("/audit")
	{
		audit.GET("", h.queryLogs)
		audit.GET("/stats", h.getStats)
		audit.GET("/export", h.exportLogs)
		audit.GET("/:id", h.getEvent)
	}
}

func (h *HTTPHandler) tenantID(c *gin.Context) (string, bool) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return "", false
	}
	return tenantID, true
}

func (h *HTTPHandler) queryLogs(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	params := QueryParams{TenantID: tenantID}

	// Parse query parameters
	if v := c.Query("actor_id"); v != "" {
		params.ActorID = &v
	}
	if v := c.Query("action"); v != "" {
		params.Action = &v
	}
	if v := c.Query("resource_type"); v != "" {
		params.ResourceType = &v
	}
	if v := c.Query("resource_id"); v != "" {
		params.ResourceID = &v
	}
	if v := c.Query("outcome"); v != "" {
		params.Outcome = &v
	}
	if v := c.Query("start_time"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.StartTime = &t
		}
	}
	if v := c.Query("end_time"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.EndTime = &t
		}
	}
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			params.Limit = n
		}
	}
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			params.Offset = n
		}
	}

	events, total, err := h.svc.Query(c.Request.Context(), params)
	if err != nil {
		h.logger.Error("Failed to query audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  total,
		"limit":  params.Limit,
		"offset": params.Offset,
	})
}

func (h *HTTPHandler) getEvent(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	event, err := h.svc.GetEvent(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}
	c.JSON(http.StatusOK, event)
}

func (h *HTTPHandler) getStats(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	lookbackDays := 7
	if v := c.Query("lookback_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lookbackDays = n
		}
	}

	stats, err := h.svc.GetStats(c.Request.Context(), tenantID, lookbackDays)
	if err != nil {
		h.logger.Error("Failed to get audit stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

func (h *HTTPHandler) exportLogs(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	params := QueryParams{TenantID: tenantID}

	// Parse query parameters
	if v := c.Query("actor_id"); v != "" {
		params.ActorID = &v
	}
	if v := c.Query("action"); v != "" {
		params.Action = &v
	}
	if v := c.Query("resource_type"); v != "" {
		params.ResourceType = &v
	}
	if v := c.Query("resource_id"); v != "" {
		params.ResourceID = &v
	}
	if v := c.Query("outcome"); v != "" {
		params.Outcome = &v
	}
	if v := c.Query("start_time"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.StartTime = &t
		}
	}
	if v := c.Query("end_time"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.EndTime = &t
		}
	}

	events, err := h.svc.Export(c.Request.Context(), params)
	if err != nil {
		h.logger.Error("Failed to export audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename=audit_logs.csv")

	writer := csv.NewWriter(c.Writer)

	// Header
	_ = writer.Write([]string{"Time", "Actor ID", "Actor Type", "Action", "Resource Type", "Resource Name", "Outcome", "IP Address"})

	for _, e := range events {
		_ = writer.Write([]string{
			e.Timestamp.Format(time.RFC3339),
			strVal(e.ActorID),
			e.ActorType,
			e.Action,
			e.ResourceType,
			strVal(e.ResourceName),
			e.Outcome,
			strVal(e.IPAddress),
		})
	}
	writer.Flush()
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
