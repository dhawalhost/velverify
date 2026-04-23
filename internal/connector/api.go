package connector

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// HTTPHandler handles connector HTTP requests.
type HTTPHandler struct {
	svc    Service
	logger *zap.Logger
}

// NewHTTPHandler creates a new connector HTTP handler.
func NewHTTPHandler(svc Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger}
}

// RegisterRoutes registers connector routes.
func (h *HTTPHandler) RegisterRoutes(rg *gin.RouterGroup) {
	g := rg.Group("/connectors")
	{
		g.GET("", h.listConnectors)
		g.POST("", h.createConnector)
		g.GET("/:id", h.getConnector)
		g.PUT("/:id", h.updateConnector)
		g.DELETE("/:id", h.deleteConnector)
		g.POST("/:id/toggle", h.toggleConnector)
		g.POST("/test", h.testConnection)
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

func (h *HTTPHandler) listConnectors(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	connectors, err := h.svc.ListConnectors(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list connectors", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"connectors": connectors})
}

func (h *HTTPHandler) createConnector(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var config Config
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, err := h.svc.CreateConnector(c.Request.Context(), tenantID, config)
	if err != nil {
		h.logger.Error("Failed to create connector", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *HTTPHandler) getConnector(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	config, err := h.svc.GetConnector(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "connector not found"})
		return
	}

	c.JSON(http.StatusOK, config)
}

func (h *HTTPHandler) updateConnector(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var config Config
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	config.ID = c.Param("id")

	if err := h.svc.UpdateConnector(c.Request.Context(), tenantID, config); err != nil {
		h.logger.Error("Failed to update connector", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

func (h *HTTPHandler) deleteConnector(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	if err := h.svc.DeleteConnector(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to delete connector", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *HTTPHandler) toggleConnector(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := c.Param("id")
	if err := h.svc.ToggleConnector(c.Request.Context(), tenantID, id, req.Enabled); err != nil {
		h.logger.Error("Failed to toggle connector", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"enabled": req.Enabled})
}

func (h *HTTPHandler) testConnection(c *gin.Context) {
	// For testing, tenant ID isn't strictly necessary but good practice
	_, ok := h.tenantID(c)
	if !ok {
		return
	}

	var config Config
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.TestConnection(c.Request.Context(), config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "status": "failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
