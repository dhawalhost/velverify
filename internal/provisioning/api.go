package provisioning

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// HTTPHandler represents the HTTP API handlers for the provisioning service.
type HTTPHandler struct {
	svc    Service
	logger *zap.Logger
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger}
}

// RegisterRoutes registers the provisioning routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	router.GET("/health", h.healthCheck)
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
