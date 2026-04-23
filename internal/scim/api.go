package scim

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/internal/directory"
	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// HTTPHandler handles SCIM HTTP requests.
type HTTPHandler struct {
	svc              *Service
	logger           *zap.Logger
	repo             directory.Repository
	serviceAuthToken string // internal service token
}

// NewHTTPHandler creates a new SCIM HTTP handler.
func NewHTTPHandler(svc *Service, repo directory.Repository, serviceAuthToken string, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, repo: repo, serviceAuthToken: serviceAuthToken, logger: logger}
}

// RegisterRoutes registers SCIM endpoints.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	group := router.Group("/scim/v2")

	// Apply SCIM specific Bearer token authentication
	group.Use(directory.RequireSCIMBearerToken(h.repo, h.logger, h.serviceAuthToken))
	group.Use(scimContentType())

	// SCIM Metadata Endpoints
	group.GET("/ServiceProviderConfig", h.getServiceProviderConfig)
	group.GET("/ResourceTypes", h.getResourceTypes)
	group.GET("/Schemas", h.getSchemas)

	group.GET("/Users", h.listUsers)
	group.GET("/Users/:id", h.getUser)
	group.POST("/Users", h.createUser)
	group.PUT("/Users/:id", h.replaceUser)
	group.PATCH("/Users/:id", h.patchUser)
	group.DELETE("/Users/:id", h.deleteUser)

	// Group endpoints
	group.GET("/Groups", h.listGroups)
	group.GET("/Groups/:id", h.getGroup)
	group.POST("/Groups", h.createGroup)
	group.PUT("/Groups/:id", h.replaceGroup)
	group.PATCH("/Groups/:id", h.patchGroup)
	group.DELETE("/Groups/:id", h.deleteGroup)
}

func scimContentType() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "application/scim+json")
		c.Next()
	}
}

func (h *HTTPHandler) listUsers(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}

	filter := c.Query("filter")
	startIndex, _ := strconv.Atoi(c.DefaultQuery("startIndex", "1"))
	count, _ := strconv.Atoi(c.DefaultQuery("count", "100"))

	resp, err := h.svc.ListUsers(c.Request.Context(), tenantID, filter, startIndex, count)
	if err != nil {
		h.logger.Error("Failed to list SCIM users", zap.Error(err))
		h.respondError(c, http.StatusInternalServerError, "Internal server error", "")
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *HTTPHandler) getUser(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}
	id := c.Param("id")
	user, err := h.svc.GetUser(c.Request.Context(), tenantID, id)
	if err != nil {
		h.logger.Error("Failed to get SCIM user", zap.Error(err))
		h.respondError(c, http.StatusNotFound, "Resource not found", "")
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *HTTPHandler) createUser(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}

	var req User
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid syntax", "scimType invalidSyntax")
		return
	}

	user, err := h.svc.CreateUser(c.Request.Context(), tenantID, req)
	if err != nil {
		h.logger.Error("Failed to create SCIM user", zap.Error(err))
		h.respondError(c, http.StatusInternalServerError, "Internal server error", "")
		return
	}

	c.JSON(http.StatusCreated, user)
}

func (h *HTTPHandler) respondError(c *gin.Context, status int, detail, scimType string) {
	resp := Error{
		Schemas:  []string{ErrorSchema},
		Status:   fmt.Sprintf("%d", status),
		Detail:   detail,
		ScimType: scimType,
	}
	c.JSON(status, resp)
}

func (h *HTTPHandler) replaceUser(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}
	id := c.Param("id")

	var req User
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid syntax", "invalidSyntax")
		return
	}

	user, err := h.svc.ReplaceUser(c.Request.Context(), tenantID, id, req)
	if err != nil {
		h.logger.Error("Failed to replace SCIM user", zap.Error(err))
		h.respondError(c, http.StatusInternalServerError, "Internal server error", "")
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *HTTPHandler) patchUser(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}
	id := c.Param("id")

	var req PatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid syntax", "invalidSyntax")
		return
	}

	user, err := h.svc.PatchUser(c.Request.Context(), tenantID, id, req.Operations)
	if err != nil {
		h.logger.Error("Failed to patch SCIM user", zap.Error(err))
		h.respondError(c, http.StatusInternalServerError, "Internal server error", "")
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *HTTPHandler) deleteUser(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}
	id := c.Param("id")

	if err := h.svc.DeleteUser(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to delete SCIM user", zap.Error(err))
		h.respondError(c, http.StatusNotFound, "Resource not found", "")
		return
	}
	c.Status(http.StatusNoContent)
}

// ========== Group Handlers ==========

func (h *HTTPHandler) listGroups(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}

	startIndex, _ := strconv.Atoi(c.DefaultQuery("startIndex", "1"))
	count, _ := strconv.Atoi(c.DefaultQuery("count", "100"))

	resp, err := h.svc.ListGroups(c.Request.Context(), tenantID, startIndex, count)
	if err != nil {
		h.logger.Error("Failed to list SCIM groups", zap.Error(err))
		h.respondError(c, http.StatusInternalServerError, "Internal server error", "")
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *HTTPHandler) getGroup(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}
	id := c.Param("id")
	group, err := h.svc.GetGroup(c.Request.Context(), tenantID, id)
	if err != nil {
		h.logger.Error("Failed to get SCIM group", zap.Error(err))
		h.respondError(c, http.StatusNotFound, "Resource not found", "")
		return
	}
	c.JSON(http.StatusOK, group)
}

func (h *HTTPHandler) createGroup(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}

	var req Group
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid syntax", "invalidSyntax")
		return
	}

	group, err := h.svc.CreateGroup(c.Request.Context(), tenantID, req)
	if err != nil {
		h.logger.Error("Failed to create SCIM group", zap.Error(err))
		h.respondError(c, http.StatusInternalServerError, "Internal server error", "")
		return
	}
	c.JSON(http.StatusCreated, group)
}

func (h *HTTPHandler) replaceGroup(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}
	id := c.Param("id")

	var req Group
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid syntax", "invalidSyntax")
		return
	}

	group, err := h.svc.ReplaceGroup(c.Request.Context(), tenantID, id, req)
	if err != nil {
		h.logger.Error("Failed to replace SCIM group", zap.Error(err))
		h.respondError(c, http.StatusInternalServerError, "Internal server error", "")
		return
	}
	c.JSON(http.StatusOK, group)
}

func (h *HTTPHandler) patchGroup(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}
	id := c.Param("id")

	var req PatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid syntax", "invalidSyntax")
		return
	}

	group, err := h.svc.PatchGroup(c.Request.Context(), tenantID, id, req.Operations)
	if err != nil {
		h.logger.Error("Failed to patch SCIM group", zap.Error(err))
		h.respondError(c, http.StatusInternalServerError, "Internal server error", "")
		return
	}
	c.JSON(http.StatusOK, group)
}

func (h *HTTPHandler) deleteGroup(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "invalid tenant", "")
		return
	}
	id := c.Param("id")

	if err := h.svc.DeleteGroup(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to delete SCIM group", zap.Error(err))
		h.respondError(c, http.StatusNotFound, "Resource not found", "")
		return
	}
	c.Status(http.StatusNoContent)
}
