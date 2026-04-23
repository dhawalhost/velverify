package rbac

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// HTTPHandler handles RBAC HTTP requests.
type HTTPHandler struct {
	svc    Service
	logger *zap.Logger
}

// NewHTTPHandler creates a new RBAC HTTP handler.
func NewHTTPHandler(svc Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger}
}

// RegisterRoutes registers RBAC routes.
func (h *HTTPHandler) RegisterRoutes(rg *gin.RouterGroup) {
	// Roles
	roles := rg.Group("/roles")
	{
		roles.POST("", h.createRole)
		roles.GET("", h.listRoles)
		roles.GET("/:id", h.getRole)
		roles.PUT("/:id", h.updateRole)
		roles.DELETE("/:id", h.deleteRole)
		roles.GET("/:id/permissions", h.getRolePermissions)
		roles.POST("/:id/permissions/:permId", h.assignPermissionToRole)
		roles.DELETE("/:id/permissions/:permId", h.removePermissionFromRole)
	}

	// Permissions
	perms := rg.Group("/permissions")
	{
		perms.POST("", h.createPermission)
		perms.GET("", h.listPermissions)
	}

	// User roles
	users := rg.Group("/users")
	{
		users.GET("/:userId/roles", h.getUserRoles)
		users.POST("/:userId/roles/:roleId", h.assignRoleToUser)
		users.DELETE("/:userId/roles/:roleId", h.removeRoleFromUser)
		users.GET("/:userId/permissions", h.getUserPermissions)
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

func (h *HTTPHandler) createRole(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	role, err := h.svc.CreateRole(c.Request.Context(), tenantID, body.Name, body.Description)
	if err != nil {
		h.logger.Error("Failed to create role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, role)
}

func (h *HTTPHandler) listRoles(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	roles, err := h.svc.ListRoles(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list roles", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

func (h *HTTPHandler) getRole(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	role, err := h.svc.GetRole(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	c.JSON(http.StatusOK, role)
}

func (h *HTTPHandler) updateRole(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	role, err := h.svc.UpdateRole(c.Request.Context(), tenantID, id, body.Name, body.Description)
	if err != nil {
		h.logger.Error("Failed to update role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, role)
}

func (h *HTTPHandler) deleteRole(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	if err := h.svc.DeleteRole(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to delete role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *HTTPHandler) getRolePermissions(c *gin.Context) {
	id := c.Param("id")
	perms, err := h.svc.GetRolePermissions(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get role permissions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"permissions": perms})
}

func (h *HTTPHandler) assignPermissionToRole(c *gin.Context) {
	roleID := c.Param("id")
	permID := c.Param("permId")

	if err := h.svc.AssignPermissionToRole(c.Request.Context(), roleID, permID); err != nil {
		h.logger.Error("Failed to assign permission", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "assigned"})
}

func (h *HTTPHandler) removePermissionFromRole(c *gin.Context) {
	roleID := c.Param("id")
	permID := c.Param("permId")

	if err := h.svc.RemovePermissionFromRole(c.Request.Context(), roleID, permID); err != nil {
		h.logger.Error("Failed to remove permission", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *HTTPHandler) createPermission(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var body struct {
		Resource    string `json:"resource"`
		Action      string `json:"action"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	perm, err := h.svc.CreatePermission(c.Request.Context(), tenantID, body.Resource, body.Action, body.Description)
	if err != nil {
		h.logger.Error("Failed to create permission", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, perm)
}

func (h *HTTPHandler) listPermissions(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	perms, err := h.svc.ListPermissions(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list permissions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"permissions": perms})
}

func (h *HTTPHandler) getUserRoles(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	userID := c.Param("userId")
	roles, err := h.svc.GetUserRoles(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("Failed to get user roles", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

func (h *HTTPHandler) assignRoleToUser(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	userID := c.Param("userId")
	roleID := c.Param("roleId")

	if err := h.svc.AssignRoleToUser(c.Request.Context(), tenantID, userID, roleID, nil); err != nil {
		h.logger.Error("Failed to assign role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "assigned"})
}

func (h *HTTPHandler) removeRoleFromUser(c *gin.Context) {
	userID := c.Param("userId")
	roleID := c.Param("roleId")

	if err := h.svc.RemoveRoleFromUser(c.Request.Context(), userID, roleID); err != nil {
		h.logger.Error("Failed to remove role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *HTTPHandler) getUserPermissions(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	userID := c.Param("userId")
	perms, err := h.svc.GetUserPermissions(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("Failed to get user permissions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"permissions": perms})
}
