package directory

import (
	"net/http"

	"github.com/dhawalhost/velverify/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

// HTTPHandler represents the HTTP API handlers for the directory service.
type HTTPHandler struct {
	svc    Service
	logger *zap.Logger
	validate *validator.Validate
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger, validate: validator.New()}
}

// RegisterRoutes registers the directory routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	// Health check
	router.GET("/health", h.healthCheck)

	// User routes
	users := router.Group("/users")
	{
		users.POST("", h.createUser)
		users.GET("/:id", h.getUserByID)
		users.GET("", h.getUserByEmail) // /users?email=...
		users.PUT("/:id", h.updateUser)
		users.DELETE("/:id", h.deleteUser)
	}

	// Group routes
	groups := router.Group("/groups")
	{
		groups.POST("", h.createGroup)
		groups.GET("/:id", h.getGroupByID)
		groups.PUT("/:id", h.updateGroup)
		groups.DELETE("/:id", h.deleteGroup)
	}

	// Group membership routes
	groupMembership := router.Group("/groups/:id/users")
	{
		groupMembership.POST("", h.addUserToGroup)
		groupMembership.DELETE("/:userID", h.removeUserFromGroup)
	}
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

// User handlers
func (h *HTTPHandler) createUser(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind create user request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Create user request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := h.svc.CreateUser(c.Request.Context(), tenantID, req.User)
	if err != nil {
		h.logger.Error("Create user failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, CreateUserResponse{UserID: userID})
}

func (h *HTTPHandler) getUserByID(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	req := GetUserByIDRequest{ID: c.Param("id")} // Extract ID from param
	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Get user by ID request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.svc.GetUserByID(c.Request.Context(), tenantID, req.ID)
	if err != nil {
		h.logger.Error("Get user by ID failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, GetUserByIDResponse{User: user})
}

func (h *HTTPHandler) getUserByEmail(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	req := GetUserByEmailRequest{Email: c.Query("email")} // Extract email from query
	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Get user by email request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.svc.GetUserByEmail(c.Request.Context(), tenantID, req.Email)
	if err != nil {
		h.logger.Error("Get user by email failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, GetUserByEmailResponse{User: user})
}

func (h *HTTPHandler) updateUser(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	id := c.Param("id")
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		h.logger.Error("Failed to bind update user request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req := UpdateUserRequest{ID: id, User: user} // Create UpdateUserRequest
	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Update user request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.svc.UpdateUser(c.Request.Context(), tenantID, id, req.User)
	if err != nil {
		h.logger.Error("Update user failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusOK)
}

func (h *HTTPHandler) deleteUser(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	req := DeleteUserRequest{ID: c.Param("id")} // Extract ID from param
	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Delete user request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.svc.DeleteUser(c.Request.Context(), tenantID, req.ID)
	if err != nil {
		h.logger.Error("Delete user failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// Group handlers
func (h *HTTPHandler) createGroup(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	var req CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind create group request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Create group request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	groupID, err := h.svc.CreateGroup(c.Request.Context(), tenantID, req.Group)
	if err != nil {
		h.logger.Error("Create group failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, CreateGroupResponse{GroupID: groupID})
}

func (h *HTTPHandler) getGroupByID(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	req := GetGroupByIDRequest{ID: c.Param("id")} // Extract ID from param
	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Get group by ID request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group, err := h.svc.GetGroupByID(c.Request.Context(), tenantID, req.ID)
	if err != nil {
		h.logger.Error("Get group by ID failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, GetGroupByIDResponse{Group: group})
}

func (h *HTTPHandler) updateGroup(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	id := c.Param("id")
	var group User
	if err := c.ShouldBindJSON(&group); err != nil {
		h.logger.Error("Failed to bind update group request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req := UpdateGroupRequest{ID: id, Group: group} // Create UpdateGroupRequest
	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Update group request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.svc.UpdateGroup(c.Request.Context(), tenantID, id, req.Group)
	if err != nil {
		h.logger.Error("Update group failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusOK)
}

func (h *HTTPHandler) deleteGroup(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	req := DeleteGroupRequest{ID: c.Param("id")} // Extract ID from param
	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Delete group request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.svc.DeleteGroup(c.Request.Context(), tenantID, req.ID)
	if err != nil {
		h.logger.Error("Delete group failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// Group membership handlers
func (h *HTTPHandler) addUserToGroup(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	groupID := c.Param("id")
	var req AddUserToGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind add user to group request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Add user to group request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.svc.AddUserToGroup(c.Request.Context(), tenantID, req.UserID, groupID)
	if err != nil {
		h.logger.Error("Add user to group failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *HTTPHandler) removeUserFromGroup(c *gin.Context) {
	tenantID := "dummy-tenant-id" // Placeholder, should come from middleware/context
	groupID := c.Param("id")
	req := RemoveUserFromGroupRequest{GroupID: groupID, UserID: c.Param("userID")} // Create RemoveUserFromGroupRequest
	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Remove user from group request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := h.svc.RemoveUserFromGroup(c.Request.Context(), tenantID, req.UserID, req.GroupID)
	if err != nil {
		h.logger.Error("Remove user from group failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}
