package directory

import (
	"errors"
	"net/http"

	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

// HTTPHandler represents the HTTP API handlers for the directory service.
type HTTPHandler struct {
	svc         Service
	logger      *zap.Logger
	validate    *validator.Validate
	serviceAuth middleware.ServiceAuthConfig
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, logger *zap.Logger, cfg HTTPHandlerConfig) *HTTPHandler {
	serviceAuth := middleware.ServiceAuthConfig{
		HeaderName: cfg.ServiceAuthHeader,
		Token:      cfg.ServiceAuthToken,
	}
	return &HTTPHandler{svc: svc, logger: logger, validate: validator.New(), serviceAuth: serviceAuth}
}

// HTTPHandlerConfig controls optional behavior for the HTTP handler.
type HTTPHandlerConfig struct {
	ServiceAuthToken  string
	ServiceAuthHeader string
}

// RegisterRoutes registers the directory routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	// Health check
	router.GET("/health", h.healthCheck)

	tenantProtected := router.Group("/")
	tenantProtected.Use(middleware.TenantExtractor(middleware.TenantConfig{
		SlugResolver: h.svc.GetTenantIDBySlug,
	}))

	internalRoutes := router.Group("/internal")
	internalRoutes.Use(middleware.ServiceAuthenticator(h.serviceAuth))
	internalRoutes.Use(middleware.TenantExtractor(middleware.TenantConfig{
		SlugResolver: h.svc.GetTenantIDBySlug,
	}))
	internalRoutes.POST("/credentials/verify", h.verifyCredentials)

	// Global internal routes (no tenant context required)
	globalInternalRoutes := router.Group("/internal")
	globalInternalRoutes.Use(middleware.ServiceAuthenticator(h.serviceAuth))
	globalInternalRoutes.GET("/discover", h.discoverTenant)
	globalInternalRoutes.GET("/tenants/resolve", h.resolveTenantSlug)

	// Tenant Management
	router.POST("/tenants", h.createTenant)

	// User routes
	users := tenantProtected.Group("/users")
	{
		users.POST("", h.createUser)
		users.GET("/:id", h.getUserByID)
		users.GET("", h.listUsers) // Handles both List and GetByEmail
		users.PUT("/:id", h.updateUser)
		users.DELETE("/:id", h.deleteUser)
	}

	// Group routes
	groups := tenantProtected.Group("/groups")
	{
		groups.POST("", h.createGroup)
		groups.GET("/:id", h.getGroupByID)
		groups.PUT("/:id", h.updateGroup)
		groups.DELETE("/:id", h.deleteGroup)
	}

	// Group membership routes
	groupMembership := groups.Group(":id/users")
	{
		groupMembership.POST("", h.addUserToGroup)
		groupMembership.DELETE("/:userID", h.removeUserFromGroup)
	}

	// User-Organization mappings (within a tenant)
	userOrgs := tenantProtected.Group("/users/:id/organizations")
	{
		userOrgs.POST("/:orgID", h.addUserToOrganization)
		userOrgs.DELETE("/:orgID", h.removeUserFromOrganization)
		userOrgs.GET("", h.listUserOrganizations)
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
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
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
		if errors.Is(err, ErrEmailAlreadyExistsGlobally) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, CreateUserResponse{UserID: userID})
}

func (h *HTTPHandler) getUserByID(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
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

func (h *HTTPHandler) listUsers(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	// Check if this is a GetByEmail request
	email := c.Query("email")
	if email != "" {
		req := GetUserByEmailRequest{Email: email}
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
		return
	}

	// Otherwise, it's a List request
	var req ListUsersRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Limit <= 0 {
		req.Limit = 10
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	users, total, err := h.svc.ListUsers(c.Request.Context(), tenantID, req.Limit, req.Offset)
	if err != nil {
		h.logger.Error("List users failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ListUsersResponse{Users: users, Total: total})
}

func (h *HTTPHandler) updateUser(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
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
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
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
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
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
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
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
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	id := c.Param("id")
	var group Group
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
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
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
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	groupID := c.Param("id")
	var req AddUserToGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind add user to group request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.GroupID = groupID
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
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
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

func (h *HTTPHandler) verifyCredentials(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	var req VerifyCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind verify credentials request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Verify credentials request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.svc.VerifyCredentials(c.Request.Context(), tenantID, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidCredentials.Error()})
			return
		}
		h.logger.Error("Verify credentials failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, VerifyCredentialsResponse{User: user})
}

func (h *HTTPHandler) discoverTenant(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email required"})
		return
	}

	tenantID, err := h.svc.GetTenantByEmail(c.Request.Context(), email)
	if err != nil {
		h.logger.Error("Discover tenant failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if tenantID == "" {
		c.Status(http.StatusNotFound)
		return
	}

	c.JSON(http.StatusOK, gin.H{"tenant_id": tenantID})
}

func (h *HTTPHandler) tenantID(c *gin.Context) (string, bool) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		h.logger.Error("tenant id missing", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return "", false
	}
	return tenantID, true
}

type CreateTenantRequest struct {
	ID   string `json:"id" binding:"required"`
	Name string `json:"name" binding:"required"`
	Slug string `json:"slug" binding:"required"`
	Plan string `json:"plan"`
}

func (h *HTTPHandler) createTenant(c *gin.Context) {
	var req CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	plan := req.Plan
	if plan == "" {
		plan = "default" // or "free"
	}

	if err := h.svc.CreateTenant(c.Request.Context(), req.ID, req.Name, req.Slug, plan); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{"error": "tenant already exists"})
			return
		}
		h.logger.Error("Failed to create tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create tenant"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "tenant created successfully"})
}

func (h *HTTPHandler) resolveTenantSlug(c *gin.Context) {
	slug := c.Query("slug")
	if slug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "slug is required"})
		return
	}
	tenantID, err := h.svc.GetTenantIDBySlug(c.Request.Context(), slug)
	if err != nil {
		h.logger.Error("Failed to resolve tenant slug", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve tenant slug"})
		return
	}
	if tenantID == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tenant_id": tenantID})
}
func (h *HTTPHandler) addUserToOrganization(c *gin.Context) {
	tenantID, _ := h.tenantID(c)
	userID := c.Param("id")
	orgID := c.Param("orgID")
	var req struct {
		Role string `json:"role"`
	}
	_ = c.ShouldBindJSON(&req)

	if err := h.svc.AddUserToOrganization(c.Request.Context(), tenantID, userID, orgID, req.Role); err != nil {
		h.logger.Error("Add user to organization failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add user to organization"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user added to organization"})
}

func (h *HTTPHandler) removeUserFromOrganization(c *gin.Context) {
	tenantID, _ := h.tenantID(c)
	userID := c.Param("id")
	orgID := c.Param("orgID")

	if err := h.svc.RemoveUserFromOrganization(c.Request.Context(), tenantID, userID, orgID); err != nil {
		h.logger.Error("Remove user from organization failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove user from organization"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user removed from organization"})
}

func (h *HTTPHandler) listUserOrganizations(c *gin.Context) {
	tenantID, _ := h.tenantID(c)
	userID := c.Param("id")

	orgIDs, err := h.svc.ListUserOrganizations(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("List user organizations failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list user organizations"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"organization_ids": orgIDs})
}
