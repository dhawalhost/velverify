package governance

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// OrganizationHandler handles organization API requests.
type OrganizationHandler struct {
	svc    Service
	logger *zap.Logger
}

// NewOrganizationHandler creates a new organization handler.
func NewOrganizationHandler(svc Service, logger *zap.Logger) *OrganizationHandler {
	return &OrganizationHandler{svc: svc, logger: logger}
}

// RegisterRoutes registers organization routes.
func (h *OrganizationHandler) RegisterRoutes(rg *gin.RouterGroup) {
	orgs := rg.Group("/organizations")
	{
		orgs.GET("", h.listOrganizations)
		orgs.POST("", h.createOrganization)
		orgs.GET("/:id", h.getOrganization)
		orgs.PUT("/:id", h.updateOrganization)
		orgs.DELETE("/:id", h.deleteOrganization)

		// User assignments
		orgs.POST("/:id/users", h.addUserToOrganization)
		orgs.DELETE("/:id/users/:userID", h.removeUserFromOrganization)
		orgs.GET("/users/:userID", h.listUserOrganizations)
	}
}

// CreateOrganizationRequest is the request to create an organization.
type CreateOrganizationRequest struct {
	Name        string          `json:"name" binding:"required"`
	DisplayName *string         `json:"display_name"`
	Description *string         `json:"description"` // For compatibility with tests
	Domain      *string         `json:"domain"`
	Metadata    json.RawMessage `json:"metadata"`
	Settings    json.RawMessage `json:"settings"`
}

// UpdateOrganizationRequest is the request to update an organization.
type UpdateOrganizationRequest struct {
	Name           *string         `json:"name"`
	DisplayName    *string         `json:"display_name"`
	Domain         *string         `json:"domain"`
	DomainVerified *bool           `json:"domain_verified"`
	Metadata       json.RawMessage `json:"metadata"`
	Settings       json.RawMessage `json:"settings"`
}

func (h *OrganizationHandler) listOrganizations(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	orgs, err := h.svc.ListOrganizations(c.Request.Context(), tenantID, limit, offset)
	if err != nil {
		h.logger.Error("Failed to list organizations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list organizations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"organizations": orgs})
}

func (h *OrganizationHandler) createOrganization(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	var req CreateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if org with same name exists
	existing, _ := h.svc.GetOrganizationByName(c.Request.Context(), tenantID, req.Name)
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "organization with this name already exists"})
		return
	}

	displayName := req.DisplayName
	if displayName == nil {
		displayName = req.Description
	}

	org := &Organization{
		TenantID:    tenantID,
		Name:        req.Name,
		DisplayName: displayName,
		Domain:      req.Domain,
		Metadata:    req.Metadata,
		Settings:    req.Settings,
	}

	if err := h.svc.CreateOrganization(c.Request.Context(), org); err != nil {
		h.logger.Error("Failed to create organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create organization"})
		return
	}

	c.JSON(http.StatusCreated, org)
}

func (h *OrganizationHandler) getOrganization(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	orgID := c.Param("id")
	org, err := h.svc.GetOrganization(c.Request.Context(), tenantID, orgID)
	if err != nil {
		h.logger.Error("Failed to get organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get organization"})
		return
	}
	if org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	c.JSON(http.StatusOK, org)
}

func (h *OrganizationHandler) updateOrganization(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	orgID := c.Param("id")
	existing, err := h.svc.GetOrganization(c.Request.Context(), tenantID, orgID)
	if err != nil {
		h.logger.Error("Failed to get organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get organization"})
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	var req UpdateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Apply updates
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.DisplayName != nil {
		existing.DisplayName = req.DisplayName
	}
	if req.Domain != nil {
		existing.Domain = req.Domain
	}
	if req.DomainVerified != nil {
		existing.DomainVerified = *req.DomainVerified
	}
	if req.Metadata != nil {
		existing.Metadata = req.Metadata
	}
	if req.Settings != nil {
		existing.Settings = req.Settings
	}

	if err := h.svc.UpdateOrganization(c.Request.Context(), existing); err != nil {
		h.logger.Error("Failed to update organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update organization"})
		return
	}

	c.JSON(http.StatusOK, existing)
}

func (h *OrganizationHandler) deleteOrganization(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	orgID := c.Param("id")
	if err := h.svc.DeleteOrganization(c.Request.Context(), tenantID, orgID); err != nil {
		h.logger.Error("Failed to delete organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete organization"})
		return
	}

	c.Status(http.StatusNoContent)
}
func (h *OrganizationHandler) addUserToOrganization(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	orgID := c.Param("id")
	var req struct {
		UserID string `json:"user_id" binding:"required"`
		Role   string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.AddUserToOrganization(c.Request.Context(), tenantID, req.UserID, orgID, req.Role); err != nil {
		h.logger.Error("Failed to add user to organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add user to organization"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user added to organization"})
}

func (h *OrganizationHandler) removeUserFromOrganization(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	orgID := c.Param("id")
	userID := c.Param("userID")

	if err := h.svc.RemoveUserFromOrganization(c.Request.Context(), tenantID, userID, orgID); err != nil {
		h.logger.Error("Failed to remove user from organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove user from organization"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user removed from organization"})
}

func (h *OrganizationHandler) listUserOrganizations(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	userID := c.Param("userID")

	orgIDs, err := h.svc.ListUserOrganizations(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("Failed to list user organizations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list user organizations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"organization_ids": orgIDs})
}
