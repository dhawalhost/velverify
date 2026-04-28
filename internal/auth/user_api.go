package auth

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

type UserAppResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	LaunchURL   string `json:"launch_url"` // Computed launch URL (e.g. OIDC init)
	IconURL     string `json:"icon_url"`   // Placeholder for now
}

// getUserApps returns the list of applications available to the current user (tenant).
func (h *HTTPHandler) getUserApps(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant context required"})
		return
	}

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user context required"})
		return
	}

	// Fetch apps assigned to this specific user
	apps, err := h.appStore.ListAssignedApps(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("Failed to list assigned apps for user portal",
			zap.String("tenant_id", tenantID),
			zap.String("user_id", userID),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list applications"})
		return
	}

	resp := make([]UserAppResponse, 0, len(apps))
	for _, app := range apps {
		launchURL := ""
		var redirectURIs []string
		if err := json.Unmarshal(app.RedirectURIs, &redirectURIs); err == nil && len(redirectURIs) > 0 {
			launchURL = redirectURIs[0]
		}

		resp = append(resp, UserAppResponse{
			ID:          app.ID,
			Name:        app.Name,
			Description: stringValue(app.Description),
			LaunchURL:   launchURL,
			IconURL:     stringValue(app.LogoURL),
		})
	}

	c.JSON(http.StatusOK, gin.H{"apps": resp})
}

func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// getUserProfile returns the current logged-in user's profile info.
func (h *HTTPHandler) getUserProfile(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant context required"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user context required"})
		return
	}

	profile, err := h.svc.GetUserByID(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("Failed to fetch user profile", zap.String("user_id", userID), zap.Error(err))
		c.JSON(http.StatusOK, gin.H{
			"id": userID,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":    profile.ID,
		"email": profile.Email,
		"name":  profile.Name,
	})
}

type UpdateProfileRequest struct {
	Password string `json:"password"`
}

// updateUserProfile allows user to update their own profile (password).
func (h *HTTPHandler) updateUserProfile(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant context required"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user context required"})
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := make(map[string]interface{})
	if req.Password != "" {
		updates["password"] = req.Password
	}

	if len(updates) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "no changes requested"})
		return
	}

	if err := h.svc.UpdateUserSelf(c.Request.Context(), tenantID, userID, updates); err != nil {
		h.logger.Error("Failed to update user profile", zap.String("user_id", userID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "profile updated successfully"})
}
