package governance

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// CampaignHTTPHandler handles campaign HTTP requests.
type CampaignHTTPHandler struct {
	svc    CampaignService
	logger *zap.Logger
}

// NewCampaignHTTPHandler creates a new campaign HTTP handler.
func NewCampaignHTTPHandler(svc CampaignService, logger *zap.Logger) *CampaignHTTPHandler {
	return &CampaignHTTPHandler{svc: svc, logger: logger}
}

// RegisterRoutes registers campaign routes.
func (h *CampaignHTTPHandler) RegisterRoutes(rg *gin.RouterGroup) {
	campaigns := rg.Group("/campaigns")
	{
		campaigns.POST("", h.createCampaign)
		campaigns.GET("", h.listCampaigns)
		campaigns.GET("/:id", h.getCampaign)
		campaigns.POST("/:id/start", h.startCampaign)
		campaigns.POST("/:id/complete", h.completeCampaign)
		campaigns.POST("/:id/cancel", h.cancelCampaign)
		campaigns.DELETE("/:id", h.deleteCampaign)

		// Review items
		campaigns.POST("/:id/items", h.addReviewItem)
		campaigns.GET("/:id/items", h.listPendingItems)
		campaigns.GET("/items", h.listReviewItems)
		campaigns.POST("/:id/items/:itemId/approve", h.approveItem)
		campaigns.POST("/:id/items/:itemId/revoke", h.revokeItem)
	}
}

func (h *CampaignHTTPHandler) tenantID(c *gin.Context) (string, bool) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		h.logger.Error("tenant id missing", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return "", false
	}
	return tenantID, true
}

func (h *CampaignHTTPHandler) createCampaign(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var input CreateCampaignInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	campaign, err := h.svc.CreateCampaign(c.Request.Context(), tenantID, input)
	if err != nil {
		h.logger.Error("Failed to create campaign", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, campaign)
}

func (h *CampaignHTTPHandler) listCampaigns(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	status := c.Query("status")
	campaigns, err := h.svc.ListCampaigns(c.Request.Context(), tenantID, status)
	if err != nil {
		h.logger.Error("Failed to list campaigns", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": campaigns})
}

func (h *CampaignHTTPHandler) getCampaign(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	campaign, err := h.svc.GetCampaign(c.Request.Context(), tenantID, id)
	if err != nil {
		h.logger.Error("Failed to get campaign", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "campaign not found"})
		return
	}
	c.JSON(http.StatusOK, campaign)
}

func (h *CampaignHTTPHandler) startCampaign(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	if err := h.svc.StartCampaign(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to start campaign", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "active"})
}

func (h *CampaignHTTPHandler) completeCampaign(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	if err := h.svc.CompleteCampaign(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to complete campaign", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "completed"})
}

func (h *CampaignHTTPHandler) cancelCampaign(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	if err := h.svc.CancelCampaign(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to cancel campaign", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

func (h *CampaignHTTPHandler) deleteCampaign(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	id := c.Param("id")
	if err := h.svc.DeleteCampaign(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("Failed to delete campaign", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *CampaignHTTPHandler) addReviewItem(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	campaignID := c.Param("id")
	var item CertificationItem
	if err := c.ShouldBindJSON(&item); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.svc.AddReviewItem(c.Request.Context(), tenantID, campaignID, item)
	if err != nil {
		h.logger.Error("Failed to add review item", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, result)
}

func (h *CampaignHTTPHandler) listPendingItems(c *gin.Context) {
	campaignID := c.Param("id")
	items, err := h.svc.ListPendingItems(c.Request.Context(), campaignID)
	if err != nil {
		h.logger.Error("Failed to list pending items", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *CampaignHTTPHandler) listReviewItems(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	reviewerID := c.Query("reviewer_id")
	if reviewerID == "" {
		reviewerID = campaignActorIDFromRequest(c)
	}
	if reviewerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reviewer_id is required"})
		return
	}

	items, err := h.svc.ListReviewItems(c.Request.Context(), tenantID, reviewerID)
	if err != nil {
		h.logger.Error("Failed to list review items", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *CampaignHTTPHandler) approveItem(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	itemID := c.Param("itemId")
	var body struct {
		Comment string `json:"comment"`
	}
	_ = c.ShouldBindJSON(&body)

	if err := h.svc.ApproveItem(c.Request.Context(), tenantID, itemID, body.Comment); err != nil {
		h.logger.Error("Failed to approve item", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"decision": "approve"})
}

func (h *CampaignHTTPHandler) revokeItem(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	itemID := c.Param("itemId")
	var body struct {
		Comment string `json:"comment"`
	}
	_ = c.ShouldBindJSON(&body)

	if err := h.svc.RevokeItem(c.Request.Context(), tenantID, itemID, body.Comment); err != nil {
		h.logger.Error("Failed to revoke item", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"decision": "revoke"})
}

func campaignActorIDFromRequest(c *gin.Context) string {
	if userID := strings.TrimSpace(c.GetString("user_id")); userID != "" {
		return userID
	}
	if userID := strings.TrimSpace(c.GetHeader("X-User-ID")); userID != "" {
		return userID
	}
	return ""
}
