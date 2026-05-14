package auth

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

// TOTPEnrollRequest is the request to start TOTP enrollment.
type TOTPEnrollRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// TOTPEnrollResponse contains the secret and QR code for enrollment.
type TOTPEnrollResponse struct {
	Secret  string `json:"secret"`
	QRCode  string `json:"qr_code"` // Base64 encoded PNG
	OTPAuth string `json:"otpauth_url"`
}

// TOTPVerifyRequest is the request to verify a TOTP code.
type TOTPVerifyRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Code   string `json:"code" binding:"required"`
}

func (h *HTTPHandler) RequireMFAAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			token, err := c.Cookie("wardseal_access_token")
			if err == nil {
				authHeader = "Bearer " + token
			}
		}

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := h.svc.ValidateToken(tokenString)
		if err == nil {
			c.Set("user_id", claims.Subject)
			c.Set("claims", claims)
			c.Next()
			return
		}

		claims, err = h.svc.ValidateStepUpToken(tokenString)
		if err == nil {
			c.Set("user_id", claims.Subject)
			c.Set("claims", claims)
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
	}
}

// RegisterTOTPRoutes registers TOTP-related routes.
func (h *HTTPHandler) RegisterTOTPRoutes(rg *gin.RouterGroup) {
	totp := rg.Group("/totp")
	totp.Use(h.RequireMFAAuth())
	{
		totp.POST("/enroll", h.enrollTOTP)
		totp.POST("/verify", h.verifyTOTP)
		totp.DELETE("", h.deleteTOTP)
		totp.GET("/status", h.getTOTPStatus)
	}
}

func (h *HTTPHandler) enrollTOTP(c *gin.Context) {
	var req TOTPEnrollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	req.UserID = userID

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "WardSeal",
		AccountName: req.UserID,
	})
	if err != nil {
		h.logger.Error("Failed to generate TOTP key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate TOTP key"})
		return
	}

	// Generate QR code
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		h.logger.Error("Failed to generate QR image", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate QR code"})
		return
	}
	if err := png.Encode(&buf, img); err != nil {
		h.logger.Error("Failed to encode QR image", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode QR code"})
		return
	}
	qrBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	// Store the secret (unverified)
	secret := &TOTPSecret{
		IdentityID: req.UserID,
		TenantID:   tenantID,
		Secret:     key.Secret(),
	}
	if err := h.svc.TOTP().Create(c.Request.Context(), secret); err != nil {
		h.logger.Error("Failed to store TOTP secret", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store TOTP secret"})
		return
	}

	c.JSON(http.StatusOK, TOTPEnrollResponse{
		Secret:  key.Secret(),
		QRCode:  qrBase64,
		OTPAuth: key.URL(),
	})
}

func (h *HTTPHandler) verifyTOTP(c *gin.Context) {
	var req TOTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	req.UserID = userID

	// Get stored secret
	stored, err := h.svc.TOTP().GetByIdentity(c.Request.Context(), tenantID, req.UserID)
	if err != nil {
		h.logger.Error("Failed to get TOTP secret", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve TOTP secret"})
		return
	}
	if stored == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "TOTP not enrolled for this user"})
		return
	}

	// Validate code
	valid := totp.Validate(req.Code, stored.Secret)
	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid TOTP code"})
		return
	}

	// Mark as verified if not already
	if !stored.Verified {
		if err := h.svc.TOTP().MarkVerified(c.Request.Context(), stored.ID); err != nil {
			h.logger.Error("Failed to mark TOTP verified", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify TOTP"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"verified": true})
}

func (h *HTTPHandler) deleteTOTP(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.svc.TOTP().Delete(c.Request.Context(), tenantID, userID); err != nil {
		h.logger.Error("Failed to delete TOTP", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete TOTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "TOTP deleted"})
}

func (h *HTTPHandler) getTOTPStatus(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	// Try query param first (for admin/support tools)
	userID := c.Query("user_id")
	if userID == "" {
		// Fallback to session user
		userID = c.GetString("user_id")
	}

	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	stored, err := h.svc.TOTP().GetByIdentity(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("Failed to get TOTP status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get TOTP status"})
		return
	}

	status := gin.H{
		"enrolled": false,
		"verified": false,
	}

	if stored != nil {
		status["enrolled"] = true
		status["verified"] = stored.Verified
		status["created_at"] = stored.CreatedAt
	}

	// Fetch Real Security Intel
	risk, err := h.svc.Signal().GetUserRisk(c.Request.Context(), tenantID, userID)
	if err == nil && risk != nil {
		status["risk_score"] = risk.Score
		status["risk_level"] = risk.Level
	} else {
		status["risk_score"] = 0
		status["risk_level"] = "low"
	}

	latestLogin, err := h.svc.Signal().GetLatestSuccess(c.Request.Context(), userID)
	if err == nil && latestLogin != nil {
		status["last_login_at"] = latestLogin.Timestamp
		status["last_login_ip"] = latestLogin.IPAddress
	}

	c.JSON(http.StatusOK, status)
}
