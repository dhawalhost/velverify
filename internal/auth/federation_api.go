package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func (h *HTTPHandler) socialLogin(c *gin.Context) {
	var req SocialLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind social login request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Social login request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// For MVP/Simulated flow, we assume the client might send email/external_id directly
	// In production, `Code` would be exchanged.

	resp, err := h.svc.SocialLogin(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, ErrMFARequired) {
			c.JSON(http.StatusOK, gin.H{
				"pending_token": resp.AccessToken,
				"error":         "mfa_required",
				"message":       "Additional authentication required",
			})
			return
		}
		h.logger.Error("Social login failed", zap.Error(err))
		svcErr := &Error{}
		if errors.As(err, &svcErr) {
			h.respondOAuthError(c, svcErr)
		} else {
			// Handle specific errors like "linking required" if we strictly enforced it
			// But we implemented auto-provision so generic error is fine.
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}
