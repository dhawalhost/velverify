package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

func (h *HTTPHandler) RegisterWebAuthnRoutes(rg *gin.RouterGroup) {
	rg.POST("/webauthn/login/begin", h.beginWebAuthnLogin)
	rg.POST("/webauthn/login/finish", h.finishWebAuthnLogin)

	protected := rg.Group("/webauthn")
	protected.Use(middleware.RequireUserAuth(h.svc.ValidateToken))
	{
		protected.POST("/register/begin", h.beginWebAuthnRegistration)
		protected.POST("/register/finish", h.finishWebAuthnRegistration)
	}
}

func (h *HTTPHandler) beginWebAuthnRegistration(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	options, session, err := h.svc.BeginWebAuthnRegistration(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to begin registration", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Store session
	h.webAuthnSessions.Set(c.Request.Context(), userID, *session)

	c.JSON(http.StatusOK, options)
}

func (h *HTTPHandler) finishWebAuthnRegistration(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	session, ok := h.webAuthnSessions.Get(c.Request.Context(), userID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session not found"})
		return
	}

	err := h.svc.FinishWebAuthnRegistration(c.Request.Context(), userID, session, c.Request)
	if err != nil {
		h.logger.Error("Failed to finish registration", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.webAuthnSessions.Delete(c.Request.Context(), userID)
	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func (h *HTTPHandler) beginWebAuthnLogin(c *gin.Context) {
	// User not authenticated yet.
	// We need to know who is trying to login (username/email? or user_id if known).
	// Let's accept username/email in body? Or assume client sends user_id for now?
	// Standard WebAuthn flow often starts with username.
	// But our Service expects UserID. We'd need to lookup UserID from Username.
	// Service.Login does that internally.
	// Let's assume the client sends the User ID (maybe obtained from a previous "identify" step).

	type BeginLoginRequest struct {
		UserID string `json:"user_id"`
	}
	var req BeginLoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if req.UserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id required"})
		return
	}

	options, session, err := h.svc.BeginWebAuthnLogin(c.Request.Context(), req.UserID)
	if err != nil {
		h.logger.Error("Failed to begin login", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.webAuthnSessions.Set(c.Request.Context(), req.UserID, *session)
	c.JSON(http.StatusOK, options)
}

func (h *HTTPHandler) finishWebAuthnLogin(c *gin.Context) {
	// Can't bind JSON body easily because we need the raw request for webauthn library?
	// Actually webauthn library parses the request body itself.
	// But we need the UserID to find the session.
	// It's often passed in query param or header in this step if not in body alongside cred.
	userID := c.Query("user_id") // Simple way
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id query param required"})
		return
	}

	session, ok := h.webAuthnSessions.Get(c.Request.Context(), userID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session not found"})
		return
	}

	token, err := h.svc.FinishWebAuthnLogin(c.Request.Context(), userID, session, c.Request)
	if err != nil {
		h.logger.Error("Failed to finish login", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	h.webAuthnSessions.Delete(c.Request.Context(), userID)

	// Set httpOnly cookies for session security
	h.setAuthCookies(c, token, "")

	c.JSON(http.StatusOK, gin.H{"access_token": token, "token_type": "Bearer"})
}
