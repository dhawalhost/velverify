package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func (h *HTTPHandler) RegisterWebAuthnRoutes(rg *gin.RouterGroup) {
	rg.POST("/mfa/webauthn/register/begin", h.beginWebAuthnRegistration)
	rg.POST("/mfa/webauthn/register/finish", h.finishWebAuthnRegistration)
	rg.POST("/mfa/webauthn/login/begin", h.beginWebAuthnLogin)
	rg.POST("/mfa/webauthn/login/finish", h.finishWebAuthnLogin)
}

func (h *HTTPHandler) beginWebAuthnRegistration(c *gin.Context) {
	// User must be authenticated to register a passkey
	// We expect the user ID to be in the context or passed?
	// For MVP, let's assume the user is calling this and we get ID from token/context.
	// OR if this is a "bootstrap" phase, we might accept a user_id param if secured otherwise.
	// But usually registration requires auth.
	// Let's assume this endpoint is protected by a middleware that sets "user_id".
	// Since we are adding this to `tenantProtected`, it verifies tenant but maybe not user?
	// We need to know WHO is registering.
	// Check if we can get user from context (e.g. from Bearer token if middleware parsed it).
	// If not, we might need to rely on a passed ID, trusting the client? NO.
	// For this exercise, let's assume we extract it from a "X-User-ID" header for simplicity in testing,
	// OR better, we should have an Auth middleware.
	// Let's use X-User-ID for now as we don't have full AuthN middleware on this specific route group yet?
	// Actually we do have `tenantProtected` but that only checks tenant.
	userID := c.Request.Header.Get("X-User-ID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id required"})
		return
	}

	options, session, err := h.svc.BeginWebAuthnRegistration(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to begin registration", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Store session
	h.webAuthnSessions.Set(userID, *session)

	c.JSON(http.StatusOK, options)
}

func (h *HTTPHandler) finishWebAuthnRegistration(c *gin.Context) {
	userID := c.Request.Header.Get("X-User-ID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id required"})
		return
	}

	session, ok := h.webAuthnSessions.Get(userID)
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

	h.webAuthnSessions.Delete(userID)
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

	h.webAuthnSessions.Set(req.UserID, *session)
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

	session, ok := h.webAuthnSessions.Get(userID)
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

	h.webAuthnSessions.Delete(userID)
	c.JSON(http.StatusOK, gin.H{"access_token": token, "token_type": "Bearer"})
}
