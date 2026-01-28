package auth

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

// Cookie configuration
const (
	AccessTokenCookie   = "wardseal_access_token"
	RefreshTokenCookie  = "wardseal_refresh_token"
	CookieMaxAge        = 3600          // 1 hour for access token
	RefreshCookieMaxAge = 7 * 24 * 3600 // 7 days for refresh token
)

// setAuthCookies sets httpOnly secure cookies for authentication tokens
func setAuthCookies(c *gin.Context, accessToken, refreshToken string) {
	secure := os.Getenv("ENVIRONMENT") == "production"
	sameSite := http.SameSiteStrictMode

	// Access token cookie (1 hour)
	c.SetSameSite(sameSite)
	c.SetCookie(AccessTokenCookie, accessToken, CookieMaxAge, "/", "", secure, true)

	// Refresh token cookie (7 days) - if provided
	if refreshToken != "" {
		c.SetCookie(RefreshTokenCookie, refreshToken, RefreshCookieMaxAge, "/oauth2/token", "", secure, true)
	}
}

// clearAuthCookies removes authentication cookies
func clearAuthCookies(c *gin.Context) {
	c.SetCookie(AccessTokenCookie, "", -1, "/", "", false, true)
	c.SetCookie(RefreshTokenCookie, "", -1, "/oauth2/token", "", false, true)
}

// getTokenFromCookieOrHeader tries to get token from cookie first, then header
// nolint:unused // Reserved for future use
func getTokenFromCookieOrHeader(c *gin.Context) string {
	// Try cookie first
	if token, err := c.Cookie(AccessTokenCookie); err == nil && token != "" {
		return token
	}
	// Fall back to Authorization header
	authHeader := c.GetHeader("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	return ""
}

// HTTPHandler represents the HTTP API handlers for the auth service.
type HTTPHandler struct {
	svc               Service
	logger            *zap.Logger
	validate          *validator.Validate
	loginAttemptStore LoginAttemptStore
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, logger *zap.Logger, loginAttemptStore LoginAttemptStore) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger, validate: validator.New(), loginAttemptStore: loginAttemptStore}
}

// RegisterRoutes registers the authentication routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	tenantProtected := router.Group("/")
	tenantProtected.Use(middleware.TenantExtractor(middleware.TenantConfig{}))

	// Public routes (but still tenant-aware)
	router.POST("/api/v1/signup", h.signup)
	router.POST("/login/lookup", h.lookupUser) // Public lookup for tenant discovery

	// System Setup Routes (Public, no auth required to check status)
	router.GET("/api/v1/setup/status", h.getSetupStatus)
	router.POST("/api/v1/setup", h.performSetup)

	tenantProtected.POST("/login", h.login)
	tenantProtected.POST("/login/mfa", h.completeMFALogin)
	tenantProtected.POST("/logout", h.logout)
	tenantProtected.GET("/oauth2/authorize", h.authorize)
	tenantProtected.POST("/oauth2/token", h.token)
	tenantProtected.POST("/oauth2/introspect", h.introspect)
	tenantProtected.POST("/oauth2/revoke", h.revoke)
	router.GET("/.well-known/jwks.json", h.jwks)

	// Device routes
	deviceGroup := tenantProtected.Group("/api/v1/devices")
	{
		deviceGroup.POST("/register", h.registerDevice)
		deviceGroup.POST("/:id/posture", h.updatePosture)
		deviceGroup.GET("", h.listDevices)
		deviceGroup.DELETE("/:id", h.deleteDevice)
	}

	// Signal routes (CAE)
	signalGroup := tenantProtected.Group("/api/v1/signals")
	{
		signalGroup.POST("/ingest", h.ingestSignal)
	}

	// Social Login
	tenantProtected.POST("/social/login", h.socialLogin)

	// MFA WebAuthn
	h.registerWebAuthnRoutes(tenantProtected)

	// MFA TOTP
	h.RegisterTOTPRoutes(tenantProtected.Group("/api/v1"))

	if samlProvider := h.svc.SAML(); samlProvider != nil {
		samlHandler := gin.WrapH(samlProvider)
		router.GET("/saml/metadata", samlHandler)
		router.POST("/saml/sso", samlHandler)
		router.GET("/saml/idp-init", samlHandler) // IdP Initiated endpoint
	}

	// User Portal API (Protected)
	userAPI := tenantProtected.Group("/api/v1/user")
	userAPI.GET("/apps", h.getUserApps)
	userAPI.GET("/profile", h.getUserProfile)
	userAPI.POST("/profile", h.updateUserProfile)
}

func (h *HTTPHandler) getSetupStatus(c *gin.Context) {
	required, err := h.svc.GetSystemSetupStatus(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to check setup status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"setup_required": required})
}

// SetupRequest holds credentials for system owner setup.
type SetupRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

func (h *HTTPHandler) performSetup(c *gin.Context) {
	var req SetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := h.svc.PerformSystemSetup(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		h.logger.Error("Setup failed", zap.Error(err))
		if strings.Contains(err.Error(), "not required") {
			c.JSON(http.StatusForbidden, gin.H{"error": "System setup is not available"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Setup failed"})
		return
	}

	// Set auth cookies for immediate login
	setAuthCookies(c, token, "")

	c.JSON(http.StatusOK, gin.H{
		"token":   token,
		"message": "System owner created successfully",
	})
}

func (h *HTTPHandler) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind login request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Login request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deviceID := c.Request.Header.Get("X-Device-ID")
	ip := c.ClientIP()
	tenantID := c.GetHeader("X-Tenant-ID")

	// Check account lockout
	if h.loginAttemptStore != nil && tenantID != "" {
		locked, lockedUntil, _ := h.loginAttemptStore.IsLocked(c.Request.Context(), tenantID, req.Username)
		if locked {
			h.logger.Warn("Login attempt for locked account", zap.String("username", req.Username))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "account_locked",
				"error_description": "Too many failed login attempts. Please try again later.",
				"locked_until":      lockedUntil.Format("2006-01-02T15:04:05Z07:00"),
			})
			return
		}
	}

	userAgent := c.Request.UserAgent()
	clientOSVersion := c.GetHeader("X-OS-Version")
	token, err := h.svc.Login(c.Request.Context(), req.Username, req.Password, deviceID, userAgent, ip, clientOSVersion)
	if err != nil {
		h.logger.Error("Login failed", zap.Error(err))

		// Record failed attempt
		if h.loginAttemptStore != nil && tenantID != "" {
			_ = h.loginAttemptStore.RecordAttempt(c.Request.Context(), tenantID, req.Username, ip, false)
			failures, _ := h.loginAttemptStore.GetRecentFailures(c.Request.Context(), tenantID, req.Username)
			if failures >= MaxFailedAttempts {
				_ = h.loginAttemptStore.LockAccount(c.Request.Context(), tenantID, req.Username)
				h.logger.Warn("Account locked due to too many failed attempts", zap.String("username", req.Username))
			}
		}

		if errors.Is(err, ErrInvalidCredentials) {
			h.respondOAuthError(c, ErrInvalidCredentials)
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Record successful attempt and clear any lockout
	if h.loginAttemptStore != nil && tenantID != "" {
		_ = h.loginAttemptStore.RecordAttempt(c.Request.Context(), tenantID, req.Username, ip, true)
		_ = h.loginAttemptStore.UnlockAccount(c.Request.Context(), tenantID, req.Username)
	}

	// Check if user has TOTP enabled
	if h.svc.TOTP() != nil && tenantID != "" {
		totpSecret, _ := h.svc.TOTP().GetByIdentity(c.Request.Context(), tenantID, req.Username)
		if totpSecret != nil && totpSecret.Verified {
			// MFA required - return pending token and mfa_required flag
			c.JSON(http.StatusOK, gin.H{
				"mfa_required":  true,
				"pending_token": token,
				"user_id":       req.Username,
			})
			return
		}
	}

	// Set httpOnly cookies for session security
	setAuthCookies(c, token, "")

	c.JSON(http.StatusOK, LoginResponse{Token: token})
}

type LookupRequest struct {
	Email string `json:"email" binding:"required,email"`
}

func (h *HTTPHandler) lookupUser(c *gin.Context) {
	var req LookupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := c.GetHeader("X-Tenant-ID")
	// Tenant ID is optional for lookup now (discovery supported)

	result, err := h.svc.LookupUser(c.Request.Context(), tenantID, req.Email)
	if err != nil {
		// Avoid enumerating users aggressively if preferred, but for enterprise login, exact errors are often helpful.
		// For security, we might want generic "not found" or similar if we want to hide existence.
		// But here we return 404 if not found.
		h.logger.Warn("Lookup failed", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// MFALoginRequest is the request to complete MFA login.
type MFALoginRequest struct {
	PendingToken string `json:"pending_token" binding:"required"`
	TOTPCode     string `json:"totp_code" binding:"required"`
	UserID       string `json:"user_id" binding:"required"`
}

func (h *HTTPHandler) completeMFALogin(c *gin.Context) {
	var req MFALoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	// Validate TOTP
	totpSecret, err := h.svc.TOTP().GetByIdentity(c.Request.Context(), tenantID, req.UserID)
	if err != nil || totpSecret == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "TOTP not configured"})
		return
	}

	if !totp.Validate(req.TOTPCode, totpSecret.Secret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid TOTP code"})
		return
	}

	// Set httpOnly cookies for session security
	setAuthCookies(c, req.PendingToken, "")

	// TOTP verified, return the pending token as the final token
	c.JSON(http.StatusOK, LoginResponse{Token: req.PendingToken})
}

func (h *HTTPHandler) logout(c *gin.Context) {
	// Clear httpOnly cookies
	clearAuthCookies(c)
	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

func (h *HTTPHandler) authorize(c *gin.Context) {
	var req AuthorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		h.logger.Error("Failed to bind authorize request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Authorize request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.svc.Authorize(c.Request.Context(), req)
	if err != nil {
		h.logger.Error("Authorize failed", zap.Error(err))
		svcErr := &Error{}
		if errors.As(err, &svcErr) {
			h.respondOAuthError(c, svcErr)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Redirect(http.StatusFound, resp.RedirectURI)
}

func (h *HTTPHandler) token(c *gin.Context) {
	var req TokenRequest
	// Gin's ShouldBind handles different content types
	if err := c.ShouldBind(&req); err != nil {
		h.logger.Error("Failed to bind token request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Token request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.svc.Token(c.Request.Context(), req)
	if err != nil {
		h.logger.Error("Token generation failed", zap.Error(err))
		svcErr := &Error{}
		if errors.As(err, &svcErr) {
			h.respondOAuthError(c, svcErr)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *HTTPHandler) jwks(c *gin.Context) {
	// Assuming JWKS() method is available on the service
	jwks := h.svc.JWKS()
	c.JSON(http.StatusOK, jwks)
}

func (h *HTTPHandler) introspect(c *gin.Context) {
	var req IntrospectRequest
	if err := c.ShouldBind(&req); err != nil {
		h.logger.Error("Failed to bind introspect request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Introspect request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.svc.Introspect(c.Request.Context(), req)
	if err != nil {
		h.logger.Error("Token introspection failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *HTTPHandler) revoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		h.logger.Error("Failed to bind revoke request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		h.logger.Error("Revoke request validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.Revoke(c.Request.Context(), req); err != nil {
		h.logger.Error("Token revocation failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// RFC 7009: The authorization server responds with HTTP status code 200 for success
	c.Status(http.StatusOK)
}

func (h *HTTPHandler) respondOAuthError(c *gin.Context, err *Error) {
	status := http.StatusBadRequest
	if err.Code == ErrInvalidCredentials.Code {
		status = http.StatusUnauthorized
	}
	c.JSON(status, gin.H{
		"error":             err.Code,
		"error_description": err.Message,
	})
}

// SignupRequest is the request to create a new tenant and admin user.
type SignupRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=8"`
	CompanyName string `json:"company_name" binding:"required"`
	Plan        string `json:"plan"` // Optional, defaults to "free" in service
}

func (h *HTTPHandler) signup(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call Service Signup
	token, tenantID, err := h.svc.SignUp(c.Request.Context(), req.Email, req.Password, req.CompanyName, req.Plan)
	if err != nil {
		h.logger.Error("Signup failed", zap.Error(err))
		if strings.Contains(err.Error(), "conflict") || strings.Contains(err.Error(), "exists") {
			// If user/tenant exists (unlikely given UUID, but maybe email collision in global sense?)
			// Currently our logic creates new tenant always. Directory service `CreateUser` might fail if email exists in that tenant?
			// But tenant is new. So only if `directory` service enforces unique email globally (unlikely for multi-tenant).
			c.JSON(http.StatusConflict, gin.H{"error": "Signup failed, possibly duplicate data"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Signup failed"})
		return
	}

	// Set cookies for session
	setAuthCookies(c, token, "")

	c.JSON(http.StatusCreated, gin.H{
		"token":     token,
		"tenant_id": tenantID,
		"message":   "Signup successful",
	})
}
