package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
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
	sameSite := http.SameSiteLaxMode

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
	loginAttemptStore LoginAttemptRepository
	appStore          DeveloperAppRepository
	webAuthnSessions  WebAuthnSessionRepository
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, logger *zap.Logger, loginAttemptStore LoginAttemptRepository, appStore DeveloperAppRepository) *HTTPHandler {
	return &HTTPHandler{
		svc:               svc,
		logger:            logger,
		validate:          validator.New(),
		loginAttemptStore: loginAttemptStore,
		appStore:          appStore,
		webAuthnSessions:  newInMemoryWebAuthnSessionRepository(),
	}
}

// SetWebAuthnSessionRepository allows overriding the default in-memory session repository.
func (h *HTTPHandler) SetWebAuthnSessionRepository(store WebAuthnSessionRepository) {
	if store == nil {
		return
	}
	h.webAuthnSessions = store
}

// RegisterRoutes registers the authentication routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"healthy": true})
	})

	// Public routes (but still tenant-aware if slug provided)
	router.GET("/api/v1/setup/status", h.getSetupStatus)
	router.POST("/api/v1/signup", h.signup)
	router.POST("/api/v1/setup", h.performSetup)
	router.POST("/api/v1/setup/password", h.completePasswordSetup)
	router.POST("/login/lookup", h.lookupUser) // Public lookup for tenant discovery

	// Path-based multi-tenancy group
	tenantGroup := router.Group("/t/:tenant")
	tenantGroup.Use(middleware.TenantExtractor(middleware.TenantConfig{
		HeaderName: "X-Tenant-ID", // Still check header
		SlugResolver: func(ctx context.Context, slug string) (string, error) {
			return h.svc.ResolveTenantSlug(ctx, slug)
		},
	}))

	// OIDC Discovery SHOULD NOT require a tenant ID in the request context specifically if it's based on the path,
	// but our TenantExtractor will provide it if we hit /t/:tenant/.well-known/openid-configuration.
	// We should also support the legacy global discovery if needed, but for now we focus on the path.

	tenantGroup.GET("/.well-known/openid-configuration", h.oidcConfig)
	tenantGroup.GET("/.well-known/jwks.json", h.jwks)

	// Protected routes within the tenant group
	tenantGroup.POST("/login", h.login)
	tenantGroup.POST("/login/mfa", h.completeMFALogin)
	tenantGroup.POST("/auth/mfa/step-up", h.completeMFALogin) // Alias for step-up
	tenantGroup.POST("/logout", h.logout)
	tenantGroup.GET("/oauth2/authorize", h.authorize)
	tenantGroup.POST("/oauth2/token", h.token)
	tenantGroup.POST("/oauth2/introspect", h.introspect)
	tenantGroup.POST("/oauth2/revoke", h.revoke)

	// Global routes (legacy or fallback)
	router.GET("/.well-known/jwks.json", h.jwks)

	tenantProtected := router.Group("/")
	tenantProtected.Use(middleware.TenantExtractor(middleware.TenantConfig{
		HeaderName:    "X-Tenant-ID",
		AllowFallback: false, // Disallow fallback for security in SaaS
		SlugResolver: func(ctx context.Context, slug string) (string, error) {
			return h.svc.ResolveTenantSlug(ctx, slug)
		},
	}))

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

	// API v1 group
	apiV1 := tenantProtected.Group("/api/v1")

	// MFA WebAuthn
	h.registerWebAuthnRoutes(apiV1)

	// MFA TOTP
	h.RegisterTOTPRoutes(apiV1)

	if samlProvider := h.svc.SAML(); samlProvider != nil {
		samlHandler := gin.WrapH(samlProvider)
		router.GET("/saml/metadata", samlHandler)
		router.POST("/saml/sso", samlHandler)
		router.GET("/saml/idp-init", samlHandler) // IdP Initiated endpoint
	}

	// User Portal API (Protected)
	userAPI := tenantProtected.Group("/api/v1/user")
	// Use the same signing secret as the service (signer)
	// Use the service's ValidateToken method
	userAPI.Use(middleware.RequireUserAuth(h.svc.ValidateToken))
	userAPI.GET("/apps", h.getUserApps)
	userAPI.GET("/profile", h.getUserProfile)
	userAPI.POST("/profile", h.updateUserProfile)

	setupAPI := tenantProtected.Group("/api/v1/setup")
	setupAPI.Use(middleware.RequireUserAuth(h.svc.ValidateToken))
	setupAPI.POST("/password-link", h.createPasswordSetupLink)
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

func (h *HTTPHandler) tenantSlugForID(ctx context.Context, tenantID string) string {
	if tenantID == "" {
		return ""
	}
	impl, ok := h.svc.(*authService)
	if !ok || impl.tenantStore == nil {
		return ""
	}
	slug, err := impl.tenantStore.GetSlugByID(ctx, tenantID)
	if err != nil {
		h.logger.Warn("Failed to resolve tenant slug", zap.String("tenant_id", tenantID), zap.Error(err))
		return ""
	}
	return slug
}

// SetupRequest holds credentials for system owner setup.
type SetupRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type PasswordSetupLinkRequest struct {
	UserID       string `json:"user_id" binding:"required"`
	Mode         string `json:"mode" binding:"required,oneof=invite reset"`
	ExpiresHours int    `json:"expires_hours"`
}

type CompletePasswordSetupRequest struct {
	Token    string `json:"token" binding:"required"`
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
		"token":       token,
		"tenant_id":   "admin-system",
		"tenant_slug": "admin",
		"message":     "System owner created successfully",
	})
}

func (h *HTTPHandler) createPasswordSetupLink(c *gin.Context) {
	tenantID, err := middleware.TenantIDFromContext(c.Request.Context())
	if err != nil || tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}

	var req PasswordSetupLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	impl, ok := h.svc.(*authService)
	if !ok {
		h.logger.Error("service type assertion failed for password setup link")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal service error"})
		return
	}

	token, expiresAt, err := impl.generatePasswordSetupToken(tenantID, req.UserID, req.Mode, req.ExpiresHours)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	baseUIURL := strings.TrimRight(h.svc.UIURL(), "/")
	setupURL := fmt.Sprintf("%s/set-password?token=%s&mode=%s", baseUIURL, url.QueryEscape(token), url.QueryEscape(req.Mode))

	c.JSON(http.StatusOK, gin.H{
		"mode":       req.Mode,
		"token":      token,
		"url":        setupURL,
		"expires_at": expiresAt.Format(time.RFC3339),
	})
}

func (h *HTTPHandler) completePasswordSetup(c *gin.Context) {
	var req CompletePasswordSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	impl, ok := h.svc.(*authService)
	if !ok {
		h.logger.Error("service type assertion failed for complete password setup")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal service error"})
		return
	}

	if err := impl.setPasswordWithSetupToken(c.Request.Context(), req.Token, req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password set successfully"})
}

func tenantIDFromRequest(c *gin.Context) string {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err == nil && tenantID != "" {
		return tenantID
	}
	return c.GetHeader("X-Tenant-ID")
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
	tenantID := tenantIDFromRequest(c)

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
		} else if errors.Is(err, ErrMFARequired) {
			c.JSON(http.StatusAccepted, gin.H{
				"mfa_required":   true,
				"step_up_token":  token,
				"error":          "mfa_required",
				"message":        "Additional authentication required due to risk assessment",
			})
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

	// Extract roles for the response
	claims, _ := h.svc.ValidateToken(token)
	roles := []string{}
	if claims != nil {
		roles = claims.Roles
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token:      token,
		Roles:      roles,
		TenantID:   tenantID,
		TenantSlug: h.tenantSlugForID(c.Request.Context(), tenantID),
	})
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

	tenantID := tenantIDFromRequest(c)
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}

	// Use the service to complete MFA login
	finalToken, err := h.svc.LoginWithMFAStepUp(c.Request.Context(), req.PendingToken, req.TOTPCode)
	if err != nil {
		h.logger.Error("MFA completion failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Set httpOnly cookies for session security
	setAuthCookies(c, finalToken, "")

	// Extract roles for the response
	claims, _ := h.svc.ValidateToken(finalToken)
	roles := []string{}
	if claims != nil {
		roles = claims.Roles
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token:      finalToken,
		Roles:      roles,
		TenantID:   tenantID,
		TenantSlug: h.tenantSlugForID(c.Request.Context(), tenantID),
	})
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

	// 1. Require User Session (Session Cookie)
	cookie, err := c.Cookie(AccessTokenCookie)
	if err != nil {
		// Not logged in -> Redirect to Wardseal login page
		// We pass the current authorize URL as the redirect_uri so they come back after logging in
		loginURL := fmt.Sprintf("%s/login?redirect_uri=%s", h.svc.UIURL(), url.QueryEscape(c.Request.URL.String()))
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// 2. Validate the token to extract the UserID
	var userID string
	// Check for proper token
	claims, err := h.svc.ValidateToken(cookie)
	if err == nil {
		userID = claims.Subject
	}

	if userID == "" {
		h.logger.Warn("Unauthorized access attempt to OIDC endpoint")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// 3. Verify Application Assignment
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		h.logger.Error("Failed to extract tenant ID", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant identifier"})
		return
	}

	if tenantID != "" && h.appStore != nil {
		app, err := h.appStore.GetByClientID(c.Request.Context(), req.ClientID)
		if err != nil {
			h.logger.Error("Failed to load application by client ID", zap.Error(err), zap.String("clientID", req.ClientID), zap.String("tenantID", tenantID), zap.String("userID", userID))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify app assignment"})
			return
		}
		if app != nil {
			if app.TenantID != tenantID {
				h.logger.Warn("Application tenant mismatch", zap.String("clientID", req.ClientID), zap.String("tenantID", tenantID), zap.String("appTenantID", app.TenantID), zap.String("userID", userID), zap.String("appID", app.ID))
				c.JSON(http.StatusForbidden, gin.H{
					"error":             "access_denied",
					"error_description": "This application belongs to a different tenant. Sign in to the correct tenant or use an application client from this tenant.",
				})
				return
			}

			assigned, err := h.appStore.CheckAssignment(c.Request.Context(), tenantID, app.ID, userID)
			if err != nil {
				h.logger.Error("Failed to check app assignment", zap.Error(err), zap.String("clientID", req.ClientID), zap.String("tenantID", tenantID), zap.String("userID", userID), zap.String("appID", app.ID))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify app assignment"})
				return
			}
			if !assigned && app.OwnerID == userID {
				assigned = true
				h.logger.Info("Allowing app owner without explicit assignment", zap.String("clientID", req.ClientID), zap.String("tenantID", tenantID), zap.String("userID", userID), zap.String("appID", app.ID))
			}
			if !assigned {
				h.logger.Warn("User not assigned to application", zap.String("clientID", req.ClientID), zap.String("tenantID", tenantID), zap.String("userID", userID), zap.String("appID", app.ID))
				c.JSON(http.StatusForbidden, gin.H{
					"error":             "access_denied",
					"error_description": "You are not assigned to this application. Please contact your administrator.",
				})
				return
			}
		}
	}

	resp, err := h.svc.Authorize(c.Request.Context(), userID, req)
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

	populateClientCredentialsFromBasicAuth(c, &req)

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

func populateClientCredentialsFromBasicAuth(c *gin.Context, req *TokenRequest) {
	if req == nil || req.ClientID != "" {
		return
	}

	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return
	}

	if req.ClientID == "" {
		req.ClientID = parts[0]
	}
	if req.ClientSecret == "" {
		req.ClientSecret = parts[1]
	}
}

func (h *HTTPHandler) jwks(c *gin.Context) {
	// Assuming JWKS() method is available on the service
	jwks := h.svc.JWKS()
	c.JSON(http.StatusOK, jwks)
}

func (h *HTTPHandler) oidcConfig(c *gin.Context) {
	config := h.svc.GetOIDCConfiguration()

	// Update endpoints based on extracted tenant (if any) to reflect the multi-tenancy path
	tenant, err := middleware.TenantIDFromGinContext(c)
	if err == nil && tenant != "" {
		// If we are in a /t/:tenant context, the issuer should actually be the tenant-specific one?
		// Most OIDC providers (like Google/Microsoft) use the tenant-specific URL as the issuer.

		tenantParam := c.Param("tenant")
		if tenantParam != "" {
			tenantPath := fmt.Sprintf("/t/%s", tenantParam)
			config.Issuer = fmt.Sprintf("%s%s", config.Issuer, tenantPath)
			config.AuthorizationEndpoint = strings.Replace(config.AuthorizationEndpoint, "/oauth2", tenantPath+"/oauth2", 1)
			config.TokenEndpoint = strings.Replace(config.TokenEndpoint, "/oauth2", tenantPath+"/oauth2", 1)
			config.JwksURI = strings.Replace(config.JwksURI, "/.well-known", tenantPath+"/.well-known", 1)
			config.UserinfoEndpoint = strings.Replace(config.UserinfoEndpoint, "/api", tenantPath+"/api", 1)
		}
	}

	c.JSON(http.StatusOK, config)
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
	token, tenantID, tenantSlug, err := h.svc.SignUp(c.Request.Context(), req.Email, req.Password, req.CompanyName, req.Plan)
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
		"token":       token,
		"tenant_id":   tenantID,
		"tenant_slug": tenantSlug,
		"message":     "Signup successful",
	})
}
