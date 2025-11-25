package auth

import (
	"errors"
	"net/http"

	"github.com/dhawalhost/velverify/pkg/middleware"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

// HTTPHandler represents the HTTP API handlers for the auth service.
type HTTPHandler struct {
	svc      Service
	logger   *zap.Logger
	validate *validator.Validate
}

// NewHTTPHandler creates a new HTTPHandler.
func NewHTTPHandler(svc Service, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{svc: svc, logger: logger, validate: validator.New()}
}

// RegisterRoutes registers the authentication routes.
func (h *HTTPHandler) RegisterRoutes(router *gin.Engine) {
	tenantProtected := router.Group("/")
	tenantProtected.Use(middleware.TenantExtractor(middleware.TenantConfig{}))

	tenantProtected.POST("/login", h.login)
	tenantProtected.GET("/oauth2/authorize", h.authorize)
	tenantProtected.POST("/oauth2/token", h.token)
	router.GET("/.well-known/jwks.json", h.jwks)
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

	token, err := h.svc.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		h.logger.Error("Login failed", zap.Error(err))
		if errors.Is(err, ErrInvalidCredentials) {
			h.respondOAuthError(c, ErrInvalidCredentials)
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, LoginResponse{Token: token})
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
		if svcErr, ok := err.(*Error); ok {
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
		if svcErr, ok := err.(*Error); ok {
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
