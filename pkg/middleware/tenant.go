package middleware

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// DefaultTenantHeader is the HTTP header used to carry the tenant identifier when no
// custom header name is provided.
const DefaultTenantHeader = "X-Tenant-ID"

// tenantContextKey is an unexported key type to avoid collisions in the Gin context store.
type tenantContextKey string

const tenantIDContextKey tenantContextKey = "wardseal.tenantID"

var tenantIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// TenantConfig captures the knobs for tenant extraction.
type TenantConfig struct {
	// HeaderName is the HTTP header inspected for the tenant identifier. Defaults
	// to DefaultTenantHeader when empty.
	HeaderName string
	// AllowFallback allows requests without the header to use DefaultTenantID instead
	// of being rejected.
	AllowFallback bool
	// DefaultTenantID is used when AllowFallback is true and no header value is set.
	DefaultTenantID string
	// SlugResolver is an optional function to resolve a slug to a UUID.
	SlugResolver func(ctx context.Context, slug string) (string, error)
}

// TenantExtractor returns a Gin middleware that reads the tenant identifier from
// the configured header and stores it on the Gin context for downstream handlers.
func TenantExtractor(cfg TenantConfig) gin.HandlerFunc {
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = DefaultTenantHeader
	}

	return func(c *gin.Context) {
		tenantID := c.GetHeader(headerName)
		if tenantID == "" {
			// Try query parameters
			tenantID = c.Query("tenant_id")
			if tenantID == "" {
				tenantID = c.Query("tenant")
			}
		}

		if tenantID == "" {
			// Try path parameters
			tenantID = c.Param("tenant")
		}

		if tenantID == "" {
			if cfg.AllowFallback && cfg.DefaultTenantID != "" {
				tenantID = cfg.DefaultTenantID
			} else {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "missing tenant identifier",
				})
				return
			}
		}

		// If a slug resolver is provided, we try to resolve the extracted ID as a slug first.
		// If resolution fails or returns empty, we treat the extracted ID as the literal tenant ID.
		if cfg.SlugResolver != nil {
			resolvedID, err := cfg.SlugResolver(c.Request.Context(), tenantID)
			if err == nil && resolvedID != "" {
				tenantID = resolvedID
			}
		} else {
			// Without a slug resolver, the tenant ID must be a valid UUID.
			if _, err := uuid.Parse(tenantID); err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "invalid tenant identifier format",
				})
				return
			}
		}

		// Verify character whitelist against generic injection vectors
		if !tenantIDRegex.MatchString(tenantID) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "invalid tenant identifier format",
			})
			return
		}

		c.Set(string(tenantIDContextKey), tenantID)
		ctx := context.WithValue(c.Request.Context(), tenantIDContextKey, tenantID)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// TenantIDFromGinContext extracts the tenant identifier previously stored by TenantExtractor.
func TenantIDFromGinContext(c *gin.Context) (string, error) {
	if value, ok := c.Get(string(tenantIDContextKey)); ok {
		if tenantID, ok := value.(string); ok && tenantID != "" {
			return tenantID, nil
		}
	}
	return "", errors.New("tenant id not found in context")
}

// TenantIDFromContext extracts the tenant identifier from a standard context.
func TenantIDFromContext(ctx context.Context) (string, error) {
	if value := ctx.Value(tenantIDContextKey); value != nil {
		if tenantID, ok := value.(string); ok && tenantID != "" {
			return tenantID, nil
		}
	}
	return "", errors.New("tenant id not found in context")
}

// InjectTenantID injects the tenant identifier into a standard context.
func InjectTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey, tenantID)
}
