package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// DefaultTenantHeader is the HTTP header used to carry the tenant identifier when no
// custom header name is provided.
const DefaultTenantHeader = "X-Tenant-ID"

// tenantContextKey is an unexported key type to avoid collisions in the Gin context store.
type tenantContextKey string

const tenantIDContextKey tenantContextKey = "tenantID"

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
			if cfg.AllowFallback && cfg.DefaultTenantID != "" {
				tenantID = cfg.DefaultTenantID
			} else {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "missing tenant identifier",
				})
				return
			}
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

// TenantIDFromContext extracts the tenant identifier from a standard context, typically
// populated by TenantExtractor. It is useful in service/business layers where only
// context.Context is available.
func TenantIDFromContext(ctx context.Context) (string, error) {
	if value := ctx.Value(tenantIDContextKey); value != nil {
		if tenantID, ok := value.(string); ok && tenantID != "" {
			return tenantID, nil
		}
	}
	return "", errors.New("tenant id not found in context")
}
