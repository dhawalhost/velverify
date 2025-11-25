package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
)

// DefaultServiceAuthHeader is the header name used to transmit the internal service token.
const DefaultServiceAuthHeader = "X-Service-Token"

// ServiceAuthConfig controls how the service authentication middleware behaves.
type ServiceAuthConfig struct {
	HeaderName string
	Token      string
}

// ServiceAuthenticator ensures that only trusted services can access protected routes.
func ServiceAuthenticator(cfg ServiceAuthConfig) gin.HandlerFunc {
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = DefaultServiceAuthHeader
	}

	expected := []byte(cfg.Token)

	return func(c *gin.Context) {
		provided := c.GetHeader(headerName)
		if len(expected) == 0 || provided == "" || subtle.ConstantTimeCompare([]byte(provided), expected) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid service token"})
			return
		}
		c.Next()
	}
}
