package directory

import (
	"context"
	"net/http"
	"strings"

	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/gin-gonic/gin"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// RequireSCIMBearerToken authenticates requests using the Authorization: Bearer header.
// It verifies the token against the api_keys table or an internal service whitelist.
func RequireSCIMBearerToken(repo Repository, log *zap.Logger, internalServiceToken string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"status":  "401",
				"detail":  "Authorization header is missing",
			})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"status":  "401",
				"detail":  "Authorization header must be a Bearer token",
			})
			c.Abort()
			return
		}

		token := parts[1]

		// 1. Check if it's the internal service token
		if internalServiceToken != "" && token == internalServiceToken {
			tenantID := c.GetHeader("X-Tenant-ID")
			if tenantID == "" {
				c.JSON(http.StatusBadRequest, gin.H{
					"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
					"status":  "400",
					"detail":  "X-Tenant-ID is required for internal service token usage",
				})
				c.Abort()
				return
			}
			ctx := middleware.InjectTenantID(c.Request.Context(), tenantID)
			c.Request = c.Request.WithContext(ctx)
			c.Next()
			return
		}

		// 2. Check if it's a JWT token
		if strings.Count(token, ".") == 2 {
			parser := jwtlib.NewParser()
			claims := jwtlib.MapClaims{}
			_, _, err := parser.ParseUnverified(token, claims)
			if err == nil {
				var jwtTenantID string
				if tid, ok := claims["tenant_id"].(string); ok && tid != "" {
					jwtTenantID = tid
				}
				if jwtTenantID == "" {
					jwtTenantID = c.GetHeader("X-Tenant-ID")
				}
				if jwtTenantID != "" {
					ctx := middleware.InjectTenantID(c.Request.Context(), jwtTenantID)
					c.Request = c.Request.WithContext(ctx)
					c.Next()
					return
				}
			}
		}

		// 3. Validate against API Keys
		if len(token) < 16 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"status":  "401",
				"detail":  "Invalid API Key format",
			})
			c.Abort()
			return
		}

		prefix := token[:16] + "..."

		candidates, err := repo.GetAPIKeyByPrefix(c.Request.Context(), prefix)
		if err != nil {
			log.Error("Failed to query API keys", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during authentication"})
			c.Abort()
			return
		}

		var matchedTenantID string
		var matchedKeyID string
		isValid := false

		for _, candidate := range candidates {
			if err := bcrypt.CompareHashAndPassword([]byte(candidate.KeyHash), []byte(token)); err == nil {
				isValid = true
				matchedTenantID = candidate.TenantID
				matchedKeyID = candidate.ID
				break
			}
		}

		if !isValid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"status":  "401",
				"detail":  "Invalid or revoked API Key",
			})
			c.Abort()
			return
		}

		// Update last_used_at asynchronously
		go func(kid, tid string) {
			_ = repo.UpdateAPIKeyLastUsed(context.Background(), kid, tid)
		}(matchedKeyID, matchedTenantID)

		ctx := middleware.InjectTenantID(c.Request.Context(), matchedTenantID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}
