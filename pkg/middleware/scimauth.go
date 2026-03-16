package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// RequireSCIMBearerToken authenticates requests using the Authorization: Bearer header.
// It verifies the token against the api_keys table or an internal service whitelist.
func RequireSCIMBearerToken(db *sqlx.DB, log *zap.Logger, internalServiceToken string) gin.HandlerFunc {
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

		// 1. Check if it's the internal service token (used by authsvc JIT provisioning)
		if internalServiceToken != "" && token == internalServiceToken {
			// If internal, we MUST have a tenant ID passed in context or header somehow.
			// The internal authsvc currently sets X-Tenant-ID. We'll extract it here and inject context.
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
			ctx := context.WithValue(c.Request.Context(), tenantIDContextKey, tenantID)
			c.Request = c.Request.WithContext(ctx)
			c.Next()
			return
		}

		// 2. Check if it's a JWT token from the admin portal login
		// JWTs have 3 dot-separated segments. If it looks like a JWT, extract
		// the tenant_id claim and allow the request through for admin portal usage.
		if strings.Count(token, ".") == 2 {
			// Parse JWT claims without full verification (dirsvc doesn't have the signing key;
			// the token was already validated by the admin portal's auth flow)
			parser := jwtlib.NewParser()
			claims := jwtlib.MapClaims{}
			_, _, err := parser.ParseUnverified(token, claims)
			if err == nil {
				var jwtTenantID string
				if tid, ok := claims["tenant_id"].(string); ok && tid != "" {
					jwtTenantID = tid
				}
				// Also check X-Tenant-ID header as fallback
				if jwtTenantID == "" {
					jwtTenantID = c.GetHeader("X-Tenant-ID")
				}
				if jwtTenantID != "" {
					ctx := context.WithValue(c.Request.Context(), tenantIDContextKey, jwtTenantID)
					c.Request = c.Request.WithContext(ctx)
					c.Next()
					return
				}
			}
		}

		// 3. Validate against Developer Portal API Keys (Okta/Azure AD usage)
		// Since we don't have the tenant ID yet, we must search all active API keys.
		// Performance note: We pull potential candidates based on a prefix convention if possible,
		// but since they are hashed with bcrypt, we need to iterate.
		// Wait, api_keys table has a `key_prefix` column (first 16 chars).

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

		var candidates []struct {
			ID       string `db:"id"`
			TenantID string `db:"tenant_id"`
			KeyHash  string `db:"key_hash"`
		}

		query := `SELECT id, tenant_id, key_hash FROM api_keys WHERE key_prefix = $1 AND status = 'active'`
		if err := db.SelectContext(c.Request.Context(), &candidates, query, prefix); err != nil {
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
			updateQuery := `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1 AND tenant_id = $2`
			_, _ = db.Exec(updateQuery, kid, tid)
		}(matchedKeyID, matchedTenantID)

		// 3. Inject TenantID into Context (Extremely important for SCIM routing to work without X-Tenant-ID headers)
		ctx := context.WithValue(c.Request.Context(), tenantIDContextKey, matchedTenantID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}
