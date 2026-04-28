package directory

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/dhawalhost/wardseal/pkg/config"
	"github.com/dhawalhost/wardseal/pkg/middleware"
)

	var (
		jwtPublicKey     *rsa.PublicKey
		jwtPublicKeyOnce sync.Once
	)

	func loadPublicKey(log *zap.Logger) {
		jwtPublicKeyOnce.Do(func() {
			cfgFile := os.Getenv("APP_CONFIG")
			if cfgFile == "" {
				cfgFile = os.Getenv("CONFIG_FILE")
			}
			cfg, err := config.Load(cfgFile)
			if err != nil {
				log.Warn("Failed to load config for JWT verification", zap.Error(err))
				return
			}
			if cfg.Auth.JWTPublicKeyPath == "" {
				log.Warn("JWT public key path not set, unverified JWT authentication disabled")
				return
			}
			keyBytes, err := os.ReadFile(cfg.Auth.JWTPublicKeyPath)
			if err != nil {
				log.Error("Failed to read JWT public key file", zap.Error(err))
				return
			}
			pubKey, err := jwtlib.ParseRSAPublicKeyFromPEM(keyBytes)
			if err != nil {
				log.Error("Failed to parse JWT public key", zap.Error(err))
				return
			}
			jwtPublicKey = pubKey
		})
	}

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
			loadPublicKey(log)
			if jwtPublicKey != nil {
				claims := jwtlib.MapClaims{}
				parsedToken, err := jwtlib.ParseWithClaims(token, claims, func(t *jwtlib.Token) (interface{}, error) {
					if _, ok := t.Method.(*jwtlib.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
					}
					return jwtPublicKey, nil
				})

				if err == nil && parsedToken.Valid {
					var jwtTenantID string
					if tid, ok := claims["tenant_id"].(string); ok && tid != "" {
						jwtTenantID = tid
					} else if tid, ok := claims["tenant"].(string); ok && tid != "" {
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
				} else {
					log.Warn("SCIM JWT verification failed", zap.Error(err))
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
