package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator defines a function that validates a token and returns claims.
type TokenValidator func(token string) (*Claims, error)

// RequireUserAuth validates the JWT token and populates user context.
func RequireUserAuth(validator TokenValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// Fallback to cookie
			token, err := c.Cookie("wardseal_access_token")
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
				return
			}
			authHeader = "Bearer " + token
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token format"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := validator(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("invalid or expired token: %v", err)})
			return
		}

		// Use 'sub' as user_id and 'roles' for RBAC
		c.Set("user_id", claims.Subject)
		c.Set("roles", claims.Roles)
		c.Set("claims", claims)

		// Enforce tenant isolation
		tenantID, _ := TenantIDFromGinContext(c)
		if tenantID == "" {
			// Detect missing TenantExtractor on tenant routes
			pathTenant := c.Param("tenant")
			if pathTenant == "" {
				pathTenant = c.Param("tenant_id")
			}
			if pathTenant == "" {
				pathTenant = c.Query("tenant_id")
			}
			if pathTenant == "" {
				pathTenant = c.Query("tenant")
			}
			if pathTenant == "" {
				pathTenant = c.GetHeader("X-Tenant-ID")
			}
			if pathTenant == "" {
				pathTenant = c.GetHeader("Tenant-ID")
			}
			
			if pathTenant != "" {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant context unverified"})
				return
			}
		} else {
			if claims.Tenant == "" || claims.Tenant != tenantID {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant context mismatch"})
				return
			}
		}

		c.Next()

	}
}

// Claims represents the JWT claims we care about.
type Claims struct {
	jwt.RegisteredClaims
	Roles  []string               `json:"roles,omitempty"`
	Tenant string                 `json:"tenant,omitempty"`
	Scope  string                 `json:"scope,omitempty"`
	CNF    map[string]interface{} `json:"cnf,omitempty"`
}


// ValidateToken parses and validates a JWT token string.
func ValidateToken(tokenString, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// RequireScope enforces that the token has the required scope.
func RequireScope(requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsObj, exists := c.Get("claims")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		claims, ok := claimsObj.(*Claims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid claims type"})
			return
		}
		if !HasScope(claims.Scope, requiredScope) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient_scope"})
			return
		}
		c.Next()
	}
}

// HasScope checks if the scope string contains the target scope.
func HasScope(scope, target string) bool {
	for _, value := range strings.Fields(scope) {
		if value == target {
			return true
		}
	}
	return false
}
