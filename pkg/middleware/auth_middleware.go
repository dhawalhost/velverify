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
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		// Use 'sub' as user_id and 'roles' for RBAC
		c.Set("user_id", claims.Subject)
		c.Set("roles", claims.Roles)

		c.Next()
	}
}

// Claims represents the JWT claims we care about.
type Claims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles"`
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
