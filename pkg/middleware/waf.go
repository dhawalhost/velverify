package middleware

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

var (
	// SQL Injection patterns
	sqliRegex = regexp.MustCompile(`(?i)('|\b)(UNION\b|SELECT\b|INSERT\b|DELETE\b|DROP\b|UPDATE\b|OR\b\s+\d+=\d+|--|\/\*)`)
	
	// XSS patterns
	xssRegex = regexp.MustCompile(`(?i)(<script\b|javascript:|on\w+\s*=)`)
)

// SoftwareWAFMiddleware provides Layer 7 protection against common injection attacks.
func SoftwareWAFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Check Query Parameters
		for _, values := range c.Request.URL.Query() {
			for _, val := range values {
				if detectThreat(val) {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "malicious payload detected"})
					return
				}
			}
		}

		// 2. Check Headers (e.g., X-Forwarded-For)
		for key, values := range c.Request.Header {
			// Only check specific headers to avoid false positives on auth tokens
			if strings.HasPrefix(key, "X-") || key == "User-Agent" {
				for _, val := range values {
					if detectThreat(val) {
						c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "malicious payload detected"})
						return
					}
				}
			}
		}

		// 3. Check Request Body
		if c.Request.Body != nil && c.Request.ContentLength > 0 {
			bodyBytes, err := io.ReadAll(c.Request.Body)
			if err == nil {
				// Restore body for subsequent handlers
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

				if detectThreat(string(bodyBytes)) {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "malicious payload detected"})
					return
				}
			}
		}

		c.Next()
	}
}

func detectThreat(input string) bool {
	if sqliRegex.MatchString(input) {
		return true
	}
	if xssRegex.MatchString(input) {
		return true
	}
	return false
}
