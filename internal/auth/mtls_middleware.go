package auth

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"

	"github.com/gin-gonic/gin"
)

// mTLSAuthMiddleware validates client certificates passed via X-Client-Cert header.
func mTLSAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		certHeader := c.GetHeader("X-Client-Cert")
		if certHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "client certificate required"})
			return
		}

		// Decode base64 if encoded by proxy
		certBytes, err := base64.StdEncoding.DecodeString(certHeader)
		if err != nil {
			// Attempt treating as raw PEM
			certBytes = []byte(certHeader)
		}

		block, _ := pem.Decode(certBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid certificate format"})
			return
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "failed to parse certificate"})
			return
		}

		if cert.Subject.CommonName == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "certificate missing common name"})
			return
		}

		c.Set("client_cert", cert)
		c.Next()
	}
}
