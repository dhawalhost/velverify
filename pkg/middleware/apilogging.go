package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

type responseBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (r responseBodyWriter) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// APILogger returns a Gin middleware that records API requests to the api_logs table.
func APILogger(db *sqlx.DB, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		var reqBodyBytes []byte
		if c.Request.Body != nil {
			reqBodyBytes, _ = io.ReadAll(c.Request.Body)
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(reqBodyBytes))

		resBody := &bytes.Buffer{}
		rbw := &responseBodyWriter{body: resBody, ResponseWriter: c.Writer}
		c.Writer = rbw

		c.Next()

		latency := time.Since(start).Milliseconds()
		statusCode := c.Writer.Status()

		tenantID := c.GetHeader("X-Tenant-ID")
		if tenantID == "" {
			if t, err := TenantIDFromGinContext(c); err == nil {
				tenantID = t
			}
		}

		if tenantID == "" {
			return // Cannot log without a tenant
		}

		clientID := c.GetHeader("X-Client-ID") // Allow explicit override
		if clientID == "" {
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer vv_live_") {
				// Expose the first 16 chars of the API Key as the client ID for tracing
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && len(parts[1]) >= 20 {
					clientID = parts[1][:16] + "..."
				}
			} else if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				clientID = "oauth_token" // Fallback identifier
			}
		}

		method := c.Request.Method
		path := c.Request.URL.Path
		ip := c.ClientIP()

		if db != nil {
			go logToDB(db, logger, tenantID, clientID, method, path, statusCode, latency, ip, reqBodyBytes, resBody.Bytes())
		}
	}
}

func logToDB(db *sqlx.DB, logger *zap.Logger, tenantID, clientID, method, path string, statusCode int, latency int64, ip string, reqPayload, resPayload []byte) {
	reqPayload = sanitizeJSONPayload(reqPayload)
	resPayload = sanitizeJSONPayload(resPayload)

	query := `INSERT INTO api_logs 
		(tenant_id, client_id, method, path, status_code, latency_ms, ip_address, request_payload, response_payload) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, CAST($8 AS JSONB), CAST($9 AS JSONB))`

	reqStr := "{}"
	if json.Valid(reqPayload) {
		reqStr = string(reqPayload)
	} else if len(reqPayload) > 0 {
		reqStr = `{"raw_text": ` + strconv.Quote(string(reqPayload)) + `}`
	}

	resStr := "{}"
	if json.Valid(resPayload) {
		resStr = string(resPayload)
	} else if len(resPayload) > 0 {
		resStr = `{"raw_text": ` + strconv.Quote(string(resPayload)) + `}`
	}

	_, err := db.Exec(query, tenantID, clientID, method, path, statusCode, latency, ip, reqStr, resStr)
	if err != nil {
		logger.Warn("Failed to insert API log", zap.Error(err), zap.String("tenant", tenantID), zap.String("path", path))
	}
}

func sanitizeJSONPayload(payload []byte) []byte {
	if !json.Valid(payload) {
		return payload
	}
	var data interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return payload
	}
	sanitizeNode(data)
	sanitized, err := json.Marshal(data)
	if err != nil {
		return payload
	}
	return sanitized
}

func sanitizeNode(node interface{}) {
	switch n := node.(type) {
	case map[string]interface{}:
		for k, v := range n {
			if isSensitiveKey(k) {
				n[k] = "[REDACTED]"
			} else {
				sanitizeNode(v)
			}
		}
	case []interface{}:
		for _, v := range n {
			sanitizeNode(v)
		}
	}
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	return k == "password" || k == "token" || k == "access_token" || k == "refresh_token" || k == "secret" || k == "client_secret"
}

