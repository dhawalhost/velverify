package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTenantExtractorSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantExtractor(TenantConfig{}))
	r.GET("/ping", func(c *gin.Context) {
		tenantID, err := TenantIDFromGinContext(c)
		if err != nil {
			t.Fatalf("expected tenant id, got error: %v", err)
		}
		if tenantID != "tenant-123" {
			t.Fatalf("unexpected tenant id: %s", tenantID)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set(DefaultTenantHeader, "tenant-123")
	res := httptest.NewRecorder()

	r.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
}

func TestTenantExtractorMissingHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantExtractor(TenantConfig{}))
	r.GET("/ping", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	res := httptest.NewRecorder()

	r.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.Code)
	}
}

func TestTenantIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), tenantIDContextKey, "tenant-abc")
	tenantID, err := TenantIDFromContext(ctx)
	if err != nil {
		t.Fatalf("expected tenant id, got error: %v", err)
	}
	if tenantID != "tenant-abc" {
		t.Fatalf("unexpected tenant id: %s", tenantID)
	}
}
