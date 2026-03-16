package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestClassifyRateLimitEndpoint(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "/t/acme/oauth2/token", want: "token"},
		{path: "/api/v1/setup/password", want: "setup"},
		{path: "/webhooks/notify", want: "webhook"},
		{path: "/t/acme/login", want: "login"},
		{path: "/api/v1/users", want: "default"},
	}

	for _, tt := range tests {
		got := classifyRateLimitEndpoint(tt.path)
		if got != tt.want {
			t.Fatalf("classifyRateLimitEndpoint(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestDistributedRateLimitFallbackIsTenantAndEndpointAware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(DistributedRateLimitMiddleware(DistributedRateLimitConfig{
		RedisClient: nil,
		UseTenant:   true,
		DegradedProfile: RateLimitWindowProfile{
			Requests: 1,
			Window:   time.Minute,
		},
	}))
	r.POST("/t/:tenant/login", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/t/:tenant/oauth2/token", func(c *gin.Context) { c.Status(http.StatusOK) })

	// First login request for tenant-a is allowed.
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/t/tenant-a/login", nil)
	req1.Header.Set(DefaultTenantHeader, "tenant-a")
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", w1.Code)
	}

	// Second login request for same tenant and IP should be limited.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/t/tenant-a/login", nil)
	req2.Header.Set(DefaultTenantHeader, "tenant-a")
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second same-scope request 429, got %d", w2.Code)
	}

	// Different endpoint should have a separate bucket.
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/t/tenant-a/oauth2/token", nil)
	req3.Header.Set(DefaultTenantHeader, "tenant-a")
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected different endpoint request 200, got %d", w3.Code)
	}

	// Same endpoint, different tenant should have a separate bucket.
	w4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodPost, "/t/tenant-b/login", nil)
	req4.Header.Set(DefaultTenantHeader, "tenant-b")
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("expected different tenant request 200, got %d", w4.Code)
	}
}
