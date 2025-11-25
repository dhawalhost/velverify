package governance

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dhawalhost/velverify/internal/oauthclients"
	"github.com/dhawalhost/velverify/pkg/middleware"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

func TestListOAuthClientsReturnsClients(t *testing.T) {
	tenantID := "tenant-123"
	stub := &stubService{
		listOAuthClientsFn: func(ctx context.Context, gotTenant string) ([]oauthclients.Client, error) {
			if gotTenant != tenantID {
				t.Fatalf("unexpected tenant id: %s", gotTenant)
			}
			return []oauthclients.Client{{
				TenantID:     tenantID,
				ClientID:     "client-one",
				ClientType:   "public",
				Name:         "Client One",
				Description:  sql.NullString{String: "First client", Valid: true},
				RedirectURIs: pq.StringArray{"https://app.example.com/callback"},
				AllowedScopes: pq.StringArray{
					"openid",
					"profile",
				},
			}}, nil
		},
	}

	router := newTestRouter(t, stub)

	resp := performRequest(router, http.MethodGet, "/api/v1/oauth/clients", nil, map[string]string{
		middleware.DefaultTenantHeader: tenantID,
	})

	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.Code)
	}

	var payload struct {
		Clients []OAuthClientResponse `json:"clients"`
	}
	decodeJSON(t, resp.Body.Bytes(), &payload)
	if len(payload.Clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(payload.Clients))
	}

	client := payload.Clients[0]
	if client.Description != "First client" {
		t.Fatalf("expected description to round-trip")
	}
	if client.TenantID != tenantID {
		t.Fatalf("unexpected tenant in response: %s", client.TenantID)
	}
}

func TestCreateOAuthClientValidationErrorPropagates(t *testing.T) {
	stub := &stubService{
		createOAuthClientFn: func(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclients.Client, error) {
			if input.ClientID == "" {
				t.Fatalf("expected client_id to be parsed")
			}
			return oauthclients.Client{}, validationError("invalid redirect")
		},
	}

	router := newTestRouter(t, stub)

	body := mustJSONBody(t, map[string]interface{}{
		"client_id":      "client-two",
		"name":           "Client Two",
		"client_type":    "public",
		"redirect_uris":  []string{"https://example/app/callback"},
		"allowed_scopes": []string{"openid"},
	})

	resp := performRequest(router, http.MethodPost, "/api/v1/oauth/clients", body, map[string]string{
		middleware.DefaultTenantHeader: "tenant-1",
		"Content-Type":                 "application/json",
	})

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", resp.Code)
	}

	var payload struct {
		Error string `json:"error"`
	}
	decodeJSON(t, resp.Body.Bytes(), &payload)
	if payload.Error != "invalid redirect" {
		t.Fatalf("unexpected error message: %s", payload.Error)
	}
}

func TestGetOAuthClientNotFound(t *testing.T) {
	stub := &stubService{
		getOAuthClientFn: func(ctx context.Context, tenantID, clientID string) (oauthclients.Client, error) {
			return oauthclients.Client{}, oauthclients.ErrNotFound
		},
	}
	router := newTestRouter(t, stub)

	resp := performRequest(router, http.MethodGet, "/api/v1/oauth/clients/missing", nil, map[string]string{
		middleware.DefaultTenantHeader: "tenant-1",
	})

	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.Code)
	}
}

func TestRoutesRequireTenantHeader(t *testing.T) {
	stub := &stubService{}
	router := newTestRouter(t, stub)

	resp := performRequest(router, http.MethodGet, "/api/v1/oauth/clients", nil, nil)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when tenant header missing, got %d", resp.Code)
	}
}

func newTestRouter(t *testing.T, svc Service) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewHTTPHandler(svc, zap.NewNop())
	handler.RegisterRoutes(router)
	return router
}

func performRequest(router *gin.Engine, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, path, reader)
	if err != nil {
		panic(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	return resp
}

func mustJSONBody(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal body: %v", err)
	}
	return b
}

func decodeJSON(t *testing.T, data []byte, out interface{}) {
	t.Helper()
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
}

type stubService struct {
	healthCheckFn       func(ctx context.Context) (bool, error)
	listOAuthClientsFn  func(ctx context.Context, tenantID string) ([]oauthclients.Client, error)
	getOAuthClientFn    func(ctx context.Context, tenantID, clientID string) (oauthclients.Client, error)
	createOAuthClientFn func(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclients.Client, error)
	updateOAuthClientFn func(ctx context.Context, tenantID, clientID string, input UpdateOAuthClientInput) (oauthclients.Client, error)
	deleteOAuthClientFn func(ctx context.Context, tenantID, clientID string) error
}

func (s *stubService) HealthCheck(ctx context.Context) (bool, error) {
	if s.healthCheckFn != nil {
		return s.healthCheckFn(ctx)
	}
	return true, nil
}

func (s *stubService) ListOAuthClients(ctx context.Context, tenantID string) ([]oauthclients.Client, error) {
	if s.listOAuthClientsFn == nil {
		panic("ListOAuthClients called unexpectedly")
	}
	return s.listOAuthClientsFn(ctx, tenantID)
}

func (s *stubService) GetOAuthClient(ctx context.Context, tenantID, clientID string) (oauthclients.Client, error) {
	if s.getOAuthClientFn == nil {
		panic("GetOAuthClient called unexpectedly")
	}
	return s.getOAuthClientFn(ctx, tenantID, clientID)
}

func (s *stubService) CreateOAuthClient(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclients.Client, error) {
	if s.createOAuthClientFn == nil {
		panic("CreateOAuthClient called unexpectedly")
	}
	return s.createOAuthClientFn(ctx, tenantID, input)
}

func (s *stubService) UpdateOAuthClient(ctx context.Context, tenantID, clientID string, input UpdateOAuthClientInput) (oauthclients.Client, error) {
	if s.updateOAuthClientFn == nil {
		panic("UpdateOAuthClient called unexpectedly")
	}
	return s.updateOAuthClientFn(ctx, tenantID, clientID, input)
}

func (s *stubService) DeleteOAuthClient(ctx context.Context, tenantID, clientID string) error {
	if s.deleteOAuthClientFn == nil {
		panic("DeleteOAuthClient called unexpectedly")
	}
	return s.deleteOAuthClientFn(ctx, tenantID, clientID)
}
