package governance

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

func TestListOAuthClientsReturnsClients(t *testing.T) {
	tenantID := "11111111-1111-1111-1111-111111111111"
	stub := &stubService{
		listOAuthClientsFn: func(ctx context.Context, gotTenant string) ([]oauthclient.Client, error) {
			if gotTenant != tenantID {
				t.Fatalf("unexpected tenant id: %s", gotTenant)
			}
			return []oauthclient.Client{{
				TenantID:     tenantID,
				ClientID:     "client-one",
				ClientType:   "public",
				Name:         "Client One",
				Description:  sql.NullString{String: "First client", Valid: true},
				RedirectURIs: pq.StringArray{"https://app.wardseal.com/callback"},
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
		createOAuthClientFn: func(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclient.Client, error) {
			if input.ClientID == "" {
				t.Fatalf("expected client_id to be parsed")
			}
			return oauthclient.Client{}, validationError("invalid redirect")
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
		middleware.DefaultTenantHeader: "11111111-1111-1111-1111-111111111111",
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
		getOAuthClientFn: func(ctx context.Context, tenantID, clientID string) (oauthclient.Client, error) {
			return oauthclient.Client{}, oauthclient.ErrNotFound
		},
	}
	router := newTestRouter(t, stub)

	resp := performRequest(router, http.MethodGet, "/api/v1/oauth/clients/missing", nil, map[string]string{
		middleware.DefaultTenantHeader: "11111111-1111-1111-1111-111111111111",
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
	healthCheckFn           func(ctx context.Context) (bool, error)
	listOAuthClientsFn      func(ctx context.Context, tenantID string) ([]oauthclient.Client, error)
	getOAuthClientFn        func(ctx context.Context, tenantID, clientID string) (oauthclient.Client, error)
	createOAuthClientFn     func(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclient.Client, error)
	updateOAuthClientFn     func(ctx context.Context, tenantID, clientID string, input UpdateOAuthClientInput) (oauthclient.Client, error)
	deleteOAuthClientFn     func(ctx context.Context, tenantID, clientID string) error
	createAccessRequestFn   func(ctx context.Context, tenantID string, input CreateAccessRequest) (AccessRequest, error)
	listAccessRequestsFn    func(ctx context.Context, tenantID, status string) ([]AccessRequest, error)
	approveAccessRequestFn  func(ctx context.Context, tenantID, requestID, approverID, comment string) error
	rejectAccessRequestFn   func(ctx context.Context, tenantID, requestID, approverID, comment string) error
	resolveTenantSlugFn     func(ctx context.Context, slug string) (string, error)
	listOrganizationsFn     func(ctx context.Context, tenantID string, limit, offset int) ([]Organization, error)
	createOrganizationFn    func(ctx context.Context, org *Organization) error
	getOrganizationFn       func(ctx context.Context, tenantID, orgID string) (*Organization, error)
	getOrganizationByNameFn func(ctx context.Context, tenantID, name string) (*Organization, error)
	updateOrganizationFn    func(ctx context.Context, org *Organization) error
	deleteOrganizationFn    func(ctx context.Context, tenantID, orgID string) error
	addUserToOrgFn          func(ctx context.Context, tenantID, userID, orgID, role string) error
	removeUserFromOrgFn     func(ctx context.Context, tenantID, userID, orgID string) error
	listUserOrgsFn          func(ctx context.Context, tenantID, userID string) ([]string, error)
	createIPPolicyFn        func(ctx context.Context, tenantID string, req CreateIPPolicyRequest) (IPPolicy, error)
	listIPPoliciesFn        func(ctx context.Context, tenantID string) ([]IPPolicy, error)
	deleteIPPolicyFn        func(ctx context.Context, tenantID, ipPolicyID string) error
}

func (s *stubService) HealthCheck(ctx context.Context) (bool, error) {
	if s.healthCheckFn != nil {
		return s.healthCheckFn(ctx)
	}
	return true, nil
}

func (s *stubService) ListOAuthClients(ctx context.Context, tenantID string) ([]oauthclient.Client, error) {
	if s.listOAuthClientsFn == nil {
		panic("ListOAuthClients called unexpectedly")
	}
	return s.listOAuthClientsFn(ctx, tenantID)
}

func (s *stubService) GetOAuthClient(ctx context.Context, tenantID, clientID string) (oauthclient.Client, error) {
	if s.getOAuthClientFn == nil {
		panic("GetOAuthClient called unexpectedly")
	}
	return s.getOAuthClientFn(ctx, tenantID, clientID)
}

func (s *stubService) CreateOAuthClient(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclient.Client, error) {
	if s.createOAuthClientFn == nil {
		panic("CreateOAuthClient called unexpectedly")
	}
	return s.createOAuthClientFn(ctx, tenantID, input)
}

func (s *stubService) UpdateOAuthClient(ctx context.Context, tenantID, clientID string, input UpdateOAuthClientInput) (oauthclient.Client, error) {
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

func (s *stubService) CreateAccessRequest(ctx context.Context, tenantID string, input CreateAccessRequest) (AccessRequest, error) {
	if s.createAccessRequestFn == nil {
		panic("CreateAccessRequest called unexpectedly")
	}
	return s.createAccessRequestFn(ctx, tenantID, input)
}

func (s *stubService) ListAccessRequests(ctx context.Context, tenantID, status string) ([]AccessRequest, error) {
	if s.listAccessRequestsFn == nil {
		panic("ListAccessRequests called unexpectedly")
	}
	return s.listAccessRequestsFn(ctx, tenantID, status)
}

func (s *stubService) ApproveAccessRequest(ctx context.Context, tenantID, requestID, approverID, comment string) error {
	if s.approveAccessRequestFn == nil {
		panic("ApproveAccessRequest called unexpectedly")
	}
	return s.approveAccessRequestFn(ctx, tenantID, requestID, approverID, comment)
}

func (s *stubService) RejectAccessRequest(ctx context.Context, tenantID, requestID, approverID, comment string) error {
	if s.rejectAccessRequestFn == nil {
		panic("RejectAccessRequest called unexpectedly")
	}
	return s.rejectAccessRequestFn(ctx, tenantID, requestID, approverID, comment)
}

func (s *stubService) ResolveTenantSlug(ctx context.Context, slug string) (string, error) {
	if s.resolveTenantSlugFn != nil {
		return s.resolveTenantSlugFn(ctx, slug)
	}
	return slug, nil
}

func (s *stubService) ListOrganizations(ctx context.Context, tenantID string, limit, offset int) ([]Organization, error) {
	if s.listOrganizationsFn != nil {
		return s.listOrganizationsFn(ctx, tenantID, limit, offset)
	}
	return nil, nil
}

func (s *stubService) CreateOrganization(ctx context.Context, org *Organization) error {
	if s.createOrganizationFn != nil {
		return s.createOrganizationFn(ctx, org)
	}
	return nil
}

func (s *stubService) GetOrganization(ctx context.Context, tenantID, orgID string) (*Organization, error) {
	if s.getOrganizationFn != nil {
		return s.getOrganizationFn(ctx, tenantID, orgID)
	}
	return nil, nil
}

func (s *stubService) GetOrganizationByName(ctx context.Context, tenantID, name string) (*Organization, error) {
	if s.getOrganizationByNameFn != nil {
		return s.getOrganizationByNameFn(ctx, tenantID, name)
	}
	return nil, nil
}

func (s *stubService) UpdateOrganization(ctx context.Context, org *Organization) error {
	if s.updateOrganizationFn != nil {
		return s.updateOrganizationFn(ctx, org)
	}
	return nil
}

func (s *stubService) DeleteOrganization(ctx context.Context, tenantID, orgID string) error {
	if s.deleteOrganizationFn != nil {
		return s.deleteOrganizationFn(ctx, tenantID, orgID)
	}
	return nil
}

func (s *stubService) AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error {
	if s.addUserToOrgFn != nil {
		return s.addUserToOrgFn(ctx, tenantID, userID, orgID, role)
	}
	return nil
}

func (s *stubService) RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error {
	if s.removeUserFromOrgFn != nil {
		return s.removeUserFromOrgFn(ctx, tenantID, userID, orgID)
	}
	return nil
}

func (s *stubService) ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error) {
	if s.listUserOrgsFn != nil {
		return s.listUserOrgsFn(ctx, tenantID, userID)
	}
	return nil, nil
}

func (s *stubService) CreateIPPolicy(ctx context.Context, tenantID string, req CreateIPPolicyRequest) (IPPolicy, error) {
	if s.createIPPolicyFn != nil {
		return s.createIPPolicyFn(ctx, tenantID, req)
	}
	return IPPolicy{}, nil
}

func (s *stubService) ListIPPolicies(ctx context.Context, tenantID string) ([]IPPolicy, error) {
	if s.listIPPoliciesFn != nil {
		return s.listIPPoliciesFn(ctx, tenantID)
	}
	return nil, nil
}

func (s *stubService) DeleteIPPolicy(ctx context.Context, tenantID, ipPolicyID string) error {
	if s.deleteIPPolicyFn != nil {
		return s.deleteIPPolicyFn(ctx, tenantID, ipPolicyID)
	}
	return nil
}
