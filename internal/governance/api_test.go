package governance

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/internal/auth"
	"github.com/dhawalhost/wardseal/internal/authz"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/policy"
	"github.com/dhawalhost/wardseal/internal/webhook"
	"github.com/dhawalhost/wardseal/pkg/llm"
	"github.com/dhawalhost/wardseal/pkg/middleware"
)

func TestListOAuthClientsReturnsClients(t *testing.T) {
	tenantID := "admin-system"
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
		middleware.DefaultTenantHeader: "admin-system",
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
		middleware.DefaultTenantHeader: "admin-system",
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
	dummyValidator := func(token string) (*middleware.Claims, error) {
		return &middleware.Claims{
			Tenant: "admin-system",
			Roles:  []string{"admin"},
		}, nil
	}
	handler := NewHTTPHandler(svc, &stubCampaignService{}, &stubWebhookService{}, &stubLLMProvider{}, nil, dummyValidator, zap.NewNop())
	handler.RegisterRoutes(router)
	return router
}

type stubCampaignService struct{}

func (s *stubCampaignService) CreateCampaign(ctx context.Context, tenantID string, input CreateCampaignInput) (Campaign, error) {
	return Campaign{}, nil
}

func (s *stubCampaignService) GetCampaign(ctx context.Context, tenantID, id string) (Campaign, error) {
	return Campaign{}, nil
}

func (s *stubCampaignService) ListCampaigns(ctx context.Context, tenantID, status string) ([]Campaign, error) {
	return []Campaign{}, nil
}

func (s *stubCampaignService) StartCampaign(ctx context.Context, tenantID, id string) error {
	return nil
}

func (s *stubCampaignService) CompleteCampaign(ctx context.Context, tenantID, id string) error {
	return nil
}

func (s *stubCampaignService) CancelCampaign(ctx context.Context, tenantID, id string) error {
	return nil
}

func (s *stubCampaignService) DeleteCampaign(ctx context.Context, tenantID, id string) error {
	return nil
}

func (s *stubCampaignService) AddReviewItem(ctx context.Context, tenantID, campaignID string, item CertificationItem) (CertificationItem, error) {
	return CertificationItem{}, nil
}

func (s *stubCampaignService) ListPendingItems(ctx context.Context, campaignID string) ([]CertificationItem, error) {
	return []CertificationItem{}, nil
}

func (s *stubCampaignService) ListReviewItems(ctx context.Context, tenantID, reviewerID string) ([]CertificationItem, error) {
	return []CertificationItem{}, nil
}

func (s *stubCampaignService) ApproveItem(ctx context.Context, tenantID, itemID, comment string) error {
	return nil
}

func (s *stubCampaignService) RevokeItem(ctx context.Context, tenantID, itemID, comment string) error {
	return nil
}

func (s *stubCampaignService) GenerateRecertificationCampaign(ctx context.Context, tenantID, userID string) error {
	return nil
}

func (s *stubCampaignService) SetGovernanceService(service Service) {
}

type stubWebhookService struct{}

func (s *stubWebhookService) CreateWebhook(ctx context.Context, tenantID, url, secret string, events []string) (string, error) {
	return "", nil
}

func (s *stubWebhookService) GetWebhook(ctx context.Context, tenantID, id string) (*webhook.Webhook, error) {
	return nil, nil
}

func (s *stubWebhookService) ListWebhooks(ctx context.Context, tenantID string) ([]webhook.Webhook, error) {
	return []webhook.Webhook{}, nil
}

func (s *stubWebhookService) DeleteWebhook(ctx context.Context, tenantID, id string) error {
	return nil
}

func (s *stubWebhookService) GetWebhooksForEvent(ctx context.Context, tenantID, event string) ([]webhook.Webhook, error) {
	return []webhook.Webhook{}, nil
}

type stubLLMProvider struct {
	generateResponseFn func(ctx context.Context, systemPrompt, userQuery string) (string, error)
}

func (p *stubLLMProvider) GenerateResponse(ctx context.Context, systemPrompt, userQuery string) (string, error) {
	if p.generateResponseFn != nil {
		return p.generateResponseFn(ctx, systemPrompt, userQuery)
	}
	return "I am a stub AI", nil
}

func (p *stubLLMProvider) Chat(ctx context.Context, messages []llm.Message, tools []llm.Tool) (llm.Message, error) {
	return llm.Message{Role: "assistant", Content: "I am a stub AI"}, nil
}

var _ llm.Provider = (*stubLLMProvider)(nil)

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
	req.Header.Set("Authorization", "Bearer dummy-token")
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
	confirmSafetyActionFn   func(ctx context.Context, tenantID, actionID, approverID, comment string) error
	rejectSafetyActionFn    func(ctx context.Context, tenantID, actionID, approverID, comment string) error

	listWorkloadsFn      func(ctx context.Context, tenantID string) ([]auth.Workload, error)
	getDashboardStatsFn  func(ctx context.Context, tenantID string) (DashboardStats, error)
	createWorkloadFn     func(ctx context.Context, tenantID string, w auth.Workload) (string, error)
	listRelationshipsFn  func(ctx context.Context, tenantID string, query authz.Query) ([]authz.RelationTuple, error)
	traverseGraphFn      func(ctx context.Context, tenantID, subjectID string) ([]authz.RelationTuple, error)
	gatherAuditContextFn func(ctx context.Context, tenantID string) (string, error)
	getApprovedScopesFn  func(ctx context.Context, tenantID, workloadID string) ([]string, time.Duration, error)
	getAccessRequestFn   func(ctx context.Context, tenantID, id string) (AccessRequest, error)
	listUsersFn          func(ctx context.Context, tenantID string) ([]User, error)
	listGroupsFn         func(ctx context.Context, tenantID string) ([]Group, error)
	evaluatePolicyFn     func(ctx context.Context, input policy.Input) (bool, string, error)
}

// GetDevice implements [Service].
func (s *stubService) GetDevice(ctx context.Context, tenantID string, id string) (Device, error) {
	panic("unimplemented")
}

// ListDevices implements [Service].
func (s *stubService) ListDevices(ctx context.Context, tenantID string) ([]Device, error) {
	panic("unimplemented")
}

// ListSafetyActions implements [Service].
func (s *stubService) ListSafetyActions(ctx context.Context, tenantID string, status string) ([]SafetyAction, error) {
	panic("unimplemented")
}

// ProposeSafetyAction implements [Service].
func (s *stubService) ProposeSafetyAction(ctx context.Context, tenantID string, input ProposeSafetyActionInput) (SafetyAction, error) {
	panic("unimplemented")
}

// RegisterDevice implements [Service].
func (s *stubService) RegisterDevice(ctx context.Context, tenantID string, d Device) (string, error) {
	panic("unimplemented")
}

// RejectSafetyAction implements [Service].
func (s *stubService) RejectSafetyAction(ctx context.Context, tenantID string, actionID string, approverID string, comment string) error {
	if s.rejectSafetyActionFn != nil {
		return s.rejectSafetyActionFn(ctx, tenantID, actionID, approverID, comment)
	}
	return nil
}

// UpdateDeviceStatus implements [Service].
func (s *stubService) UpdateDeviceStatus(ctx context.Context, tenantID string, id string, status string) error {
	panic("unimplemented")
}

func (s *stubService) CreateAgentAccessRequest(ctx context.Context, tenantID string, workloadID string, scopes []string, reason string, duration string) (AccessRequest, error) {
	panic("unimplemented")
}

func (s *stubService) GetAccessRequest(ctx context.Context, tenantID, id string) (AccessRequest, error) {
	if s.getAccessRequestFn != nil {
		return s.getAccessRequestFn(ctx, tenantID, id)
	}
	return AccessRequest{}, nil
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

func (s *stubService) ConfirmSafetyAction(ctx context.Context, tenantID, actionID, approverID, comment string) error {
	if s.confirmSafetyActionFn != nil {
		return s.confirmSafetyActionFn(ctx, tenantID, actionID, approverID, comment)
	}
	return nil
}

func (s *stubService) ListWorkloads(ctx context.Context, tenantID string) ([]auth.Workload, error) {
	if s.listWorkloadsFn != nil {
		return s.listWorkloadsFn(ctx, tenantID)
	}
	return nil, nil
}

func (s *stubService) CreateWorkload(ctx context.Context, tenantID string, w auth.Workload) (string, error) {
	if s.createWorkloadFn != nil {
		return s.createWorkloadFn(ctx, tenantID, w)
	}
	return "", nil
}

func (s *stubService) GetDashboardStats(ctx context.Context, tenantID string) (DashboardStats, error) {
	if s.getDashboardStatsFn != nil {
		return s.getDashboardStatsFn(ctx, tenantID)
	}
	return DashboardStats{}, nil
}

func (s *stubService) ListRelationships(ctx context.Context, tenantID string, query authz.Query) ([]authz.RelationTuple, error) {
	if s.listRelationshipsFn != nil {
		return s.listRelationshipsFn(ctx, tenantID, query)
	}
	return nil, nil
}

func (s *stubService) TraverseGraph(ctx context.Context, tenantID, subjectID string) ([]authz.RelationTuple, error) {
	if s.traverseGraphFn != nil {
		return s.traverseGraphFn(ctx, tenantID, subjectID)
	}
	return nil, nil
}

func (s *stubService) GatherAuditContext(ctx context.Context, tenantID string) (string, error) {
	if s.gatherAuditContextFn != nil {
		return s.gatherAuditContextFn(ctx, tenantID)
	}
	return "", nil
}

func (s *stubService) GetApprovedScopes(ctx context.Context, tenantID, workloadID string) ([]string, time.Duration, error) {
	if s.getApprovedScopesFn != nil {
		return s.getApprovedScopesFn(ctx, tenantID, workloadID)
	}
	return nil, 0, nil
}

func (s *stubService) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	if s.listUsersFn != nil {
		return s.listUsersFn(ctx, tenantID)
	}
	return nil, nil
}

func (s *stubService) ListGroups(ctx context.Context, tenantID string) ([]Group, error) {
	if s.listGroupsFn != nil {
		return s.listGroupsFn(ctx, tenantID)
	}
	return nil, nil
}

func (s *stubService) EvaluatePolicy(ctx context.Context, input policy.Input) (bool, string, error) {
	if s.evaluatePolicyFn != nil {
		return s.evaluatePolicyFn(ctx, input)
	}
	return true, "Allowed", nil
}
