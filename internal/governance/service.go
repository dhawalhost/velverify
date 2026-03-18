package governance

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/policy"
	"golang.org/x/crypto/bcrypt"
)

// Service defines the interface for the governance service.
type Service interface {
	HealthCheck(ctx context.Context) (bool, error)
	ListOAuthClients(ctx context.Context, tenantID string) ([]oauthclient.Client, error)
	GetOAuthClient(ctx context.Context, tenantID, clientID string) (oauthclient.Client, error)
	CreateOAuthClient(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclient.Client, error)
	UpdateOAuthClient(ctx context.Context, tenantID, clientID string, input UpdateOAuthClientInput) (oauthclient.Client, error)
	DeleteOAuthClient(ctx context.Context, tenantID, clientID string) error

	// Access Requests
	CreateAccessRequest(ctx context.Context, tenantID string, input CreateAccessRequest) (AccessRequest, error)
	ListAccessRequests(ctx context.Context, tenantID, status string) ([]AccessRequest, error)
	ApproveAccessRequest(ctx context.Context, tenantID, requestID, approverID, comment string) error
	RejectAccessRequest(ctx context.Context, tenantID, requestID, approverID, comment string) error

	ResolveTenantSlug(ctx context.Context, slug string) (string, error)

	// Organizations
	ListOrganizations(ctx context.Context, tenantID string, limit, offset int) ([]Organization, error)
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganization(ctx context.Context, tenantID, orgID string) (*Organization, error)
	GetOrganizationByName(ctx context.Context, tenantID, name string) (*Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error
	DeleteOrganization(ctx context.Context, tenantID, orgID string) error

	// Organization memberships
	AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error
	RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error
	ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error)

	// IP Access Policies
	CreateIPPolicy(ctx context.Context, tenantID string, req CreateIPPolicyRequest) (IPPolicy, error)
	ListIPPolicies(ctx context.Context, tenantID string) ([]IPPolicy, error)
	DeleteIPPolicy(ctx context.Context, tenantID, id string) error
}

type CreateOAuthClientInput struct {
	ClientID      string
	Name          string
	Description   string
	ClientType    string
	RedirectURIs  []string
	AllowedScopes []string
	ClientSecret  string
}

type UpdateOAuthClientInput struct {
	Name          *string
	Description   *string
	ClientType    *string
	RedirectURIs  []string
	AllowedScopes []string
	ClientSecret  *string
}

type governanceService struct {
	clientStore  oauthclient.Repository
	reqStore     Repository
	orgStore     OrganizationRepository
	dirClient    DirectoryClient
	policyEngine policy.Engine
}

// NewService creates a new governance service.
func NewService(clientStore oauthclient.Repository, reqStore Repository, orgStore OrganizationRepository, dirClient DirectoryClient, policyEngine policy.Engine) Service {
	return &governanceService{
		clientStore:  clientStore,
		reqStore:     reqStore,
		orgStore:     orgStore,
		dirClient:    dirClient,
		policyEngine: policyEngine,
	}
}

func (s *governanceService) HealthCheck(ctx context.Context) (bool, error) {
	return true, nil
}

func (s *governanceService) ListOAuthClients(ctx context.Context, tenantID string) ([]oauthclient.Client, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.clientStore.ListClientsByTenant(ctx, tenantID)
}

func (s *governanceService) GetOAuthClient(ctx context.Context, tenantID, clientID string) (oauthclient.Client, error) {
	if err := requireTenant(tenantID); err != nil {
		return oauthclient.Client{}, err
	}
	if clientID == "" {
		return oauthclient.Client{}, validationError("client_id is required")
	}
	return s.clientStore.GetClient(ctx, tenantID, clientID)
}

func (s *governanceService) CreateOAuthClient(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclient.Client, error) {
	if err := requireTenant(tenantID); err != nil {
		return oauthclient.Client{}, err
	}
	if err := validateCreateInput(input); err != nil {
		return oauthclient.Client{}, err
	}
	hash, err := maybeHashSecret(input.ClientType, input.ClientSecret)
	if err != nil {
		return oauthclient.Client{}, err
	}
	params := oauthclient.CreateClientParams{
		TenantID:         tenantID,
		ClientID:         input.ClientID,
		ClientType:       normalizedClientType(input.ClientType),
		Name:             input.Name,
		Description:      nullableString(input.Description),
		RedirectURIs:     append([]string(nil), input.RedirectURIs...),
		AllowedScopes:    append([]string(nil), input.AllowedScopes...),
		ClientSecretHash: hash,
	}
	return s.clientStore.CreateClient(ctx, params)
}

func (s *governanceService) UpdateOAuthClient(ctx context.Context, tenantID, clientID string, input UpdateOAuthClientInput) (oauthclient.Client, error) {
	if err := requireTenant(tenantID); err != nil {
		return oauthclient.Client{}, err
	}
	if clientID == "" {
		return oauthclient.Client{}, validationError("client_id is required")
	}
	if err := validateUpdateInput(input); err != nil {
		return oauthclient.Client{}, err
	}
	var secretHash *[]byte
	if input.ClientSecret != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(*input.ClientSecret), bcrypt.DefaultCost)
		if err != nil {
			return oauthclient.Client{}, err
		}
		secretHash = &hash
	}
	params := oauthclient.UpdateClientParams{
		Name:             input.Name,
		Description:      input.Description,
		RedirectURIs:     cloneSlice(input.RedirectURIs),
		AllowedScopes:    cloneSlice(input.AllowedScopes),
		ClientType:       normalizeClientTypePtr(input.ClientType),
		ClientSecretHash: secretHash,
	}
	return s.clientStore.UpdateClient(ctx, tenantID, clientID, params)
}

func (s *governanceService) DeleteOAuthClient(ctx context.Context, tenantID, clientID string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	if clientID == "" {
		return validationError("client_id is required")
	}
	return s.clientStore.DeleteClient(ctx, tenantID, clientID)
}

type validationErr struct {
	msg string
}

func (e *validationErr) Error() string {
	return e.msg
}

func validationError(msg string) error {
	return &validationErr{msg: msg}
}

func (s *governanceService) CreateAccessRequest(ctx context.Context, tenantID string, input CreateAccessRequest) (AccessRequest, error) {
	if err := requireTenant(tenantID); err != nil {
		return AccessRequest{}, err
	}
	requesterID := strings.TrimSpace(input.RequesterID)
	if requesterID == "" {
		if userFromContext, ok := ctx.Value("user_id").(string); ok {
			requesterID = strings.TrimSpace(userFromContext)
		}
	}
	if requesterID == "" {
		return AccessRequest{}, validationError("requester_id is required")
	}

	req := AccessRequest{
		TenantID:     tenantID,
		RequesterID:  requesterID,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		Reason:       input.Reason,
	}
	id, err := s.reqStore.CreateRequest(ctx, req)
	if err != nil {
		return AccessRequest{}, err
	}
	return s.reqStore.GetRequest(ctx, tenantID, id)
}

func (s *governanceService) ListAccessRequests(ctx context.Context, tenantID, status string) ([]AccessRequest, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.reqStore.ListRequests(ctx, tenantID, status)
}

func (s *governanceService) ApproveAccessRequest(ctx context.Context, tenantID, requestID, approverID, comment string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	// Fetch the request to get resource details
	req, err := s.reqStore.GetRequest(ctx, tenantID, requestID)
	if err != nil {
		return fmt.Errorf("failed to get request: %w", err)
	}

	// Evaluate policy
	input := policy.Input{
		Subject:  policy.Subject{ID: approverID},
		Action:   "approve",
		Resource: policy.Resource{Type: "access_request", ID: requestID},
		Context:  map[string]interface{}{"requester_id": req.RequesterID},
	}
	allowed, reason, err := s.policyEngine.Evaluate(ctx, input)
	if err != nil {
		return fmt.Errorf("policy evaluation failed: %w", err)
	}
	if !allowed {
		return fmt.Errorf("policy violation: %s", reason)
	}

	// Provision the access
	switch req.ResourceType {
	case "group":
		if err := s.dirClient.AddUserToGroup(ctx, tenantID, req.RequesterID, req.ResourceID); err != nil {
			return fmt.Errorf("provisioning failed: %w", err)
		}
	case "app":
		return validationError("resource_type 'app' is not supported yet")
	}

	// Update status to approved
	if err := s.reqStore.UpdateRequestStatus(ctx, requestID, "approved"); err != nil {
		return err
	}
	return nil
}

func (s *governanceService) RejectAccessRequest(ctx context.Context, tenantID, requestID, approverID, comment string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	return s.reqStore.UpdateRequestStatus(ctx, requestID, "rejected")
}

func (s *governanceService) ListOrganizations(ctx context.Context, tenantID string, limit, offset int) ([]Organization, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.orgStore.List(ctx, tenantID, limit, offset)
}

func (s *governanceService) CreateOrganization(ctx context.Context, org *Organization) error {
	if err := requireTenant(org.TenantID); err != nil {
		return err
	}
	return s.orgStore.Create(ctx, org)
}

func (s *governanceService) GetOrganization(ctx context.Context, tenantID, orgID string) (*Organization, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.orgStore.Get(ctx, tenantID, orgID)
}

func (s *governanceService) GetOrganizationByName(ctx context.Context, tenantID, name string) (*Organization, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.orgStore.GetByName(ctx, tenantID, name)
}

func (s *governanceService) UpdateOrganization(ctx context.Context, org *Organization) error {
	if err := requireTenant(org.TenantID); err != nil {
		return err
	}
	return s.orgStore.Update(ctx, org)
}

func (s *governanceService) DeleteOrganization(ctx context.Context, tenantID, orgID string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	return s.orgStore.Delete(ctx, tenantID, orgID)
}

func (s *governanceService) ResolveTenantSlug(ctx context.Context, slug string) (string, error) {
	return s.dirClient.ResolveTenantSlug(ctx, slug)
}

func (s *governanceService) AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	return s.dirClient.AddUserToOrganization(ctx, tenantID, userID, orgID, role)
}

func (s *governanceService) RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	return s.dirClient.RemoveUserFromOrganization(ctx, tenantID, userID, orgID)
}

func (s *governanceService) ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.dirClient.ListUserOrganizations(ctx, tenantID, userID)
}

func requireTenant(tenantID string) error {
	if tenantID == "" {
		return validationError("tenant_id is required")
	}
	return nil
}

func validateCreateInput(input CreateOAuthClientInput) error {
	if input.ClientID == "" {
		return validationError("client_id is required")
	}
	if input.Name == "" {
		return validationError("name is required")
	}
	if err := validateClientType(input.ClientType); err != nil {
		return err
	}
	if len(input.RedirectURIs) == 0 {
		return validationError("redirect_uris must include at least one URI")
	}
	for _, uri := range input.RedirectURIs {
		if _, err := url.ParseRequestURI(uri); err != nil {
			return validationError(fmt.Sprintf("invalid redirect_uri %s", uri))
		}
	}
	if len(input.AllowedScopes) == 0 {
		return validationError("allowed_scopes must include at least one scope")
	}
	if normalizedClientType(input.ClientType) == "confidential" && strings.TrimSpace(input.ClientSecret) == "" {
		return validationError("client_secret is required for confidential clients")
	}
	return nil
}

func validateUpdateInput(input UpdateOAuthClientInput) error {
	if input.ClientType != nil {
		if err := validateClientType(*input.ClientType); err != nil {
			return err
		}
	}
	for _, uri := range input.RedirectURIs {
		if _, err := url.ParseRequestURI(uri); err != nil {
			return validationError(fmt.Sprintf("invalid redirect_uri %s", uri))
		}
	}
	return nil
}

func validateClientType(clientType string) error {
	switch normalizedClientType(clientType) {
	case "public", "confidential":
		return nil
	default:
		return validationError("client_type must be public or confidential")
	}
}

func normalizedClientType(clientType string) string {
	if clientType == "" {
		return "public"
	}
	return strings.ToLower(clientType)
}

func normalizeClientTypePtr(value *string) *string {
	if value == nil {
		return nil
	}
	normalized := normalizedClientType(*value)
	return &normalized
}

func maybeHashSecret(clientType, secret string) ([]byte, error) {
	if normalizedClientType(clientType) != "confidential" || strings.TrimSpace(secret) == "" {
		return nil, nil
	}
	return bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
}

func cloneSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func nullableString(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

// IsValidationError reports whether the error represents invalid user input.
func IsValidationError(err error) bool {
	var vErr *validationErr
	return errors.As(err, &vErr)
}

func (s *governanceService) CreateIPPolicy(ctx context.Context, tenantID string, req CreateIPPolicyRequest) (IPPolicy, error) {
	if err := requireTenant(tenantID); err != nil {
		return IPPolicy{}, err
	}

	p := IPPolicy{
		ID:          generateShortID(), // Using a helper or uuid
		TenantID:    tenantID,
		Type:        req.Type,
		CIDR:        req.CIDR,
		CountryCode: req.CountryCode,
		Reason:      req.Reason,
	}

	id, err := s.reqStore.CreateIPPolicy(ctx, p)
	if err != nil {
		return IPPolicy{}, err
	}
	p.ID = id
	return p, nil
}

func (s *governanceService) ListIPPolicies(ctx context.Context, tenantID string) ([]IPPolicy, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.reqStore.ListIPPolicies(ctx, tenantID)
}

func (s *governanceService) DeleteIPPolicy(ctx context.Context, tenantID, id string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	return s.reqStore.DeleteIPPolicy(ctx, tenantID, id)
}

func generateShortID() string {
	// Simple random ID for internal use if not using UUID
	return fmt.Sprintf("pol_%d", time.Now().UnixNano())
}
