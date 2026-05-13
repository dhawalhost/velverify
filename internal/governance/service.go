package governance

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dhawalhost/wardseal/internal/auth"
	"github.com/dhawalhost/wardseal/internal/authz"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/policy"
	"github.com/dhawalhost/wardseal/internal/rbac"
	"github.com/dhawalhost/wardseal/pkg/eventbus"
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
	CreateAgentAccessRequest(ctx context.Context, tenantID string, workloadID string, scopes []string, reason string, duration string) (AccessRequest, error)
	GetAccessRequest(ctx context.Context, tenantID, id string) (AccessRequest, error)
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

	// Safety Actions
	ProposeSafetyAction(ctx context.Context, tenantID string, input ProposeSafetyActionInput) (SafetyAction, error)
	ListSafetyActions(ctx context.Context, tenantID, status string) ([]SafetyAction, error)
	ConfirmSafetyAction(ctx context.Context, tenantID, actionID, approverID, comment string) error
	RejectSafetyAction(ctx context.Context, tenantID, actionID, approverID, comment string) error

	// Identity Graph Explorer
	ListRelationships(ctx context.Context, tenantID string, query authz.Query) ([]authz.RelationTuple, error)

	// Endpoints (Device Trust)
	RegisterDevice(ctx context.Context, tenantID string, d Device) (string, error)
	ListDevices(ctx context.Context, tenantID string) ([]Device, error)
	GetDevice(ctx context.Context, tenantID, id string) (Device, error)
	UpdateDeviceStatus(ctx context.Context, tenantID, id, status string) error

	// Non-Human Identities (Workloads)
	ListWorkloads(ctx context.Context, tenantID string) ([]auth.Workload, error)
	CreateWorkload(ctx context.Context, tenantID string, workload auth.Workload) (string, error)

	// Dashboard & Stats
	GetDashboardStats(ctx context.Context, tenantID string) (DashboardStats, error)

	// Graph Traversal
	TraverseGraph(ctx context.Context, tenantID, subjectID string) ([]authz.RelationTuple, error)

	// AI Audit Context
	GatherAuditContext(ctx context.Context, tenantID string) (string, error)

	// Machine Identity Support
	GetApprovedScopes(ctx context.Context, tenantID, workloadID string) ([]string, time.Duration, error)

	// Directory Integration
	ListUsers(ctx context.Context, tenantID string) ([]User, error)
	ListGroups(ctx context.Context, tenantID string) ([]Group, error)

	// Policy Integration
	EvaluatePolicy(ctx context.Context, input policy.Input) (bool, string, error)
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
	clientStore   oauthclient.Repository
	reqStore      Repository
	orgStore      OrganizationRepository
	dirClient     DirectoryClient
	policyEngine  policy.Engine
	rbacSvc       rbac.Service
	endpointStore EndpointRepository
	workloadStore auth.WorkloadRepository
	engine        *authz.Engine
	bus           eventbus.EventBus
}

// NewService creates a new governance service.
func NewService(clientStore oauthclient.Repository, reqStore Repository, orgStore OrganizationRepository, endpointStore EndpointRepository, workloadStore auth.WorkloadRepository, dirClient DirectoryClient, policyEngine policy.Engine, rbacSvc rbac.Service, engine *authz.Engine, bus eventbus.EventBus) Service {
	return &governanceService{
		clientStore:   clientStore,
		reqStore:      reqStore,
		orgStore:      orgStore,
		endpointStore: endpointStore,
		workloadStore: workloadStore,
		dirClient:     dirClient,
		policyEngine:  policyEngine,
		rbacSvc:       rbacSvc,
		engine:        engine,
		bus:           bus,
	}
}

func (s *governanceService) HealthCheck(ctx context.Context) (bool, error) {
	return true, nil
}

func (s *governanceService) CreateAgentAccessRequest(ctx context.Context, tenantID string, workloadID string, scopes []string, reason string, duration string) (AccessRequest, error) {
	metadata, _ := json.Marshal(map[string]interface{}{
		"requested_scopes": scopes,
		"agent_workflow":   true,
	})

	return s.CreateAccessRequest(ctx, tenantID, CreateAccessRequest{
		RequesterID:   workloadID,
		RequesterType: "workload",
		ResourceType:  "machine_access",
		ResourceID:    workloadID,
		Reason:        reason,
		Duration:      duration,
		Metadata:      metadata,
	})
}

func (s *governanceService) GetApprovedScopes(ctx context.Context, tenantID, workloadID string) ([]string, time.Duration, error) {
	requests, err := s.reqStore.ListRequests(ctx, tenantID, "approved")
	if err != nil {
		return nil, 0, err
	}

	for _, req := range requests {
		if req.RequesterType == "workload" && req.RequesterID == workloadID {
			var metadata struct {
				RequestedScopes []string `json:"requested_scopes"`
			}
			if err := json.Unmarshal(req.Metadata, &metadata); err == nil && len(metadata.RequestedScopes) > 0 {
				ttl := 1 * time.Hour
				if *req.Duration != "" {
					if d, err := time.ParseDuration(*req.Duration); err == nil {
						ttl = d
					}
				}
				return metadata.RequestedScopes, ttl, nil
			}
		}
	}

	return nil, 0, errors.New("no approved machine access request found")
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

	requesterType := input.RequesterType
	if requesterType == "" {
		requesterType = "user"
	}

	req := AccessRequest{
		TenantID:      tenantID,
		RequesterID:   requesterID,
		RequesterType: requesterType,
		ResourceType:  input.ResourceType,
		ResourceID:    input.ResourceID,
		Reason:        &input.Reason,
		Duration:      &input.Duration,
		DeviceID:      &input.DeviceID,
		Metadata:      input.Metadata,
	}
	id, err := s.reqStore.CreateRequest(ctx, req)
	if err != nil {
		return AccessRequest{}, err
	}

	s.publishEvent(ctx, "AccessRequestCreated", map[string]interface{}{
		"tenant_id":     tenantID,
		"request_id":    id,
		"requester_id":  req.RequesterID,
		"resource_type": req.ResourceType,
		"resource_id":   req.ResourceID,
		"device_id":     req.DeviceID,
	})

	return s.reqStore.GetRequest(ctx, tenantID, id)
}

func (s *governanceService) GetAccessRequest(ctx context.Context, tenantID, id string) (AccessRequest, error) {
	if err := requireTenant(tenantID); err != nil {
		return AccessRequest{}, err
	}
	if id == "" {
		return AccessRequest{}, validationError("request_id is required")
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

	// Evaluate policy with Device Posture context
	deviceTrust := "unknown"
	if req.DeviceID != nil && *req.DeviceID != "" {
		device, err := s.endpointStore.GetDevice(ctx, tenantID, *req.DeviceID)
		if err == nil {
			deviceTrust = device.TrustStatus
		}
	}

	input := policy.Input{
		Subject:  policy.Subject{ID: approverID},
		Action:   "approve",
		Resource: policy.Resource{Type: "access_request", ID: requestID},
		Context: map[string]interface{}{
			"requester_id": req.RequesterID,
			"device_id":    req.DeviceID,
			"device_trust": deviceTrust,
		},
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
	case "role":
		// Assign role to user via RBAC service
		if req.Duration != nil && *req.Duration != "" {
			if err := s.rbacSvc.AssignRoleWithExpiration(ctx, tenantID, req.RequesterID, req.ResourceID, &approverID, *req.Duration); err != nil {
				return fmt.Errorf("temporal role assignment failed: %w", err)
			}
		} else {
			if err := s.rbacSvc.AssignRoleToUser(ctx, tenantID, req.RequesterID, req.ResourceID, &approverID); err != nil {
				return fmt.Errorf("role assignment failed: %w", err)
			}
		}
	}

	// Update status to approved
	if err := s.reqStore.UpdateRequestStatus(ctx, requestID, "approved"); err != nil {
		return err
	}

	s.publishEvent(ctx, "AccessRequestApproved", map[string]interface{}{
		"tenant_id":    tenantID,
		"request_id":   requestID,
		"approver_id":  approverID,
		"requester_id": req.RequesterID,
		"resource_id":  req.ResourceID,
		"device_id":    req.DeviceID,
	})

	return nil
}

func (s *governanceService) RejectAccessRequest(ctx context.Context, tenantID, requestID, approverID, comment string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	if err := s.reqStore.UpdateRequestStatus(ctx, requestID, "rejected"); err != nil {
		return err
	}

	s.publishEvent(ctx, "AccessRequestRejected", map[string]interface{}{
		"tenant_id":   tenantID,
		"request_id":  requestID,
		"approver_id": approverID,
	})
	return nil
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
		CIDR:        &req.CIDR,
		CountryCode: &req.CountryCode,
		Reason:      &req.Reason,
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

// Safety Action Implementations

func (s *governanceService) ProposeSafetyAction(ctx context.Context, tenantID string, input ProposeSafetyActionInput) (SafetyAction, error) {
	if err := requireTenant(tenantID); err != nil {
		return SafetyAction{}, err
	}

	action := SafetyAction{
		TenantID:   tenantID,
		ActionType: input.ActionType,
		TargetID:   input.TargetID,
		Metadata:   input.Metadata,
		Reason:     input.Reason,
	}

	id, err := s.reqStore.CreateSafetyAction(ctx, action)
	if err != nil {
		return SafetyAction{}, err
	}

	action, err = s.reqStore.GetSafetyAction(ctx, tenantID, id)
	if err == nil && s.bus != nil {
		// Emit event for subscribers (like Slack)
		payload, _ := json.Marshal(action)
		_ = s.bus.Publish(ctx, "ProposedRevocation", payload)
	}

	return action, err
}

func (s *governanceService) ListSafetyActions(ctx context.Context, tenantID, status string) ([]SafetyAction, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.reqStore.ListSafetyActions(ctx, tenantID, status)
}

func (s *governanceService) ConfirmSafetyAction(ctx context.Context, tenantID, actionID, approverID, comment string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}

	action, err := s.reqStore.GetSafetyAction(ctx, tenantID, actionID)
	if err != nil {
		return err
	}

	if action.Status != "pending" {
		return fmt.Errorf("action is already %s", action.Status)
	}

	// Execution
	switch action.ActionType {
	case "revoke_all_access":
		var metadata struct {
			OrgIDs []string `json:"org_ids"`
		}
		if err := json.Unmarshal(action.Metadata, &metadata); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		for _, orgID := range metadata.OrgIDs {
			_ = s.dirClient.RemoveUserFromOrganization(ctx, tenantID, action.TargetID, orgID)
		}
	default:
		return fmt.Errorf("unsupported action type: %s", action.ActionType)
	}

	return s.reqStore.UpdateSafetyActionStatus(ctx, actionID, "confirmed")
}

func (s *governanceService) RejectSafetyAction(ctx context.Context, tenantID, actionID, approverID, comment string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	return s.reqStore.UpdateSafetyActionStatus(ctx, actionID, "rejected")
}

// Endpoint (Device Trust) Implementations

func (s *governanceService) RegisterDevice(ctx context.Context, tenantID string, d Device) (string, error) {
	if err := requireTenant(tenantID); err != nil {
		return "", err
	}
	d.TenantID = tenantID
	return s.endpointStore.RegisterDevice(ctx, d)
}

func (s *governanceService) ListDevices(ctx context.Context, tenantID string) ([]Device, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.endpointStore.ListDevices(ctx, tenantID)
}

func (s *governanceService) GetDevice(ctx context.Context, tenantID, id string) (Device, error) {
	if err := requireTenant(tenantID); err != nil {
		return Device{}, err
	}
	return s.endpointStore.GetDevice(ctx, tenantID, id)
}

func (s *governanceService) UpdateDeviceStatus(ctx context.Context, tenantID, id, status string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	if err := s.endpointStore.UpdateDeviceStatus(ctx, tenantID, id, status); err != nil {
		return err
	}

	s.publishEvent(ctx, "EndpointTrustUpdated", map[string]interface{}{
		"tenant_id": tenantID,
		"device_id": id,
		"status":    status,
	})
	return nil
}

func (s *governanceService) GetDashboardStats(ctx context.Context, tenantID string) (DashboardStats, error) {
	if err := requireTenant(tenantID); err != nil {
		return DashboardStats{}, err
	}

	stats := DashboardStats{
		RiskProfile: make(map[string]int),
	}

	// 1. Directory Metrics (Users & Groups)
	users, err := s.dirClient.ListUsers(ctx, tenantID)
	if err == nil {
		stats.ActiveUsers = len(users)
	}
	groups, err := s.dirClient.ListGroups(ctx, tenantID)
	if err == nil {
		stats.TotalGroups = len(groups)
	}

	// 2. OAuth Clients & Organizations
	clients, _ := s.clientStore.ListClientsByTenant(ctx, tenantID)
	orgs, _ := s.orgStore.List(ctx, tenantID, 1000, 0)
	stats.ConnectedOrgs = len(orgs)
	if stats.ConnectedOrgs == 0 && len(clients) > 0 {
		stats.ConnectedOrgs = len(clients)
	}

	// 3. Pending Requests
	reqs, err := s.reqStore.ListRequests(ctx, tenantID, "pending")
	if err == nil {
		stats.PendingRequests = len(reqs)
	}

	// 4. Active IP Policies
	policies, err := s.reqStore.ListIPPolicies(ctx, tenantID)
	if err == nil {
		stats.ActiveIPPolicies = len(policies)
	}

	// 5. Workloads
	if s.workloadStore != nil {
		workloads, err := s.workloadStore.List(ctx, tenantID)
		if err == nil {
			stats.ActiveWorkloads = len(workloads)
		}
	}

	// 6. Security Posture (Devices & Hygiene)
	devices, err := s.endpointStore.ListDevices(ctx, tenantID)
	if err == nil {
		trusted := 0
		pending := 0
		untrusted := 0
		for _, d := range devices {
			d.DeriveTrustStatus()
			switch d.TrustStatus {
			case "trusted":
				trusted++
			case "pending":
				pending++
			case "untrusted":
				untrusted++
			}
		}

		// Calculate Hygiene Score (0-100) based on device trust and pending requests
		totalEntities := len(users) + len(devices)
		if totalEntities > 0 {
			defectPoints := (untrusted * 20) + (pending * 5) + (stats.PendingRequests * 2)
			score := 100 - (defectPoints * 100 / (totalEntities * 20))
			if score < 0 {
				score = 0
			}
			stats.HygieneScore = score
		} else {
			stats.HygieneScore = 100
		}

		stats.RiskProfile["low"] = trusted
		stats.RiskProfile["medium"] = pending
		stats.RiskProfile["high"] = untrusted
	} else {
		stats.HygieneScore = 100
		stats.RiskProfile["low"] = len(users)
		stats.RiskProfile["medium"] = stats.PendingRequests
		stats.RiskProfile["high"] = 0
	}

	return stats, nil
}

func (s *governanceService) ListWorkloads(ctx context.Context, tenantID string) ([]auth.Workload, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	if s.workloadStore == nil {
		return nil, errors.New("workload store not configured")
	}
	return s.workloadStore.List(ctx, tenantID)
}

func (s *governanceService) CreateWorkload(ctx context.Context, tenantID string, w auth.Workload) (string, error) {
	if err := requireTenant(tenantID); err != nil {
		return "", err
	}
	if s.workloadStore == nil {
		return "", errors.New("workload store not configured")
	}
	w.TenantID = tenantID

	// AUTOMATION: Generate credentials if not provided by the UI
	if w.ClientID == "" {
		w.ClientID = "workload_" + generateRandomString(12)
	}

	// For a new workload, we always generate a fresh secret if the hash is missing
	if w.ClientSecretHash == "" {
		// In a production scenario, we would return the raw secret to the user ONCE
		// For now, we generate a high-entropy secret and store the hash
		secret := generateRandomString(32)
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return "", fmt.Errorf("failed to generate secret hash: %w", err)
		}
		w.ClientSecretHash = string(hash)
	}

	if w.Status == "" {
		w.Status = "active"
	}

	return s.workloadStore.Create(ctx, w)
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return ""
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func (s *governanceService) ListRelationships(ctx context.Context, tenantID string, query authz.Query) ([]authz.RelationTuple, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	if s.engine == nil {
		return nil, errors.New("authz engine not configured")
	}

	return s.engine.ListTuples(ctx, tenantID, query)
}

func (s *governanceService) TraverseGraph(ctx context.Context, tenantID, subjectID string) ([]authz.RelationTuple, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	if s.engine == nil {
		return nil, errors.New("authz engine not configured")
	}

	return s.engine.Traverse(ctx, tenantID, subjectID)
}

func (s *governanceService) publishEvent(ctx context.Context, topic string, data map[string]interface{}) {
	if s.bus == nil {
		return
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return
	}
	_ = s.bus.Publish(ctx, topic, payload)
}
func (s *governanceService) GatherAuditContext(ctx context.Context, tenantID string) (string, error) {
	var sb strings.Builder

	// 1. Dashboard Stats
	stats, err := s.GetDashboardStats(ctx, tenantID)
	if err == nil {
		sb.WriteString("DASHBOARD STATS:\n")
		sb.WriteString(fmt.Sprintf("- Active Users: %d\n", stats.ActiveUsers))
		sb.WriteString(fmt.Sprintf("- Pending Requests: %d\n", stats.PendingRequests))
		sb.WriteString(fmt.Sprintf("- Active Workloads: %d\n", stats.ActiveWorkloads))
		sb.WriteString(fmt.Sprintf("- Hygiene Score: %d/100\n", stats.HygieneScore))
		sb.WriteString("\n")
	}

	// 2. Pending Requests (Extended Context)
	requests, err := s.ListAccessRequests(ctx, tenantID, "pending")
	if err == nil && len(requests) > 0 {
		sb.WriteString("RECENT PENDING ACCESS REQUESTS:\n")
		for i, r := range requests {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("- [%s] %s (%s) requested access to %s (%s) for reason: %s\n",
				r.ID, r.RequesterID, r.RequesterType, r.ResourceID, r.ResourceType, r.Reason))
		}
		sb.WriteString("\n")
	}

	// 3. Identity Graph Relationships
	relationships, err := s.ListRelationships(ctx, tenantID, authz.Query{})
	if err == nil && len(relationships) > 0 {
		sb.WriteString("IDENTITY RELATIONSHIP GRAPH (SAMPLE):\n")
		for i, r := range relationships {
			if i >= 20 {
				break
			}
			sb.WriteString(fmt.Sprintf("- %s:%s --(%s)--> %s:%s\n",
				r.SubjectType, r.SubjectID, r.Relation, r.Namespace, r.ObjectID))
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

func (s *governanceService) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	return s.dirClient.ListUsers(ctx, tenantID)
}

func (s *governanceService) ListGroups(ctx context.Context, tenantID string) ([]Group, error) {
	return s.dirClient.ListGroups(ctx, tenantID)
}

func (s *governanceService) EvaluatePolicy(ctx context.Context, input policy.Input) (bool, string, error) {
	return s.policyEngine.Evaluate(ctx, input)
}
