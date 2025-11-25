package governance

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/dhawalhost/velverify/internal/oauthclients"
	"golang.org/x/crypto/bcrypt"
)

// Service defines the interface for the governance service.
type Service interface {
	HealthCheck(ctx context.Context) (bool, error)
	ListOAuthClients(ctx context.Context, tenantID string) ([]oauthclients.Client, error)
	GetOAuthClient(ctx context.Context, tenantID, clientID string) (oauthclients.Client, error)
	CreateOAuthClient(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclients.Client, error)
	UpdateOAuthClient(ctx context.Context, tenantID, clientID string, input UpdateOAuthClientInput) (oauthclients.Client, error)
	DeleteOAuthClient(ctx context.Context, tenantID, clientID string) error
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
	store oauthclients.Store
}

// NewService creates a new governance service.
func NewService(store oauthclients.Store) Service {
	return &governanceService{store: store}
}

func (s *governanceService) HealthCheck(ctx context.Context) (bool, error) {
	return true, nil
}

func (s *governanceService) ListOAuthClients(ctx context.Context, tenantID string) ([]oauthclients.Client, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	return s.store.ListClientsByTenant(ctx, tenantID)
}

func (s *governanceService) GetOAuthClient(ctx context.Context, tenantID, clientID string) (oauthclients.Client, error) {
	if err := requireTenant(tenantID); err != nil {
		return oauthclients.Client{}, err
	}
	if clientID == "" {
		return oauthclients.Client{}, validationError("client_id is required")
	}
	return s.store.GetClient(ctx, tenantID, clientID)
}

func (s *governanceService) CreateOAuthClient(ctx context.Context, tenantID string, input CreateOAuthClientInput) (oauthclients.Client, error) {
	if err := requireTenant(tenantID); err != nil {
		return oauthclients.Client{}, err
	}
	if err := validateCreateInput(input); err != nil {
		return oauthclients.Client{}, err
	}
	hash, err := maybeHashSecret(input.ClientType, input.ClientSecret)
	if err != nil {
		return oauthclients.Client{}, err
	}
	params := oauthclients.CreateClientParams{
		TenantID:         tenantID,
		ClientID:         input.ClientID,
		ClientType:       normalizedClientType(input.ClientType),
		Name:             input.Name,
		Description:      nullableString(input.Description),
		RedirectURIs:     append([]string(nil), input.RedirectURIs...),
		AllowedScopes:    append([]string(nil), input.AllowedScopes...),
		ClientSecretHash: hash,
	}
	return s.store.CreateClient(ctx, params)
}

func (s *governanceService) UpdateOAuthClient(ctx context.Context, tenantID, clientID string, input UpdateOAuthClientInput) (oauthclients.Client, error) {
	if err := requireTenant(tenantID); err != nil {
		return oauthclients.Client{}, err
	}
	if clientID == "" {
		return oauthclients.Client{}, validationError("client_id is required")
	}
	if err := validateUpdateInput(input); err != nil {
		return oauthclients.Client{}, err
	}
	var secretHash *[]byte
	if input.ClientSecret != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(*input.ClientSecret), bcrypt.DefaultCost)
		if err != nil {
			return oauthclients.Client{}, err
		}
		secretHash = &hash
	}
	params := oauthclients.UpdateClientParams{
		Name:             input.Name,
		Description:      input.Description,
		RedirectURIs:     cloneSlice(input.RedirectURIs),
		AllowedScopes:    cloneSlice(input.AllowedScopes),
		ClientType:       normalizeClientTypePtr(input.ClientType),
		ClientSecretHash: secretHash,
	}
	return s.store.UpdateClient(ctx, tenantID, clientID, params)
}

func (s *governanceService) DeleteOAuthClient(ctx context.Context, tenantID, clientID string) error {
	if err := requireTenant(tenantID); err != nil {
		return err
	}
	if clientID == "" {
		return validationError("client_id is required")
	}
	return s.store.DeleteClient(ctx, tenantID, clientID)
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
