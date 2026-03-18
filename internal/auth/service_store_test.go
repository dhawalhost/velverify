package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/saml"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
)

func TestPKCEFlowWithClientStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := newStubClientStore()
	store.addClient(oauthclient.Client{
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ClientID:      "db-client",
		ClientType:    "public",
		Name:          "DB Client",
		Description:   sql.NullString{Valid: false},
		RedirectURIs:  pq.StringArray{"https://app-db.wardseal.com/callback"},
		AllowedScopes: pq.StringArray{"openid", "profile"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})

	svc := newServiceWithStore(t, store)
	ctx := contextWithTenant(t, "11111111-1111-1111-1111-111111111111")

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO1234567890abcd"
	challenge := pkceChallenge(verifier)

	authResp, err := svc.Authorize(ctx, "", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "db-client",
		RedirectURI:         "https://app-db.wardseal.com/callback",
		Scope:               "openid profile",
		State:               "state123",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("authorize error: %v", err)
	}

	code := extractCode(t, authResp.RedirectURI)
	tokenResp, err := svc.Token(ctx, TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  "https://app-db.wardseal.com/callback",
		ClientID:     "db-client",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("token error: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Fatalf("expected access token from db-backed client")
	}
}

func TestAuthorizeRejectsCrossTenantClientFromStore(t *testing.T) {
	store := newStubClientStore()
	store.addClient(oauthclient.Client{
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ClientID:      "db-client",
		ClientType:    "public",
		Name:          "DB Client",
		Description:   sql.NullString{Valid: false},
		RedirectURIs:  pq.StringArray{"https://app-db.wardseal.com/callback"},
		AllowedScopes: pq.StringArray{"openid"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})

	svc := newServiceWithStore(t, store)
	ctx := contextWithTenant(t, "22222222-2222-2222-2222-222222222222")

	_, err := svc.Authorize(ctx, "", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "db-client",
		RedirectURI:         "https://app-db.wardseal.com/callback",
		Scope:               "openid",
		CodeChallenge:       pkceChallenge("verifier"),
		CodeChallengeMethod: "S256",
	})
	if !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("expected ErrInvalidClient for cross-tenant access, got %v", err)
	}
}

func TestAuthorizeRejectsUnknownClientFromStore(t *testing.T) {
	svc := newServiceWithStore(t, newStubClientStore())
	ctx := contextWithTenant(t, "11111111-1111-1111-1111-111111111111")

	_, err := svc.Authorize(ctx, "", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "no-client",
		RedirectURI:         "https://app-db.wardseal.com/callback",
		Scope:               "openid",
		CodeChallenge:       pkceChallenge("verifier"),
		CodeChallengeMethod: "S256",
	})
	if !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("expected ErrInvalidClient when store is missing client, got %v", err)
	}
}

func newServiceWithStore(t *testing.T, store oauthclient.Repository) Service {
	t.Helper()
	svc, err := NewService(Config{
		BaseURL:             "http://wardseal.com",
		DirectoryServiceURL: "http://dir-service",
		ClientStore:         store,
		SAMLStore:           saml.NewStore(nil),
	})
	if err != nil {
		t.Fatalf("failed to create auth service with store: %v", err)
	}
	return svc
}

type stubClientStore struct {
	clients map[string]oauthclient.Client
}

func newStubClientStore() *stubClientStore {
	return &stubClientStore{clients: make(map[string]oauthclient.Client)}
}

func (s *stubClientStore) key(tenantID, clientID string) string {
	return tenantID + "::" + clientID
}

func (s *stubClientStore) addClient(client oauthclient.Client) {
	s.clients[s.key(client.TenantID, client.ClientID)] = client
}

func (s *stubClientStore) ListClients(ctx context.Context) ([]oauthclient.Client, error) {
	out := make([]oauthclient.Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	return out, nil
}

func (s *stubClientStore) ListClientsByTenant(ctx context.Context, tenantID string) ([]oauthclient.Client, error) {
	var out []oauthclient.Client
	for _, c := range s.clients {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *stubClientStore) GetClient(ctx context.Context, tenantID, clientID string) (oauthclient.Client, error) {
	if client, ok := s.clients[s.key(tenantID, clientID)]; ok {
		return client, nil
	}
	return oauthclient.Client{}, oauthclient.ErrNotFound
}

func (s *stubClientStore) CreateClient(ctx context.Context, params oauthclient.CreateClientParams) (oauthclient.Client, error) {
	client := oauthclient.Client{
		TenantID:      params.TenantID,
		ClientID:      params.ClientID,
		ClientType:    params.ClientType,
		Name:          params.Name,
		Description:   nullableDescription(params.Description),
		RedirectURIs:  pq.StringArray(params.RedirectURIs),
		AllowedScopes: pq.StringArray(params.AllowedScopes),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	s.addClient(client)
	return client, nil
}

func (s *stubClientStore) UpdateClient(ctx context.Context, tenantID, clientID string, params oauthclient.UpdateClientParams) (oauthclient.Client, error) {
	client, ok := s.clients[s.key(tenantID, clientID)]
	if !ok {
		return oauthclient.Client{}, oauthclient.ErrNotFound
	}
	if params.Name != nil {
		client.Name = *params.Name
	}
	if params.Description != nil {
		client.Description = nullableDescription(params.Description)
	}
	if params.RedirectURIs != nil {
		client.RedirectURIs = pq.StringArray(params.RedirectURIs)
	}
	if params.AllowedScopes != nil {
		client.AllowedScopes = pq.StringArray(params.AllowedScopes)
	}
	if params.ClientType != nil {
		client.ClientType = *params.ClientType
	}
	s.clients[s.key(tenantID, clientID)] = client
	return client, nil
}

func (s *stubClientStore) DeleteClient(ctx context.Context, tenantID, clientID string) error {
	if _, ok := s.clients[s.key(tenantID, clientID)]; !ok {
		return oauthclient.ErrNotFound
	}
	delete(s.clients, s.key(tenantID, clientID))
	return nil
}

func nullableDescription(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	if *value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}
