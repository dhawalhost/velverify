package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/dhawalhost/velverify/internal/oauthclients"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
)

func TestPKCEFlowWithClientStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := newStubClientStore()
	store.addClient(oauthclients.Client{
		TenantID:      "tenant-1",
		ClientID:      "db-client",
		ClientType:    "public",
		Name:          "DB Client",
		Description:   sql.NullString{Valid: false},
		RedirectURIs:  pq.StringArray{"https://app-db.example.com/callback"},
		AllowedScopes: pq.StringArray{"openid", "profile"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})

	svc := newServiceWithStore(t, store)
	ctx := contextWithTenant(t, "tenant-1")

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO1234567890abcd"
	challenge := pkceChallenge(verifier)

	authResp, err := svc.Authorize(ctx, AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "db-client",
		RedirectURI:         "https://app-db.example.com/callback",
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
		RedirectURI:  "https://app-db.example.com/callback",
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
	store.addClient(oauthclients.Client{
		TenantID:      "tenant-1",
		ClientID:      "db-client",
		ClientType:    "public",
		Name:          "DB Client",
		Description:   sql.NullString{Valid: false},
		RedirectURIs:  pq.StringArray{"https://app-db.example.com/callback"},
		AllowedScopes: pq.StringArray{"openid"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})

	svc := newServiceWithStore(t, store)
	ctx := contextWithTenant(t, "tenant-2")

	_, err := svc.Authorize(ctx, AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "db-client",
		RedirectURI:         "https://app-db.example.com/callback",
		Scope:               "openid",
		CodeChallenge:       pkceChallenge("verifier"),
		CodeChallengeMethod: "S256",
	})
	if err != ErrInvalidClient {
		t.Fatalf("expected ErrInvalidClient for cross-tenant access, got %v", err)
	}
}

func TestAuthorizeRejectsUnknownClientFromStore(t *testing.T) {
	svc := newServiceWithStore(t, newStubClientStore())
	ctx := contextWithTenant(t, "tenant-1")

	_, err := svc.Authorize(ctx, AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "no-client",
		RedirectURI:         "https://app-db.example.com/callback",
		Scope:               "openid",
		CodeChallenge:       pkceChallenge("verifier"),
		CodeChallengeMethod: "S256",
	})
	if err != ErrInvalidClient {
		t.Fatalf("expected ErrInvalidClient when store is missing client, got %v", err)
	}
}

func newServiceWithStore(t *testing.T, store oauthclients.Store) Service {
	t.Helper()
	svc, err := NewService(Config{
		DirectoryServiceURL: "http://dirsvc",
		ClientStore:         store,
	})
	if err != nil {
		t.Fatalf("failed to create auth service with store: %v", err)
	}
	return svc
}

type stubClientStore struct {
	clients map[string]oauthclients.Client
}

func newStubClientStore() *stubClientStore {
	return &stubClientStore{clients: make(map[string]oauthclients.Client)}
}

func (s *stubClientStore) key(tenantID, clientID string) string {
	return tenantID + "::" + clientID
}

func (s *stubClientStore) addClient(client oauthclients.Client) {
	s.clients[s.key(client.TenantID, client.ClientID)] = client
}

func (s *stubClientStore) ListClients(ctx context.Context) ([]oauthclients.Client, error) {
	out := make([]oauthclients.Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	return out, nil
}

func (s *stubClientStore) ListClientsByTenant(ctx context.Context, tenantID string) ([]oauthclients.Client, error) {
	var out []oauthclients.Client
	for _, c := range s.clients {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *stubClientStore) GetClient(ctx context.Context, tenantID, clientID string) (oauthclients.Client, error) {
	if client, ok := s.clients[s.key(tenantID, clientID)]; ok {
		return client, nil
	}
	return oauthclients.Client{}, oauthclients.ErrNotFound
}

func (s *stubClientStore) CreateClient(ctx context.Context, params oauthclients.CreateClientParams) (oauthclients.Client, error) {
	client := oauthclients.Client{
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

func (s *stubClientStore) UpdateClient(ctx context.Context, tenantID, clientID string, params oauthclients.UpdateClientParams) (oauthclients.Client, error) {
	client, ok := s.clients[s.key(tenantID, clientID)]
	if !ok {
		return oauthclients.Client{}, oauthclients.ErrNotFound
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
		return oauthclients.ErrNotFound
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
