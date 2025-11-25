package governance

import (
	"context"
	"testing"

	"github.com/dhawalhost/velverify/internal/oauthclients"
)

var ctx = context.Background()

func TestCreateOAuthClientValidatesRedirects(t *testing.T) {
	svc := NewService(&fakeStore{})
	_, err := svc.CreateOAuthClient(ctx, "tenant-1", CreateOAuthClientInput{
		ClientID:      "client-a",
		Name:          "Client A",
		RedirectURIs:  nil,
		AllowedScopes: []string{"openid"},
	})
	if err == nil || !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestCreateOAuthClientHashesSecret(t *testing.T) {
	store := &fakeStore{}
	svc := NewService(store)
	secret := "super-secret"
	client, err := svc.CreateOAuthClient(ctx, "tenant-1", CreateOAuthClientInput{
		ClientID:      "client-b",
		Name:          "Client B",
		ClientType:    "confidential",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedScopes: []string{"openid"},
		ClientSecret:  secret,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(store.lastCreateParams.ClientSecretHash) == 0 {
		t.Fatalf("expected secret hash to be stored")
	}
	if client.ClientType != "confidential" {
		t.Fatalf("expected confidential client type")
	}
}

func TestUpdateOAuthClientValidatesRedirects(t *testing.T) {
	store := &fakeStore{}
	svc := NewService(store)
	_, err := svc.UpdateOAuthClient(ctx, "tenant-1", "client-x", UpdateOAuthClientInput{
		RedirectURIs: []string{"http://localhost:bad"},
	})
	if err == nil || !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

type fakeStore struct {
	clients          map[string]oauthclients.Client
	lastCreateParams oauthclients.CreateClientParams
}

func (f *fakeStore) ensureClients() {
	if f.clients == nil {
		f.clients = map[string]oauthclients.Client{}
	}
}

func (f *fakeStore) ListClients(ctx context.Context) ([]oauthclients.Client, error) {
	f.ensureClients()
	out := make([]oauthclients.Client, 0, len(f.clients))
	for _, c := range f.clients {
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeStore) ListClientsByTenant(ctx context.Context, tenantID string) ([]oauthclients.Client, error) {
	f.ensureClients()
	var out []oauthclients.Client
	for _, c := range f.clients {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeStore) GetClient(ctx context.Context, tenantID, clientID string) (oauthclients.Client, error) {
	f.ensureClients()
	c, ok := f.clients[tenantID+clientID]
	if !ok {
		return oauthclients.Client{}, oauthclients.ErrNotFound
	}
	return c, nil
}

func (f *fakeStore) CreateClient(ctx context.Context, params oauthclients.CreateClientParams) (oauthclients.Client, error) {
	f.ensureClients()
	f.lastCreateParams = params
	client := oauthclients.Client{
		TenantID:      params.TenantID,
		ClientID:      params.ClientID,
		ClientType:    params.ClientType,
		Name:          params.Name,
		RedirectURIs:  params.RedirectURIs,
		AllowedScopes: params.AllowedScopes,
	}
	f.clients[params.TenantID+params.ClientID] = client
	return client, nil
}

func (f *fakeStore) UpdateClient(ctx context.Context, tenantID, clientID string, params oauthclients.UpdateClientParams) (oauthclients.Client, error) {
	f.ensureClients()
	client := oauthclients.Client{TenantID: tenantID, ClientID: clientID}
	f.clients[tenantID+clientID] = client
	return client, nil
}

func (f *fakeStore) DeleteClient(ctx context.Context, tenantID, clientID string) error {
	f.ensureClients()
	delete(f.clients, tenantID+clientID)
	return nil
}
