package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"time"

	saml2 "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"github.com/jmoiron/sqlx"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// Store implements samlidp.Store interface.
type Store struct {
	db                  *sqlx.DB
	directoryURL        string
	serviceAuthToken    string
	serviceAuthHeader   string
	httpClient          *http.Client
	samlidp.MemoryStore // Still using for sessions temporarily, pending Phase 3.2
}

// NewStore creates a new SAML Store with directory integration.
func NewStore(db *sqlx.DB, directoryURL, authToken, authHeader string) *Store {
	return &Store{
		db:                db,
		directoryURL:      directoryURL,
		serviceAuthToken:  authToken,
		serviceAuthHeader: authHeader,
		httpClient:        &http.Client{Timeout: 5 * time.Second},
		MemoryStore:       samlidp.MemoryStore{},
	}
}

// ServiceProvider represents a configured SP (Database Model).
type ServiceProvider struct {
	EntityID          string    `db:"entity_id"`
	TenantID          string    `db:"tenant_id"`
	MetadataURL       string    `db:"metadata_url"`
	ACSURL            string    `db:"acs_url"`
	Certificate       string    `db:"certificate"`
	CreatedAt         time.Time `db:"created_at"`
	UpdatedAt         time.Time `db:"updated_at"`
	EncryptAssertions bool      `db:"encrypt_assertions"`
	SignAssertions    bool      `db:"sign_assertions"`
	EncryptionKey     *rsa.PrivateKey
}

// GetServiceProvider retrieves a service provider by EntityID with tenant isolation.
func (s *Store) GetServiceProvider(ctx context.Context, entityID string) (*saml2.ServiceProvider, error) {
	tenantID, err := middleware.TenantIDFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant identification failed: %w", err)
	}

	var sp ServiceProvider
	err = s.db.GetContext(ctx, &sp, "SELECT * FROM saml_providers WHERE entity_id = $1 AND tenant_id = $2", entityID, tenantID)
	if err != nil {
		return nil, err
	}

	cert, err := parseCert(sp.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	acsURL := parseURL(sp.ACSURL)
	metadataURL := parseURL(sp.MetadataURL)

	return &saml2.ServiceProvider{
		EntityID:    sp.EntityID,
		MetadataURL: metadataURL,
		AcsURL:      acsURL,
		Certificate: cert,
		// EncryptionKey: sp.EncryptionKey,
		// Metadata field removed as it seems it's not present in this version or optional
	}, nil
}

// GetUser retrieves a user from the central directory service.
func (s *Store) GetUser(ctx context.Context, email string) (*samlidp.User, error) {
	tenantID, err := middleware.TenantIDFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant identification failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/users", s.directoryURL), nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("email", email)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, tenantID)
	if s.serviceAuthToken != "" {
		req.Header.Set(s.serviceAuthHeader, s.serviceAuthToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call directory service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, samlidp.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory service returned status %d", resp.StatusCode)
	}

	var userResp struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, fmt.Errorf("failed to decode directory response: %w", err)
	}

	// Map WardSeal user to samlidp.User
	return &samlidp.User{
		Name:  userResp.User.Email, // We use email as the name/id for SAML
		Email: userResp.User.Email,
	}, nil
}

// Helper functions
func parseCert(pemStr string) (*x509.Certificate, error) {
	if pemStr == "" {
		return nil, nil
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseURL(u string) url.URL {
	parser, _ := url.Parse(u)
	if parser == nil {
		return url.URL{}
	}
	return *parser
}
