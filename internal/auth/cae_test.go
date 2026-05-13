package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type mockAsymmetricSigner struct {
	privKey *rsa.PrivateKey
}

func (s *mockAsymmetricSigner) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privKey)
}
func (s *mockAsymmetricSigner) KeyID() string                   { return "test-key" }
func (s *mockAsymmetricSigner) PublicJWK() (interface{}, error) { return nil, nil }
func (s *mockAsymmetricSigner) PublicKey() *rsa.PublicKey       { return &s.privKey.PublicKey }
func (s *mockAsymmetricSigner) Algorithm() string               { return "RS256" }
func (s *mockAsymmetricSigner) Close() error                    { return nil }

// Mock Signal Store for CAE tests
type mockSignalStore struct {
	events map[string][]SecurityEvent
}

func (m *mockSignalStore) Ingest(ctx context.Context, event *SecurityEvent) error {
	if m.events == nil {
		m.events = make(map[string][]SecurityEvent)
	}
	m.events[event.SubjectID] = append(m.events[event.SubjectID], *event)
	return nil
}
func (m *mockSignalStore) IngestLogin(ctx context.Context, signal *LoginSignal) error { return nil }
func (m *mockSignalStore) GetLatestCriticalEvent(ctx context.Context, subjectID string, since time.Time) (*SecurityEvent, error) {
	if m.events == nil {
		return nil, nil
	}
	events, ok := m.events[subjectID]
	if !ok {
		return nil, nil
	}
	var latest *SecurityEvent
	for _, e := range events {
		if e.EventTime.After(since) {
			if latest == nil || e.EventTime.After(latest.EventTime) {
				eCopy := e
				latest = &eCopy
			}
		}
	}
	if latest == nil {
		return nil, nil
	}
	return latest, nil
}
func (m *mockSignalStore) GetLatestSuccess(ctx context.Context, subjectID string) (*LoginSignal, error) {
	return nil, nil
}
func (m *mockSignalStore) UpdateUserRisk(ctx context.Context, risk UserRisk) error { return nil }
func (m *mockSignalStore) GetHighRiskUsers(ctx context.Context, tenantID string, threshold int) ([]UserRisk, error) {
	return nil, nil
}

func TestCAE_ValidateToken_Revocation(t *testing.T) {
	signalStore := &mockSignalStore{}
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := &mockAsymmetricSigner{privKey: privKey}

	svc := &authService{
		signalStore: signalStore,
		signer:      signer,
	}

	tenantID := uuid.New().String()
	userID := uuid.New().String()

	// 1. Generate Token
	tokenString, err := svc.generateAccessToken(context.Background(), tenantID, "test-client", "openid profile", userID)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// 2. Validate Token (should succeed)
	claims, err := svc.ValidateToken(tokenString)
	if err != nil {
		t.Fatalf("expected token to be valid, got error: %v", err)
	}
	if claims.Subject != userID {
		t.Errorf("expected subject %s, got %s", userID, claims.Subject)
	}

	// 3. Ingest Critical Security Event AFTER token issuance
	time.Sleep(1 * time.Second) // Ensure event time is after iat
	event := &SecurityEvent{
		SubjectID: userID,
		TenantID:  tenantID,
		EventType: "impossible-travel",
		EventTime: time.Now(),
		Reason:    "User detected in multiple locations",
	}
	_ = signalStore.Ingest(context.Background(), event)

	// 4. Validate Token again (should fail due to CAE)
	_, err = svc.ValidateToken(tokenString)
	if err == nil {
		t.Fatalf("expected token validation to fail after critical event, but it succeeded")
	}
	if err.Error() != "token revoked due to critical security event: User detected in multiple locations" {
		t.Errorf("unexpected error message: %v", err)
	}
}
