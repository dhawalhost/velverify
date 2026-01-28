package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dhawalhost/wardseal/internal/auth"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/saml"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gopkg.in/go-jose/go-jose.v2"
)

// MockService matches auth.Service interface
type MockService struct {
	mock.Mock
}

func (m *MockService) Login(ctx context.Context, username, password, deviceID, userAgent, ip, clientOSVersion string) (string, error) {
	args := m.Called(ctx, username, password, deviceID, userAgent, ip, clientOSVersion)
	return args.String(0), args.Error(1)
}

func (m *MockService) GetSystemSetupStatus(ctx context.Context) (bool, error) {
	args := m.Called(ctx)
	return args.Bool(0), args.Error(1)
}

func (m *MockService) PerformSystemSetup(ctx context.Context, email, password string) (string, error) {
	args := m.Called(ctx, email, password)
	return args.String(0), args.Error(1)
}

// ... other interface methods mocked as needed (stubbed for now to satisfy interface)
func (m *MockService) Authorize(ctx context.Context, req auth.AuthorizeRequest) (auth.AuthorizeResponse, error) {
	return auth.AuthorizeResponse{}, nil
}
func (m *MockService) Token(ctx context.Context, req auth.TokenRequest) (auth.TokenResponse, error) {
	return auth.TokenResponse{}, nil
}
func (m *MockService) Introspect(ctx context.Context, req auth.IntrospectRequest) (auth.IntrospectResponse, error) {
	return auth.IntrospectResponse{}, nil
}
func (m *MockService) Revoke(ctx context.Context, req auth.RevokeRequest) error { return nil }
func (m *MockService) SAML() *saml.Provider                                     { return nil }
func (m *MockService) JWKS() jose.JSONWebKeySet                                 { return jose.JSONWebKeySet{} }
func (m *MockService) Device() auth.DeviceStore                                 { return nil }
func (m *MockService) Signal() auth.SignalStore                                 { return nil }
func (m *MockService) WebAuthn() *webauthn.WebAuthn                             { return nil }
func (m *MockService) BeginWebAuthnRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return nil, nil, nil
}
func (m *MockService) FinishWebAuthnRegistration(ctx context.Context, userID string, session webauthn.SessionData, req *http.Request) error {
	return nil
}
func (m *MockService) BeginWebAuthnLogin(ctx context.Context, userID string) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return nil, nil, nil
}
func (m *MockService) FinishWebAuthnLogin(ctx context.Context, userID string, session webauthn.SessionData, req *http.Request) (string, error) {
	return "", nil
}
func (m *MockService) SocialLogin(ctx context.Context, req auth.SocialLoginRequest) (auth.TokenResponse, error) {
	return auth.TokenResponse{}, nil
}
func (m *MockService) GetBranding(ctx context.Context, tenantID string) (auth.BrandingConfig, error) {
	return auth.BrandingConfig{}, nil
}
func (m *MockService) UpdateBranding(ctx context.Context, config auth.BrandingConfig) error {
	return nil
}
func (m *MockService) TOTP() auth.TOTPStore { return nil }
func (m *MockService) LookupUser(ctx context.Context, tenantID, email string) (auth.LookupResult, error) {
	return auth.LookupResult{}, nil
}
func (m *MockService) SignUp(ctx context.Context, email, password, companyName, plan string) (string, string, error) {
	return "", "", nil
}
func (m *MockService) ListClients(ctx context.Context, tenantID string) ([]oauthclient.Client, error) {
	return nil, nil
}
func (m *MockService) UpdateUserSelf(ctx context.Context, tenantID, userID string, updates map[string]interface{}) error {
	return nil
}

// Simple test to verify the HTTP wiring for Setup and Login
func TestSystemSetupAndLoginFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := new(MockService)
	// LoginAttemptStore can be nil for this test
	h := auth.NewHTTPHandler(mockSvc, nil, nil)

	router := gin.New()
	h.RegisterRoutes(router)

	t.Run("Check Setup Status", func(t *testing.T) {
		mockSvc.On("GetSystemSetupStatus", mock.Anything).Return(true, nil).Once()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1/setup/status", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"setup_required":true`)
	})

	t.Run("Perform Setup", func(t *testing.T) {
		mockSvc.On("PerformSystemSetup", mock.Anything, "admin@example.com", "password123").Return("mock_token_123", nil).Once()

		body := map[string]string{
			"email":    "admin@example.com",
			"password": "password123",
		}
		jsonBody, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/setup", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "System owner created successfully")
		assert.Contains(t, w.Header().Get("Set-Cookie"), "wardseal_access_token=mock_token_123")
	})

	t.Run("Login", func(t *testing.T) {
		mockSvc.On("Login", mock.Anything, "admin@example.com", "password123", "", "", "", "").Return("mock_login_token", nil).Once()

		body := map[string]string{
			"username": "admin@example.com",
			"password": "password123",
		}
		jsonBody, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", bytes.NewReader(jsonBody))
		// Mock Tenant ID as if we are on the login page (setup usually assumes system tenant or no tenant initially/discovery)
		// UI might send a header.
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "mock_login_token")
	})
}
