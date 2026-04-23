package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

const testServiceToken = "test-token"

func newHandler(svc Service) *HTTPHandler {
	return NewHTTPHandler(svc, zap.NewNop(), HTTPHandlerConfig{ServiceAuthToken: testServiceToken})
}

func TestCreateUserUsesTenantHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &mockDirectoryService{createUserID: "user-123"}
	handler := newHandler(svc)
	r := gin.New()
	handler.RegisterRoutes(r)

	body := strings.NewReader(`{"user":{"email":"user@wardseal.com","password":"password123","status":"active"}}`)
	req := httptest.NewRequest(http.MethodPost, "/users", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, "22222222-2222-2222-2222-222222222222")
	resp := httptest.NewRecorder()

	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.Code)
	}

	if svc.lastTenantID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("expected tenant tenant-xyz, got %s", svc.lastTenantID)
	}
}

func TestCreateUserMissingTenantHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &mockDirectoryService{createUserID: "user-123"}
	handler := newHandler(svc)
	r := gin.New()
	handler.RegisterRoutes(r)

	body := strings.NewReader(`{"user":{"email":"user@wardseal.com","password":"password123","status":"active"}}`)
	req := httptest.NewRequest(http.MethodPost, "/users", body)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.Code)
	}

	if svc.createUserCalled {
		t.Fatalf("service should not be called when tenant header missing")
	}
}

func TestVerifyCredentialsUsesTenantHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	user := User{ID: "user-123", Email: "user@wardseal.com", Status: "active"}
	svc := &mockDirectoryService{verifyReturnUser: user}
	handler := newHandler(svc)
	r := gin.New()
	handler.RegisterRoutes(r)

	body := strings.NewReader(`{"email":"user@wardseal.com","password":"password123"}`)
	req := httptest.NewRequest(http.MethodPost, "/internal/credentials/verify", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, "22222222-2222-2222-2222-222222222222")
	req.Header.Set(middleware.DefaultServiceAuthHeader, testServiceToken)
	resp := httptest.NewRecorder()

	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	if !svc.verifyCredentialsCalled {
		t.Fatalf("expected verify credentials to be called")
	}

	if svc.verifyTenantID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("expected tenant tenant-xyz, got %s", svc.verifyTenantID)
	}

	var payload VerifyCredentialsResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.User.ID != user.ID {
		t.Fatalf("expected user id %s, got %s", user.ID, payload.User.ID)
	}
}

func TestVerifyCredentialsMissingTenantHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &mockDirectoryService{}
	handler := newHandler(svc)
	r := gin.New()
	handler.RegisterRoutes(r)

	body := strings.NewReader(`{"email":"user@wardseal.com","password":"password123"}`)
	req := httptest.NewRequest(http.MethodPost, "/internal/credentials/verify", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultServiceAuthHeader, testServiceToken)
	resp := httptest.NewRecorder()

	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.Code)
	}

	if svc.verifyCredentialsCalled {
		t.Fatalf("service should not be called when tenant header missing")
	}
}

func TestVerifyCredentialsUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &mockDirectoryService{verifyErr: ErrInvalidCredentials}
	handler := newHandler(svc)
	r := gin.New()
	handler.RegisterRoutes(r)

	body := strings.NewReader(`{"email":"user@wardseal.com","password":"badpassword"}`)
	req := httptest.NewRequest(http.MethodPost, "/internal/credentials/verify", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, "22222222-2222-2222-2222-222222222222")
	req.Header.Set(middleware.DefaultServiceAuthHeader, testServiceToken)
	resp := httptest.NewRecorder()

	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
}

func TestVerifyCredentialsMissingServiceToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &mockDirectoryService{}
	handler := newHandler(svc)
	r := gin.New()
	handler.RegisterRoutes(r)

	body := strings.NewReader(`{"email":"user@wardseal.com","password":"password123"}`)
	req := httptest.NewRequest(http.MethodPost, "/internal/credentials/verify", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, "22222222-2222-2222-2222-222222222222")
	resp := httptest.NewRecorder()

	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
}

type mockDirectoryService struct {
	createUserID            string
	createUserErr           error
	createUserCalled        bool
	lastTenantID            string
	lastUser                User
	verifyErr               error
	verifyReturnUser        User
	verifyTenantID          string
	verifyCredentialsCalled bool
}

func (m *mockDirectoryService) HealthCheck(context.Context) (bool, error) {
	return true, nil
}

func (m *mockDirectoryService) CreateUser(ctx context.Context, tenantID string, user User) (string, error) {
	m.createUserCalled = true
	m.lastTenantID = tenantID
	m.lastUser = user
	return m.createUserID, m.createUserErr
}

func (m *mockDirectoryService) GetUserByID(context.Context, string, string) (User, error) {
	return User{}, nil
}

func (m *mockDirectoryService) GetUserByEmail(context.Context, string, string) (User, error) {
	return User{}, nil
}

func (m *mockDirectoryService) ListUsers(context.Context, string, int, int) ([]User, int, error) {
	return []User{}, 0, nil
}

func (m *mockDirectoryService) UpdateUser(context.Context, string, string, User) error {
	return nil
}

func (m *mockDirectoryService) DeleteUser(context.Context, string, string) error {
	return nil
}

func (m *mockDirectoryService) CreateGroup(context.Context, string, Group) (string, error) {
	return "group-123", nil
}

func (m *mockDirectoryService) GetGroupByID(context.Context, string, string) (Group, error) {
	return Group{}, nil
}

func (m *mockDirectoryService) ListGroups(context.Context, string, int, int) ([]Group, int, error) {
	return []Group{}, 0, nil
}

func (m *mockDirectoryService) UpdateGroup(context.Context, string, string, Group) error {
	return nil
}

func (m *mockDirectoryService) DeleteGroup(context.Context, string, string) error {
	return nil
}

func (m *mockDirectoryService) AddUserToGroup(context.Context, string, string, string) error {
	return nil
}

func (m *mockDirectoryService) RemoveUserFromGroup(context.Context, string, string, string) error {
	return nil
}

func (m *mockDirectoryService) VerifyCredentials(ctx context.Context, tenantID, email, password string) (User, error) {
	m.verifyCredentialsCalled = true
	m.verifyTenantID = tenantID
	m.lastUser = User{Email: email, Password: password}
	if m.verifyErr != nil {
		return User{}, m.verifyErr
	}
	return m.verifyReturnUser, nil
}

func (m *mockDirectoryService) GetTenantByEmail(context.Context, string) (string, error) {
	return "22222222-2222-2222-2222-222222222222", nil
}

func (m *mockDirectoryService) GetTenantIDBySlug(context.Context, string) (string, error) {
	return "22222222-2222-2222-2222-222222222222", nil
}

func (m *mockDirectoryService) CreateTenant(context.Context, string, string, string, string) error {
	return nil
}

func (m *mockDirectoryService) AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error {
	return nil
}

func (m *mockDirectoryService) RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error {
	return nil
}

func (m *mockDirectoryService) ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error) {
	return nil, nil
}

func (m *mockDirectoryService) ListGroupMembers(ctx context.Context, tenantID, groupID string) ([]User, error) {
	return nil, nil
}
