package auth

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/dhawalhost/wardseal/internal/rbac"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"
)

// Mock RBAC Store
type mockRBACRepo struct {
	roles       []string
	permissions []string
}

func (m *mockRBACRepo) GetUserRoles(ctx context.Context, tenantID, userID string) ([]rbac.Role, error) {
	roles := make([]rbac.Role, len(m.roles))
	for i, name := range m.roles {
		roles[i] = rbac.Role{Name: name}
	}
	return roles, nil
}
func (m *mockRBACRepo) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]rbac.Permission, error) {
	perms := make([]rbac.Permission, len(m.permissions))
	for i, name := range m.permissions {
		perms[i] = rbac.Permission{Resource: name}
	}
	return perms, nil
}

// Satisfy rbac.Repository interface
func (m *mockRBACRepo) CreateRole(ctx context.Context, r rbac.Role) (string, error)             { return "", nil }
func (m *mockRBACRepo) GetRole(ctx context.Context, tenantID, id string) (rbac.Role, error)    { return rbac.Role{}, nil }
func (m *mockRBACRepo) GetRoleByName(ctx context.Context, tenantID, name string) (rbac.Role, error) {
	return rbac.Role{}, nil
}
func (m *mockRBACRepo) ListRoles(ctx context.Context, tenantID string) ([]rbac.Role, error)      { return nil, nil }
func (m *mockRBACRepo) UpdateRole(ctx context.Context, id string, r rbac.Role) error           { return nil }
func (m *mockRBACRepo) DeleteRole(ctx context.Context, tenantID, id string) error             { return nil }
func (m *mockRBACRepo) CreatePermission(ctx context.Context, p rbac.Permission) (string, error) { return "", nil }
func (m *mockRBACRepo) ListPermissions(ctx context.Context, tenantID string) ([]rbac.Permission, error) {
	return nil, nil
}
func (m *mockRBACRepo) GetPermissionsByRole(ctx context.Context, roleID string) ([]rbac.Permission, error) {
	return nil, nil
}
func (m *mockRBACRepo) AssignPermissionToRole(ctx context.Context, roleID, permissionID string) error {
	return nil
}
func (m *mockRBACRepo) RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error {
	return nil
}
func (m *mockRBACRepo) AssignRoleToUser(ctx context.Context, tenantID, userID, roleID string, assignedBy *string) error {
	return nil
}
func (m *mockRBACRepo) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error { return nil }

func TestZeroTrust_RBACClaimsInJWT(t *testing.T) {
	rbacStore := &mockRBACRepo{
		roles:       []string{"admin", "editor"},
		permissions: []string{"read:all", "write:all"},
	}
	
	svc := &authService{
		rbacStore: rbacStore,
		signer:    &mockSigner{},
	}

	tenantID := uuid.New().String()
	userID := uuid.New().String()

	// 1. Test Access Token
	token, err := svc.generateAccessToken(context.Background(), tenantID, "test-client", "openid profile", userID)
	if err != nil {
		t.Fatalf("failed to generate access token: %v", err)
	}

	claims := jwt.MapClaims{}
	_, _, err = new(jwt.Parser).ParseUnverified(token, claims)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	roles, ok := claims["roles"].([]interface{})
	if !ok || len(roles) != 2 {
		t.Errorf("expected 2 roles in claims, got %v", claims["roles"])
	}

	// 2. Test ID Token
	idToken, err := svc.generateIDToken(context.Background(), tenantID, "test-client", userID, "nonce-123")
	if err != nil {
		t.Fatalf("failed to generate id token: %v", err)
	}

	idClaims := jwt.MapClaims{}
	_, _, err = new(jwt.Parser).ParseUnverified(idToken, idClaims)
	if err != nil {
		t.Fatalf("failed to parse id token: %v", err)
	}

	if _, ok := idClaims["roles"]; !ok {
		t.Errorf("missing roles claim in ID token when profile scope requested")
	}
}

func TestZeroTrust_AdaptiveMFATrigger(t *testing.T) {
	tenantID := uuid.New().String()
	blockedIP := "10.0.0.1"
	
	repo := &mockIPPolicyRepo{
		policies: []IPPolicy{
			{
				Type:     IPPolicyBlock,
				CIDR:     strPtr(blockedIP + "/32"),
				TenantID: tenantID,
			},
		},
	}

	engine := NewRiskEngine(nil, nil, nil).WithIPPolicy(repo, nil)
	
	ctx := middleware.InjectTenantID(context.Background(), tenantID)

	res, err := engine.Evaluate(ctx, uuid.New().String(), "", blockedIP)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if res.Score < 40 {
		t.Fatalf("expected risk score >= 40 for blocked IP, got %d", res.Score)
	}
}

// Mock Signer for JWT generation in tests
type mockSigner struct{}

func (s *mockSigner) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("test-secret"))
}
func (s *mockSigner) KeyID() string { return "test-key" }
func (s *mockSigner) PublicJWK() (interface{}, error) { return nil, nil }
func (s *mockSigner) PublicKey() *rsa.PublicKey { return nil }
func (s *mockSigner) Algorithm() string { return "HS256" }
func (s *mockSigner) Close() error { return nil }

func strPtr(s string) *string { return &s }

type mockIPPolicyRepo struct {
	policies []IPPolicy
}

func (m *mockIPPolicyRepo) Create(ctx context.Context, p IPPolicy) (string, error) { return "", nil }
func (m *mockIPPolicyRepo) List(ctx context.Context, tenantID string) ([]IPPolicy, error) { return nil, nil }
func (m *mockIPPolicyRepo) Delete(ctx context.Context, tenantID, id string) error { return nil }
func (m *mockIPPolicyRepo) ListBlocked(ctx context.Context, tenantID string) ([]IPPolicy, error) {
	return m.policies, nil
}
