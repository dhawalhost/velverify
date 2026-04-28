package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dhawalhost/wardseal/internal/authz"
)

// Service defines RBAC service operations.
type Service interface {
	// Roles
	CreateRole(ctx context.Context, tenantID, name, description string) (Role, error)
	GetRole(ctx context.Context, tenantID, id string) (Role, error)
	ListRoles(ctx context.Context, tenantID string) ([]Role, error)
	UpdateRole(ctx context.Context, tenantID, id, name, description string) (Role, error)
	DeleteRole(ctx context.Context, tenantID, id string) error

	// Permissions
	CreatePermission(ctx context.Context, tenantID, resource, action, description string) (Permission, error)
	ListPermissions(ctx context.Context, tenantID string) ([]Permission, error)

	// Role-Permission
	AssignPermissionToRole(ctx context.Context, roleID, permissionID string) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error
	GetRolePermissions(ctx context.Context, roleID string) ([]Permission, error)

	// User-Role
	AssignRoleToUser(ctx context.Context, tenantID, userID, roleID string, assignedBy *string) error
	AssignRoleWithExpiration(ctx context.Context, tenantID, userID, roleID string, assignedBy *string, duration string) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID string) error
	GetUserRoles(ctx context.Context, tenantID, userID string) ([]Role, error)
	GetUserPermissions(ctx context.Context, tenantID, userID string) ([]Permission, error)
	ListExpiredAssignments(ctx context.Context) ([]UserRole, error)

	// Authorization check
	HasPermission(ctx context.Context, tenantID, userID, resource, action string) (bool, error)
}

type service struct {
	store       Repository
	graphEngine *authz.Engine
}

// NewService creates a new RBAC service with hybrid authorization support.
func NewService(store Repository, graphEngine *authz.Engine) Service {
	return &service{
		store:       store,
		graphEngine: graphEngine,
	}
}

func (s *service) CreateRole(ctx context.Context, tenantID, name, description string) (Role, error) {
	if name == "" {
		return Role{}, fmt.Errorf("role name is required")
	}

	r := Role{TenantID: tenantID, Name: name, Description: description}
	id, err := s.store.CreateRole(ctx, r)
	if err != nil {
		return Role{}, fmt.Errorf("failed to create role: %w", err)
	}
	return s.store.GetRole(ctx, tenantID, id)
}

func (s *service) GetRole(ctx context.Context, tenantID, id string) (Role, error) {
	return s.store.GetRole(ctx, tenantID, id)
}

func (s *service) ListRoles(ctx context.Context, tenantID string) ([]Role, error) {
	roles, err := s.store.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		if err := s.seedDefaultRolesAndPermissions(ctx, tenantID); err == nil {
			return s.store.ListRoles(ctx, tenantID)
		}
	}
	return roles, nil
}

func (s *service) UpdateRole(ctx context.Context, tenantID, id, name, description string) (Role, error) {
	r := Role{Name: name, Description: description}
	if err := s.store.UpdateRole(ctx, id, r); err != nil {
		return Role{}, fmt.Errorf("failed to update role: %w", err)
	}
	return s.store.GetRole(ctx, tenantID, id)
}

func (s *service) DeleteRole(ctx context.Context, tenantID, id string) error {
	return s.store.DeleteRole(ctx, tenantID, id)
}

func (s *service) CreatePermission(ctx context.Context, tenantID, resource, action, description string) (Permission, error) {
	if resource == "" || action == "" {
		return Permission{}, fmt.Errorf("resource and action are required")
	}

	p := Permission{TenantID: tenantID, Resource: resource, Action: action, Description: description}
	id, err := s.store.CreatePermission(ctx, p)
	if err != nil {
		return Permission{}, fmt.Errorf("failed to create permission: %w", err)
	}
	p.ID = id
	return p, nil
}

func (s *service) ListPermissions(ctx context.Context, tenantID string) ([]Permission, error) {
	perms, err := s.store.ListPermissions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(perms) == 0 {
		if err := s.seedDefaultRolesAndPermissions(ctx, tenantID); err == nil {
			return s.store.ListPermissions(ctx, tenantID)
		}
	}
	return perms, nil
}

func (s *service) AssignPermissionToRole(ctx context.Context, roleID, permissionID string) error {
	return s.store.AssignPermissionToRole(ctx, roleID, permissionID)
}

func (s *service) RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error {
	return s.store.RemovePermissionFromRole(ctx, roleID, permissionID)
}

func (s *service) GetRolePermissions(ctx context.Context, roleID string) ([]Permission, error) {
	return s.store.GetPermissionsByRole(ctx, roleID)
}

func (s *service) AssignRoleToUser(ctx context.Context, tenantID, userID, roleID string, assignedBy *string) error {
	return s.store.AssignRoleToUser(ctx, tenantID, userID, roleID, assignedBy)
}

func (s *service) AssignRoleWithExpiration(ctx context.Context, tenantID, userID, roleID string, assignedBy *string, duration string) error {
	d, err := time.ParseDuration(duration)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	expiresAt := time.Now().Add(d)

	// We use the direct Exec in the store for this specialized case
	_, err = s.store.(*sqlRepository).db.ExecContext(ctx,
		`INSERT INTO user_roles (user_id, role_id, tenant_id, assigned_by, expires_at) 
		 VALUES ($1, $2, $3, $4, $5) 
		 ON CONFLICT (user_id, role_id) DO UPDATE SET assigned_at = NOW(), assigned_by = $4, expires_at = $5`,
		userID, roleID, tenantID, assignedBy, expiresAt)
	return err
}

func (s *service) ListExpiredAssignments(ctx context.Context) ([]UserRole, error) {
	return s.store.ListExpiredAssignments(ctx)
}

func (s *service) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	return s.store.RemoveRoleFromUser(ctx, userID, roleID)
}

func (s *service) GetUserRoles(ctx context.Context, tenantID, userID string) ([]Role, error) {
	return s.store.GetUserRoles(ctx, tenantID, userID)
}

func (s *service) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]Permission, error) {
	return s.store.GetUserPermissions(ctx, tenantID, userID)
}

// HasPermission checks if a user has a specific permission via RBAC roles or ReBAC relationships.
func (s *service) HasPermission(ctx context.Context, tenantID, userID, resource, action string) (bool, error) {
	// 1. RBAC Check (Traditional Roles)
	perms, err := s.store.GetUserPermissions(ctx, tenantID, userID)
	if err == nil {
		for _, p := range perms {
			if (p.Resource == resource || p.Resource == "*") &&
				(p.Action == action || p.Action == "*" || p.Action == "admin") {
				return true, nil
			}
		}
	}

	// 2. ReBAC Check (Graph Relationships)
	// We map the RBAC 'resource:action' to a Graph 'namespace:resource_id' and 'relation'
	// For example: resource='document', action='edit' => namespace='document', relation='editor'
	if s.graphEngine != nil {
		// We assume the resource passed in is the object_id,
		// and we try to infer namespace from it or use a default.
		// For WardSeal, we'll try to parse "namespace:id" if present, else use generic.

		ns := "resource"
		objID := resource
		if parts := strings.Split(resource, ":"); len(parts) == 2 {
			ns = parts[0]
			objID = parts[1]
		}

		// Map actions to relations
		relation := action
		switch action {
		case "read", "view":
			relation = "viewer"
		case "write", "edit", "update":
			relation = "editor"
		case "delete", "manage":
			relation = "owner"
		}

		allowed, err := s.graphEngine.Check(ctx, tenantID, userID, "user", relation, ns, objID)
		if err == nil && allowed {
			return true, nil
		}
	}

	return false, nil
}

func (s *service) seedDefaultRolesAndPermissions(ctx context.Context, tenantID string) error {
	type permDef struct {
		resource    string
		action      string
		description string
	}
	type roleDef struct {
		name        string
		description string
		perms       []string
	}

	defaultPerms := []permDef{
		{"*", "*", "Full administrative access to all resources"},
		{"users", "read", "Read user profiles"},
		{"users", "write", "Create and edit user profiles"},
		{"users", "delete", "Delete user profiles"},
		{"groups", "read", "Read access groups"},
		{"groups", "write", "Create and edit access groups"},
		{"groups", "delete", "Delete access groups"},
		{"roles", "read", "Read roles and permission mappings"},
		{"roles", "write", "Create and edit roles and permission mappings"},
		{"roles", "delete", "Delete roles"},
		{"policies", "read", "Read zero-trust access policies"},
		{"policies", "write", "Create and edit zero-trust access policies"},
		{"policies", "delete", "Delete zero-trust access policies"},
		{"audit", "read", "Read system audit logs"},
		{"applications", "read", "View application mappings"},
		{"applications", "write", "Create and edit application mappings"},
		{"applications", "delete", "Delete application mappings"},
	}

	defaultRoles := []roleDef{
		{"super-admin", "Full access to all system administrative tasks and configurations", []string{"*:*"}},
		{"security-admin", "Manage and configure security parameters and policies", []string{
			"users:read", "groups:read", "roles:read", "policies:read", "audit:read", "applications:read",
		}},
		{"user-admin", "Create, manage, and configure user profiles and access groups", []string{
			"users:read", "users:write", "users:delete", "groups:read", "groups:write", "groups:delete",
		}},
		{"standard-user", "Basic access privileges assigned to normal organizational members", []string{
			"applications:read",
		}},
	}

	permIDs := make(map[string]string)
	for _, pd := range defaultPerms {
		pid, err := s.store.CreatePermission(ctx, Permission{
			TenantID:    tenantID,
			Resource:    pd.resource,
			Action:      pd.action,
			Description: pd.description,
		})
		if err != nil {
			return fmt.Errorf("failed to seed permission %s:%s: %w", pd.resource, pd.action, err)
		}
		permIDs[fmt.Sprintf("%s:%s", pd.resource, pd.action)] = pid
	}

	for _, rd := range defaultRoles {
		rid, err := s.store.CreateRole(ctx, Role{
			TenantID:    tenantID,
			Name:        rd.name,
			Description: rd.description,
		})
		if err != nil {
			return fmt.Errorf("failed to seed role %s: %w", rd.name, err)
		}

		for _, pkey := range rd.perms {
			if pid, ok := permIDs[pkey]; ok {
				_ = s.store.AssignPermissionToRole(ctx, rid, pid)
			}
		}
	}

	return nil
}
