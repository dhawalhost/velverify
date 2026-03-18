package rbac

import (
	"context"
	"fmt"
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
	RemoveRoleFromUser(ctx context.Context, userID, roleID string) error
	GetUserRoles(ctx context.Context, tenantID, userID string) ([]Role, error)
	GetUserPermissions(ctx context.Context, tenantID, userID string) ([]Permission, error)

	// Authorization check
	HasPermission(ctx context.Context, tenantID, userID, resource, action string) (bool, error)
}

type service struct {
	store Repository
}

// NewService creates a new RBAC service.
func NewService(store Repository) Service {
	return &service{store: store}
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
	return s.store.ListRoles(ctx, tenantID)
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
	return s.store.ListPermissions(ctx, tenantID)
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

func (s *service) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	return s.store.RemoveRoleFromUser(ctx, userID, roleID)
}

func (s *service) GetUserRoles(ctx context.Context, tenantID, userID string) ([]Role, error) {
	return s.store.GetUserRoles(ctx, tenantID, userID)
}

func (s *service) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]Permission, error) {
	return s.store.GetUserPermissions(ctx, tenantID, userID)
}

// HasPermission checks if a user has a specific permission.
func (s *service) HasPermission(ctx context.Context, tenantID, userID, resource, action string) (bool, error) {
	perms, err := s.store.GetUserPermissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}

	for _, p := range perms {
		// Check for exact match or wildcard
		if (p.Resource == resource || p.Resource == "*") &&
			(p.Action == action || p.Action == "*" || p.Action == "admin") {
			return true, nil
		}
	}
	return false, nil
}
