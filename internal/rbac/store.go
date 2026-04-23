package rbac

import (
	"context"
	"time"

	"github.com/jmoiron/sqlx"
)

// Role represents an RBAC role.
type Role struct {
	ID          string    `json:"id" db:"id"`
	TenantID    string    `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description,omitempty" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Permission represents an RBAC permission.
type Permission struct {
	ID          string    `json:"id" db:"id"`
	TenantID    string    `json:"tenant_id" db:"tenant_id"`
	Resource    string    `json:"resource" db:"resource"`
	Action      string    `json:"action" db:"action"`
	Description string    `json:"description,omitempty" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// UserRole represents a user's role assignment.
type UserRole struct {
	UserID     string     `json:"user_id" db:"user_id"`
	RoleID     string     `json:"role_id" db:"role_id"`
	TenantID   string     `json:"tenant_id" db:"tenant_id"`
	AssignedAt time.Time  `json:"assigned_at" db:"assigned_at"`
	AssignedBy *string    `json:"assigned_by,omitempty" db:"assigned_by"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
}

// Repository defines RBAC storage operations.
type Repository interface {
	// Roles
	CreateRole(ctx context.Context, r Role) (string, error)
	GetRole(ctx context.Context, tenantID, id string) (Role, error)
	GetRoleByName(ctx context.Context, tenantID, name string) (Role, error)
	ListRoles(ctx context.Context, tenantID string) ([]Role, error)
	UpdateRole(ctx context.Context, id string, r Role) error
	DeleteRole(ctx context.Context, tenantID, id string) error

	// Permissions
	CreatePermission(ctx context.Context, p Permission) (string, error)
	ListPermissions(ctx context.Context, tenantID string) ([]Permission, error)
	GetPermissionsByRole(ctx context.Context, roleID string) ([]Permission, error)

	// Role-Permission mapping
	AssignPermissionToRole(ctx context.Context, roleID, permissionID string) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error

	// User-Role mapping
	AssignRoleToUser(ctx context.Context, tenantID, userID, roleID string, assignedBy *string) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID string) error
	GetUserRoles(ctx context.Context, tenantID, userID string) ([]Role, error)
	GetUserPermissions(ctx context.Context, tenantID, userID string) ([]Permission, error)
	ListExpiredAssignments(ctx context.Context) ([]UserRole, error)
}

type sqlRepository struct {
	db *sqlx.DB
}

// NewRepository creates a new RBAC repository.
func NewRepository(db *sqlx.DB) Repository {
	return &sqlRepository{db: db}
}

func (s *sqlRepository) CreateRole(ctx context.Context, r Role) (string, error) {
	var id string
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO roles (tenant_id, name, description) VALUES ($1, $2, $3) RETURNING id`,
		r.TenantID, r.Name, r.Description,
	).Scan(&id)
	return id, err
}

func (s *sqlRepository) GetRole(ctx context.Context, tenantID, id string) (Role, error) {
	var r Role
	err := s.db.GetContext(ctx, &r, `SELECT * FROM roles WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return r, err
}

func (s *sqlRepository) GetRoleByName(ctx context.Context, tenantID, name string) (Role, error) {
	var r Role
	err := s.db.GetContext(ctx, &r, `SELECT * FROM roles WHERE name = $1 AND tenant_id = $2`, name, tenantID)
	return r, err
}

func (s *sqlRepository) ListRoles(ctx context.Context, tenantID string) ([]Role, error) {
	var roles []Role
	err := s.db.SelectContext(ctx, &roles, `SELECT * FROM roles WHERE tenant_id = $1 ORDER BY name`, tenantID)
	return roles, err
}

func (s *sqlRepository) UpdateRole(ctx context.Context, id string, r Role) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE roles SET name = $1, description = $2, updated_at = NOW() WHERE id = $3`,
		r.Name, r.Description, id)
	return err
}

func (s *sqlRepository) DeleteRole(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (s *sqlRepository) CreatePermission(ctx context.Context, p Permission) (string, error) {
	var id string
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO permissions (tenant_id, resource, action, description) 
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		p.TenantID, p.Resource, p.Action, p.Description,
	).Scan(&id)
	return id, err
}

func (s *sqlRepository) ListPermissions(ctx context.Context, tenantID string) ([]Permission, error) {
	var perms []Permission
	err := s.db.SelectContext(ctx, &perms,
		`SELECT * FROM permissions WHERE tenant_id = $1 ORDER BY resource, action`, tenantID)
	return perms, err
}

func (s *sqlRepository) GetPermissionsByRole(ctx context.Context, roleID string) ([]Permission, error) {
	var perms []Permission
	err := s.db.SelectContext(ctx, &perms,
		`SELECT p.* FROM permissions p 
		 JOIN role_permissions rp ON p.id = rp.permission_id 
		 WHERE rp.role_id = $1`, roleID)
	return perms, err
}

func (s *sqlRepository) AssignPermissionToRole(ctx context.Context, roleID, permissionID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		roleID, permissionID)
	return err
}

func (s *sqlRepository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`,
		roleID, permissionID)
	return err
}

func (s *sqlRepository) AssignRoleToUser(ctx context.Context, tenantID, userID, roleID string, assignedBy *string) error {
	// By default, no expiration. Specific duration is set via specialized wrapper if needed,
	// but here we allow it to be updated separately or we could add it to params.
	// For simplicity in the repository, we'll add an internal method or just Exec direct.
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_roles (user_id, role_id, tenant_id, assigned_by) 
		 VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, role_id) DO UPDATE SET assigned_at = NOW(), assigned_by = $4`,
		userID, roleID, tenantID, assignedBy)
	return err
}

func (s *sqlRepository) ListExpiredAssignments(ctx context.Context) ([]UserRole, error) {
	var assignments []UserRole
	err := s.db.SelectContext(ctx, &assignments,
		`SELECT * FROM user_roles WHERE expires_at IS NOT NULL AND expires_at < NOW()`)
	return assignments, err
}

func (s *sqlRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`,
		userID, roleID)
	return err
}

func (s *sqlRepository) GetUserRoles(ctx context.Context, tenantID, userID string) ([]Role, error) {
	var roles []Role
	err := s.db.SelectContext(ctx, &roles,
		`SELECT r.* FROM roles r 
		 JOIN user_roles ur ON r.id = ur.role_id 
		 WHERE ur.user_id = $1 AND ur.tenant_id = $2`, userID, tenantID)
	return roles, err
}

func (s *sqlRepository) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]Permission, error) {
	var perms []Permission
	err := s.db.SelectContext(ctx, &perms,
		`SELECT DISTINCT p.* FROM permissions p
		 JOIN role_permissions rp ON p.id = rp.permission_id
		 JOIN user_roles ur ON rp.role_id = ur.role_id
		 WHERE ur.user_id = $1 AND ur.tenant_id = $2`, userID, tenantID)
	return perms, err
}
