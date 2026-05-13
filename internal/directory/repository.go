package directory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

// Repository defines the interface for database operations.
type Repository interface {
	HealthCheck(ctx context.Context) error

	// Transaction support
	WithTransaction(ctx context.Context, fn func(tx *sqlx.Tx) error) error

	// User operations
	CreateIdentity(ctx context.Context, tx *sqlx.Tx, tenantID string, displayName, externalID *string, phoneNumbers PhoneNumbers, department, title, timezone *string) (string, error)
	CreateAccount(ctx context.Context, tx *sqlx.Tx, userID, tenantID, email, passwordHash string) error
	GetUserByID(ctx context.Context, tenantID, id string) (User, error)
	GetUserByEmail(ctx context.Context, tenantID, email string) (User, error)
	ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, int, error)
	ListPendingDeletions(ctx context.Context, olderThan time.Time) ([]User, error)
	UpdateIdentity(ctx context.Context, tx *sqlx.Tx, tenantID, id, status string, displayName, externalID *string, phoneNumbers PhoneNumbers, department, title, timezone *string, mfaEnforced *bool) error
	UpdateAccount(ctx context.Context, tx *sqlx.Tx, tenantID, id, email, passwordHash string) error
	DeleteIdentity(ctx context.Context, tenantID, id string) error

	// Group operations
	CreateGroup(ctx context.Context, tenantID string, name string) (string, error)
	GetGroupByID(ctx context.Context, tenantID, id string) (Group, error)
	ListGroups(ctx context.Context, tenantID string, limit, offset int) ([]Group, int, error)
	UpdateGroup(ctx context.Context, tenantID, id, name string) error
	DeleteGroup(ctx context.Context, tenantID, id string) error

	AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error
	ListGroupMembers(ctx context.Context, tenantID, groupID string) ([]User, error)
	ListUserGroups(ctx context.Context, tenantID, userID string) ([]Group, error)

	// Organization
	AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error
	RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error
	ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error)

	// Tenant
	CreateTenant(ctx context.Context, id, name, slug, plan string) error
	GetTenantIDBySlug(ctx context.Context, slug string) (string, error)
	GetTenantIDByEmail(ctx context.Context, email string) (string, error)
	GetPasswordHash(ctx context.Context, tenantID, email string) (User, string, error)

	// API Keys (for SCIM/Integrations)
	GetAPIKeyByPrefix(ctx context.Context, prefix string) ([]APIKeyCandidate, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id, tenantID string) error
}

type APIKeyCandidate struct {
	ID       string `db:"id"`
	TenantID string `db:"tenant_id"`
	KeyHash  string `db:"key_hash"`
}

type sqlRepository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) Repository {
	return &sqlRepository{db: db}
}

func (r *sqlRepository) HealthCheck(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

func (r *sqlRepository) WithTransaction(ctx context.Context, fn func(tx *sqlx.Tx) error) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sqlRepository) CreateIdentity(ctx context.Context, tx *sqlx.Tx, tenantID string, displayName, externalID *string, phoneNumbers PhoneNumbers, department, title, timezone *string) (string, error) {
	var id string
	query := `INSERT INTO identities (tenant_id, status, display_name, external_id, phone_numbers, department, title, timezone) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`
	var err error
	if tx != nil {
		err = tx.QueryRowxContext(ctx, query, tenantID, "active", displayName, externalID, phoneNumbers, department, title, timezone).Scan(&id)
	} else {
		err = r.db.QueryRowxContext(ctx, query, tenantID, "active", displayName, externalID, phoneNumbers, department, title, timezone).Scan(&id)
	}
	return id, err
}

func (r *sqlRepository) CreateAccount(ctx context.Context, tx *sqlx.Tx, userID, tenantID, email, passwordHash string) error {
	query := `INSERT INTO accounts (identity_id, tenant_id, login, password_hash) VALUES ($1, $2, $3, $4)`
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID, tenantID, email, passwordHash)
	} else {
		_, err = r.db.ExecContext(ctx, query, userID, tenantID, email, passwordHash)
	}
	return err
}

func (r *sqlRepository) GetUserByID(ctx context.Context, tenantID, id string) (User, error) {
	var user User
	err := r.db.GetContext(ctx, &user, `SELECT i.id, i.tenant_id, a.login AS email, i.display_name, i.external_id, i.phone_numbers, i.department, i.title, i.timezone, i.status, i.mfa_enforced, i.created_at, i.updated_at
		 FROM identities i JOIN accounts a ON i.id = a.identity_id WHERE i.id = $1 AND i.tenant_id = $2`,
		id, tenantID)
	return user, err
}

func (r *sqlRepository) GetUserByEmail(ctx context.Context, tenantID, email string) (User, error) {
	var user User
	err := r.db.GetContext(ctx, &user, `SELECT i.id, i.tenant_id, a.login AS email, i.display_name, i.external_id, i.phone_numbers, i.department, i.title, i.timezone, i.status, i.mfa_enforced, i.created_at, i.updated_at
		 FROM identities i JOIN accounts a ON i.id = a.identity_id WHERE a.login = $1 AND a.tenant_id = $2`,
		email, tenantID)
	return user, err
}

func (r *sqlRepository) GetPasswordHash(ctx context.Context, tenantID, email string) (User, string, error) {
	var record struct {
		User
		PasswordHash string `db:"password_hash"`
	}
	err := r.db.GetContext(ctx, &record, `SELECT i.id, i.tenant_id, a.login AS email, i.display_name, i.external_id, i.phone_numbers, i.department, i.title, i.timezone, i.status, i.mfa_enforced, i.created_at, i.updated_at, a.password_hash
		FROM identities i JOIN accounts a ON i.id = a.identity_id
		WHERE a.login = $1 AND a.tenant_id = $2`, email, tenantID)
	if err != nil {
		return User{}, "", err
	}
	return record.User, record.PasswordHash, nil
}

func (r *sqlRepository) ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, int, error) {
	var total int
	err := r.db.GetContext(ctx, &total, `SELECT COUNT(*) FROM identities WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, 0, err
	}

	var users []User
	err = r.db.SelectContext(ctx, &users, `SELECT i.id, i.tenant_id, a.login AS email, i.display_name, i.external_id, i.phone_numbers, i.department, i.title, i.timezone, i.status, i.mfa_enforced, i.created_at, i.updated_at
		FROM identities i JOIN accounts a ON i.id = a.identity_id 
		WHERE i.tenant_id = $1 
		ORDER BY i.created_at DESC 
		LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	return users, total, err
}

func (r *sqlRepository) ListPendingDeletions(ctx context.Context, olderThan time.Time) ([]User, error) {
	var users []User
	err := r.db.SelectContext(ctx, &users, `SELECT i.id, i.tenant_id, a.login AS email, i.display_name, i.external_id, i.phone_numbers, i.department, i.title, i.timezone, i.status, i.mfa_enforced, i.created_at, i.updated_at
		FROM identities i JOIN accounts a ON i.id = a.identity_id 
		WHERE i.status = 'pending_deletion' AND i.updated_at < $1`,
		olderThan)
	return users, err
}

func (r *sqlRepository) UpdateIdentity(ctx context.Context, tx *sqlx.Tx, tenantID, id, status string, displayName, externalID *string, phoneNumbers PhoneNumbers, department, title, timezone *string, mfaEnforced *bool) error {
	query := `UPDATE identities SET status = $1, display_name = $2, external_id = $3, phone_numbers = $4, department = $5, title = $6, timezone = $7, mfa_enforced = $8, updated_at = NOW() WHERE id = $9 AND tenant_id = $10`
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, status, displayName, externalID, phoneNumbers, department, title, timezone, mfaEnforced, id, tenantID)
	} else {
		_, err = r.db.ExecContext(ctx, query, status, displayName, externalID, phoneNumbers, department, title, timezone, mfaEnforced, id, tenantID)
	}
	return err
}

func (r *sqlRepository) UpdateAccount(ctx context.Context, tx *sqlx.Tx, tenantID, id, email, passwordHash string) error {
	if email != "" {
		query := `UPDATE accounts SET login = $1 WHERE identity_id = $2 AND tenant_id = $3`
		if tx != nil {
			if _, err := tx.ExecContext(ctx, query, email, id, tenantID); err != nil {
				return err
			}
		} else {
			if _, err := r.db.ExecContext(ctx, query, email, id, tenantID); err != nil {
				return err
			}
		}
	}
	if passwordHash != "" {
		query := `UPDATE accounts SET password_hash = $1 WHERE identity_id = $2 AND tenant_id = $3`
		if tx != nil {
			if _, err := tx.ExecContext(ctx, query, passwordHash, id, tenantID); err != nil {
				return err
			}
		} else {
			if _, err := r.db.ExecContext(ctx, query, passwordHash, id, tenantID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *sqlRepository) DeleteIdentity(ctx context.Context, tenantID, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM identities WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (r *sqlRepository) CreateGroup(ctx context.Context, tenantID string, name string) (string, error) {
	var id string
	err := r.db.QueryRowxContext(ctx, `INSERT INTO groups (tenant_id, name) VALUES ($1, $2) RETURNING id`, tenantID, name).Scan(&id)
	return id, err
}

func (r *sqlRepository) GetGroupByID(ctx context.Context, tenantID, id string) (Group, error) {
	var group Group
	err := r.db.GetContext(ctx, &group, `SELECT id, tenant_id, name, created_at, updated_at FROM groups WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return group, err
}

func (r *sqlRepository) ListGroups(ctx context.Context, tenantID string, limit, offset int) ([]Group, int, error) {
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT COUNT(*) FROM groups WHERE tenant_id = $1`, tenantID); err != nil {
		return nil, 0, err
	}
	var groups []Group
	err := r.db.SelectContext(ctx, &groups, `SELECT id, tenant_id, name, created_at, updated_at FROM groups WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	return groups, total, err
}

func (r *sqlRepository) UpdateGroup(ctx context.Context, tenantID, id, name string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE groups SET name = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3`, name, id, tenantID)
	return err
}

func (r *sqlRepository) DeleteGroup(ctx context.Context, tenantID, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM groups WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (r *sqlRepository) AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error {
	query := `INSERT INTO identity_groups (identity_id, group_id, tenant_id)
		SELECT $1::uuid, $2::uuid, $3::varchar
		WHERE EXISTS (SELECT 1 FROM identities WHERE id = $1::uuid AND tenant_id = $3::varchar)
		AND EXISTS (SELECT 1 FROM groups WHERE id = $2::uuid AND tenant_id = $3::varchar)`
	_, err := r.db.ExecContext(ctx, query, userID, groupID, tenantID)
	return err
}

func (r *sqlRepository) RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM identity_groups WHERE identity_id = $1 AND group_id = $2 AND tenant_id = $3`, userID, groupID, tenantID)
	return err
}

func (r *sqlRepository) ListGroupMembers(ctx context.Context, tenantID, groupID string) ([]User, error) {
	var users []User
	query := `SELECT i.id, i.tenant_id, a.login AS email, i.status, i.created_at, i.updated_at
		FROM identities i
		JOIN accounts a ON i.id = a.identity_id
		JOIN identity_groups ig ON i.id = ig.identity_id
		WHERE ig.group_id = $1 AND i.tenant_id = $2`
	err := r.db.SelectContext(ctx, &users, query, groupID, tenantID)
	return users, err
}

func (r *sqlRepository) ListUserGroups(ctx context.Context, tenantID, userID string) ([]Group, error) {
	var groups []Group
	query := `SELECT g.id, g.tenant_id, g.name, g.created_at, g.updated_at
		FROM groups g
		JOIN identity_groups ig ON g.id = ig.group_id
		WHERE ig.identity_id = $1 AND g.tenant_id = $2`
	err := r.db.SelectContext(ctx, &groups, query, userID, tenantID)
	return groups, err
}

func (r *sqlRepository) AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO user_organizations (tenant_id, user_id, org_id, role) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant_id, user_id, org_id) DO UPDATE SET role = EXCLUDED.role, updated_at = NOW()`, tenantID, userID, orgID, role)
	return err
}

func (r *sqlRepository) RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_organizations WHERE tenant_id = $1 AND user_id = $2 AND org_id = $3`, tenantID, userID, orgID)
	return err
}

func (r *sqlRepository) ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error) {
	var orgIDs []string
	err := r.db.SelectContext(ctx, &orgIDs, `SELECT org_id FROM user_organizations WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	return orgIDs, err
}

func (r *sqlRepository) CreateTenant(ctx context.Context, id, name, slug, plan string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug, plan, created_at, updated_at) VALUES ($1, $2, $3, $4, NOW(), NOW())`, id, name, slug, plan)
	return err
}

func (r *sqlRepository) GetTenantIDBySlug(ctx context.Context, slug string) (string, error) {
	var id string
	err := r.db.GetContext(ctx, &id, `SELECT id FROM tenants WHERE slug = $1`, slug)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (r *sqlRepository) GetTenantIDByEmail(ctx context.Context, email string) (string, error) {
	var tenantID string
	err := r.db.GetContext(ctx, &tenantID, `SELECT tenant_id FROM accounts WHERE login = $1 LIMIT 1`, email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return tenantID, err
}

func (r *sqlRepository) GetAPIKeyByPrefix(ctx context.Context, prefix string) ([]APIKeyCandidate, error) {
	var candidates []APIKeyCandidate
	query := `SELECT id, tenant_id, key_hash FROM api_keys WHERE key_prefix = $1 AND status = 'active'`
	err := r.db.SelectContext(ctx, &candidates, query, prefix)
	return candidates, err
}

func (r *sqlRepository) UpdateAPIKeyLastUsed(ctx context.Context, id, tenantID string) error {
	query := `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1 AND tenant_id = $2`
	_, err := r.db.ExecContext(ctx, query, id, tenantID)
	return err
}
