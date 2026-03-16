package directory

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
)

// Service defines the interface for the directory service.
type Service interface {
	HealthCheck(ctx context.Context) (bool, error)

	// User management
	CreateUser(ctx context.Context, tenantID string, user User) (string, error)
	GetUserByID(ctx context.Context, tenantID, id string) (User, error)
	GetUserByEmail(ctx context.Context, tenantID, email string) (User, error)
	ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, int, error)
	UpdateUser(ctx context.Context, tenantID, id string, user User) error
	DeleteUser(ctx context.Context, tenantID, id string) error

	// Group management
	CreateGroup(ctx context.Context, tenantID string, group Group) (string, error)
	GetGroupByID(ctx context.Context, tenantID, id string) (Group, error)
	ListGroups(ctx context.Context, tenantID string, limit, offset int) ([]Group, int, error)
	UpdateGroup(ctx context.Context, tenantID, id string, group Group) error
	DeleteGroup(ctx context.Context, tenantID, id string) error

	// Group membership
	AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error

	// Credential validation
	VerifyCredentials(ctx context.Context, tenantID, email, password string) (User, error)

	// Discovery
	GetTenantByEmail(ctx context.Context, email string) (string, error)

	// Tenant Management
	CreateTenant(ctx context.Context, id, name, slug, plan string) error
}

type directoryService struct {
	db *sqlx.DB // Use sqlx.DB
}

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrAlreadyExists = errors.New("already exists")

// NewService creates a new directory service.
func NewService(db *sqlx.DB) Service { // Use sqlx.DB
	return &directoryService{db: db}
}

func (s *directoryService) HealthCheck(ctx context.Context) (bool, error) {
	err := s.db.PingContext(ctx)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *directoryService) CreateUser(ctx context.Context, tenantID string, user User) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	tx, err := s.db.BeginTxx(ctx, nil) // Use BeginTxx for sqlx
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var userID string
	err = tx.QueryRowxContext(ctx, // Use QueryRowxContext for sqlx
		`INSERT INTO identities (tenant_id, status) VALUES ($1, $2) RETURNING id`,
		tenantID, "active").Scan(&userID)
	if err != nil {
		return "", err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO accounts (identity_id, tenant_id, login, password_hash) VALUES ($1, $2, $3, $4)`,
		userID, tenantID, user.Email, string(hashedPassword))
	if err != nil {
		return "", err
	}

	return userID, tx.Commit()
}

func (s *directoryService) GetUserByID(ctx context.Context, tenantID, id string) (User, error) {
	var user User
	err := s.db.GetContext(ctx, &user, `SELECT i.id, i.tenant_id, a.login AS email, i.status, i.created_at, i.updated_at
		 FROM identities i JOIN accounts a ON i.id = a.identity_id WHERE i.id = $1 AND i.tenant_id = $2`,
		id, tenantID)
	return user, err
}

func (s *directoryService) GetUserByEmail(ctx context.Context, tenantID, email string) (User, error) {
	var user User
	err := s.db.GetContext(ctx, &user, `SELECT i.id, i.tenant_id, a.login AS email, i.status, i.created_at, i.updated_at
		 FROM identities i JOIN accounts a ON i.id = a.identity_id WHERE a.login = $1 AND a.tenant_id = $2 AND i.tenant_id = $2`,
		email, tenantID)
	return user, err
}

func (s *directoryService) ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, int, error) {
	// Get total count
	var total int
	err := s.db.GetContext(ctx, &total, `SELECT COUNT(*) FROM identities WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, 0, err
	}

	// Get paginated users
	var users []User
	err = s.db.SelectContext(ctx, &users, `SELECT i.id, i.tenant_id, a.login AS email, i.status, i.created_at, i.updated_at
		FROM identities i JOIN accounts a ON i.id = a.identity_id 
		WHERE i.tenant_id = $1 
		ORDER BY i.created_at DESC 
		LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (s *directoryService) UpdateUser(ctx context.Context, tenantID, id string, user User) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if user.Email != "" {
		_, err := tx.ExecContext(ctx, `UPDATE accounts SET login = $1 WHERE identity_id = $2 AND tenant_id = $3`, user.Email, id, tenantID)
		if err != nil {
			return err
		}
	}

	if user.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE accounts SET password_hash = $1 WHERE identity_id = $2 AND tenant_id = $3`, string(hashedPassword), id, tenantID)
		if err != nil {
			return err
		}
	}

	if user.Status != "" {
		_, err := tx.ExecContext(ctx, `UPDATE identities SET status = $1 WHERE id = $2 AND tenant_id = $3`, user.Status, id, tenantID)
		if err != nil {
			return err
		}
	}

	_, err = tx.ExecContext(ctx, `UPDATE identities SET updated_at = NOW() WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *directoryService) DeleteUser(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM identities WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (s *directoryService) CreateGroup(ctx context.Context, tenantID string, group Group) (string, error) {
	var groupID string
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO groups (tenant_id, name) VALUES ($1, $2) RETURNING id`,
		tenantID, group.Name).Scan(&groupID)
	return groupID, err
}

func (s *directoryService) GetGroupByID(ctx context.Context, tenantID, id string) (Group, error) {
	var group Group
	err := s.db.GetContext(ctx, &group, `SELECT id, tenant_id, name, created_at, updated_at FROM groups WHERE id = $1 AND tenant_id = $2`,
		id, tenantID)
	return group, err
}

func (s *directoryService) ListGroups(ctx context.Context, tenantID string, limit, offset int) ([]Group, int, error) {
	var total int
	err := s.db.GetContext(ctx, &total, `SELECT COUNT(*) FROM groups WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, 0, err
	}

	var groups []Group
	err = s.db.SelectContext(ctx, &groups, `SELECT id, tenant_id, name, created_at, updated_at 
		FROM groups WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	return groups, total, nil
}

func (s *directoryService) UpdateGroup(ctx context.Context, tenantID, id string, group Group) error {
	_, err := s.db.ExecContext(ctx, `UPDATE groups SET name = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3`, group.Name, id, tenantID)
	return err
}

func (s *directoryService) DeleteGroup(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (s *directoryService) AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO identity_groups (identity_id, group_id, tenant_id)
	SELECT $1, $2, $3
	WHERE EXISTS (SELECT 1 FROM identities WHERE id = $1 AND tenant_id = $3)
	AND EXISTS (SELECT 1 FROM groups WHERE id = $2 AND tenant_id = $3)`, userID, groupID, tenantID)
	return err
}

func (s *directoryService) RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM identity_groups
	WHERE identity_id = $1 AND group_id = $2 AND tenant_id = $3`, userID, groupID, tenantID)
	return err
}

func (s *directoryService) VerifyCredentials(ctx context.Context, tenantID, email, password string) (User, error) {
	var record struct {
		User
		PasswordHash string `db:"password_hash"`
	}

	err := s.db.GetContext(ctx, &record, `SELECT i.id, i.tenant_id, a.login AS email, i.status, i.created_at, i.updated_at, a.password_hash
		FROM identities i JOIN accounts a ON i.id = a.identity_id
		WHERE a.login = $1 AND a.tenant_id = $2 AND i.tenant_id = $2`, email, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrInvalidCredentials
		}
		return User{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(record.PasswordHash), []byte(password)); err != nil {
		return User{}, ErrInvalidCredentials
	}

	return record.User, nil
}

func (s *directoryService) GetTenantByEmail(ctx context.Context, email string) (string, error) {
	var tenantID string
	// We just need the tenant_id from accounts table
	err := s.db.GetContext(ctx, &tenantID, `SELECT tenant_id FROM accounts WHERE login = $1 LIMIT 1`, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil // Not found
		}
		return "", err
	}
	return tenantID, nil
}

func (s *directoryService) CreateTenant(ctx context.Context, id, name, slug, plan string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug, plan, created_at, updated_at) VALUES ($1, $2, $3, $4, NOW(), NOW())`,
		id, name, slug, plan)
	if err != nil {
		// PostgreSql error code 23505 is unique_violation
		// This is a bit brittle, but works for our Postgres setup.
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}
