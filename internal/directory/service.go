package directory

import (
	"context"
	"database/sql"
	"errors"

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
	UpdateUser(ctx context.Context, tenantID, id string, user User) error
	DeleteUser(ctx context.Context, tenantID, id string) error

	// Group management
	CreateGroup(ctx context.Context, tenantID string, group Group) (string, error)
	GetGroupByID(ctx context.Context, tenantID, id string) (Group, error)
	UpdateGroup(ctx context.Context, tenantID, id string, group Group) error
	DeleteGroup(ctx context.Context, tenantID, id string) error

	// Group membership
	AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error

	// Credential validation
	VerifyCredentials(ctx context.Context, tenantID, email, password string) (User, error)
}

type directoryService struct {
	db *sqlx.DB // Use sqlx.DB
}

var ErrInvalidCredentials = errors.New("invalid credentials")

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
	defer tx.Rollback()

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

func (s *directoryService) UpdateUser(ctx context.Context, tenantID, id string, user User) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

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
