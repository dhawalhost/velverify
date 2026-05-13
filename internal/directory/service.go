package directory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/dhawalhost/wardseal/pkg/eventbus"

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
	ListPendingDeletions(ctx context.Context, olderThan time.Time) ([]User, error)
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
	ListGroupMembers(ctx context.Context, tenantID, groupID string) ([]User, error)
	ListUserGroups(ctx context.Context, tenantID, userID string) ([]Group, error)

	// Credential validation
	VerifyCredentials(ctx context.Context, tenantID, email, password string) (User, error)

	// Discovery
	GetTenantByEmail(ctx context.Context, email string) (string, error)

	// User-Organization mapping
	AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error
	RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error
	ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error)

	// Tenant Management
	CreateTenant(ctx context.Context, id, name, slug, plan string) error
	GetTenantIDBySlug(ctx context.Context, slug string) (string, error)
}

type directoryService struct {
	repo Repository
	bus  eventbus.EventBus
	passwordHistory map[string][]string
	mu sync.RWMutex
}

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrAlreadyExists = errors.New("already exists")
var ErrEmailAlreadyExistsGlobally = errors.New("email already in use globally")

var commonPasswords = map[string]bool{
	"password":     true,
	"12345678":     true,
	"qwertyuiop":   true,
	"admin123":     true,
	"welcome1":     true,
	"wardseal123":  true,
}

func validatePasswordPolicy(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	
	if commonPasswords[strings.ToLower(password)] {
		return errors.New("password is too common")
	}
	
	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)
	
	for _, char := range password {
		switch {
		case 'a' <= char && char <= 'z':
			hasLower = true
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case strings.ContainsRune(`!@#$%^&*()-_=+[]{};:'",.<>/?\|~`, char):
			hasSpecial = true
		}
	}
	
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}
	
	return nil
}

// NewService creates a new directory service.
func NewService(repo Repository, bus eventbus.EventBus) Service {
	return &directoryService{
		repo:            repo,
		bus:             bus,
		passwordHistory: make(map[string][]string),
	}
}

func (s *directoryService) HealthCheck(ctx context.Context) (bool, error) {
	if err := s.repo.HealthCheck(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *directoryService) CreateUser(ctx context.Context, tenantID string, user User) (string, error) {
	if err := validatePasswordPolicy(user.Password); err != nil {
		return "", err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	var userID string
	err = s.repo.WithTransaction(ctx, func(tx *sqlx.Tx) error {
		var err error
		userID, err = s.repo.CreateIdentity(ctx, tx, tenantID, user.DisplayName, user.ExternalID, user.PhoneNumbers, user.Department, user.Title, user.Timezone)
		if err != nil {
			return err
		}

		err = s.repo.CreateAccount(ctx, tx, userID, tenantID, user.Email, string(hashedPassword))
		if err != nil {
			if strings.Contains(err.Error(), "unique constraint") && strings.Contains(err.Error(), "accounts_login_key") {
				return ErrEmailAlreadyExistsGlobally
			}
			return err
		}
		return nil
	})

	if err == nil && s.bus != nil {
		payload, _ := json.Marshal(map[string]string{
			"tenant_id": tenantID,
			"user_id":   userID,
			"email":     user.Email,
		})
		_ = s.bus.Publish(ctx, "UserCreated", payload)
	}
	return userID, err
}

func (s *directoryService) GetUserByID(ctx context.Context, tenantID, id string) (User, error) {
	return s.repo.GetUserByID(ctx, tenantID, id)
}

func (s *directoryService) GetUserByEmail(ctx context.Context, tenantID, email string) (User, error) {
	return s.repo.GetUserByEmail(ctx, tenantID, email)
}

func (s *directoryService) ListUserGroups(ctx context.Context, tenantID, userID string) ([]Group, error) {
	return s.repo.ListUserGroups(ctx, tenantID, userID)
}

func (s *directoryService) ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, int, error) {
	return s.repo.ListUsers(ctx, tenantID, limit, offset)
}

func (s *directoryService) ListPendingDeletions(ctx context.Context, olderThan time.Time) ([]User, error) {
	return s.repo.ListPendingDeletions(ctx, olderThan)
}

func (s *directoryService) UpdateUser(ctx context.Context, tenantID, id string, user User) error {
	if user.Password != "" {
		if err := validatePasswordPolicy(user.Password); err != nil {
			return err
		}
		
		s.mu.RLock()
		history := s.passwordHistory[id]
		s.mu.RUnlock()
		
		for _, oldHash := range history {
			if err := bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(user.Password)); err == nil {
				return errors.New("password has been used recently")
			}
		}
	}

	err := s.repo.WithTransaction(ctx, func(tx *sqlx.Tx) error {
		var passwordHash string
		if user.Password != "" {
			hp, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			passwordHash = string(hp)
		}

		if err := s.repo.UpdateIdentity(ctx, tx, tenantID, id, user.Status, user.DisplayName, user.ExternalID, user.PhoneNumbers, user.Department, user.Title, user.Timezone, user.MFAEnforced); err != nil {
			return err
		}

		return s.repo.UpdateAccount(ctx, tx, tenantID, id, user.Email, passwordHash)
	})

	if err == nil && user.Password != "" {
		s.mu.Lock()
		history := s.passwordHistory[id]
		if len(history) >= 5 {
			history = history[1:]
		}
		hp, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		s.passwordHistory[id] = append(history, string(hp))
		s.mu.Unlock()
	}

	return err
}

func (s *directoryService) DeleteUser(ctx context.Context, tenantID, id string) error {
	err := s.repo.DeleteIdentity(ctx, tenantID, id)
	if err == nil && s.bus != nil {
		payload, _ := json.Marshal(map[string]string{
			"tenant_id": tenantID,
			"user_id":   id,
		})
		_ = s.bus.Publish(ctx, "UserDeactivated", payload)
	}
	return err
}

func (s *directoryService) CreateGroup(ctx context.Context, tenantID string, group Group) (string, error) {
	return s.repo.CreateGroup(ctx, tenantID, group.Name)
}

func (s *directoryService) GetGroupByID(ctx context.Context, tenantID, id string) (Group, error) {
	return s.repo.GetGroupByID(ctx, tenantID, id)
}

func (s *directoryService) ListGroups(ctx context.Context, tenantID string, limit, offset int) ([]Group, int, error) {
	return s.repo.ListGroups(ctx, tenantID, limit, offset)
}

func (s *directoryService) UpdateGroup(ctx context.Context, tenantID, id string, group Group) error {
	return s.repo.UpdateGroup(ctx, tenantID, id, group.Name)
}

func (s *directoryService) DeleteGroup(ctx context.Context, tenantID, id string) error {
	return s.repo.DeleteGroup(ctx, tenantID, id)
}

func (s *directoryService) AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error {
	err := s.repo.AddUserToGroup(ctx, tenantID, userID, groupID)
	if err == nil && s.bus != nil {
		payload, _ := json.Marshal(map[string]string{
			"tenant_id": tenantID,
			"user_id":   userID,
			"group_id":  groupID,
			"action":    "add",
		})
		_ = s.bus.Publish(ctx, "GroupMembershipChanged", payload)
	}
	return err
}

func (s *directoryService) RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error {
	err := s.repo.RemoveUserFromGroup(ctx, tenantID, userID, groupID)
	if err == nil && s.bus != nil {
		payload, _ := json.Marshal(map[string]string{
			"tenant_id": tenantID,
			"user_id":   userID,
			"group_id":  groupID,
			"action":    "remove",
		})
		_ = s.bus.Publish(ctx, "GroupMembershipChanged", payload)
	}
	return err
}

func (s *directoryService) ListGroupMembers(ctx context.Context, tenantID, groupID string) ([]User, error) {
	return s.repo.ListGroupMembers(ctx, tenantID, groupID)
}

func (s *directoryService) VerifyCredentials(ctx context.Context, tenantID, email, password string) (User, error) {
	user, hash, err := s.repo.GetPasswordHash(ctx, tenantID, email)
	if err != nil {
		return User{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return User{}, ErrInvalidCredentials
	}

	return user, nil
}

func (s *directoryService) GetTenantByEmail(ctx context.Context, email string) (string, error) {
	return s.repo.GetTenantIDByEmail(ctx, email)
}

func (s *directoryService) CreateTenant(ctx context.Context, id, name, slug, plan string) error {
	err := s.repo.CreateTenant(ctx, id, name, slug, plan)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return ErrAlreadyExists
		}
	}
	return err
}

func (s *directoryService) GetTenantIDBySlug(ctx context.Context, slug string) (string, error) {
	return s.repo.GetTenantIDBySlug(ctx, slug)
}

func (s *directoryService) AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error {
	if role == "" {
		role = "member"
	}
	return s.repo.AddUserToOrganization(ctx, tenantID, userID, orgID, role)
}

func (s *directoryService) RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error {
	return s.repo.RemoveUserFromOrganization(ctx, tenantID, userID, orgID)
}

func (s *directoryService) ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error) {
	return s.repo.ListUserOrganizations(ctx, tenantID, userID)
}
