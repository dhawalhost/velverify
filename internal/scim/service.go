package scim

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/dhawalhost/wardseal/internal/directory"
)

// Service defines the business logic for SCIM operations.
type Service struct {
	dirSvc directory.Service
}

// NewService creates a new SCIM service.
func NewService(dirSvc directory.Service) *Service {
	return &Service{
		dirSvc: dirSvc,
	}
}

// CreateUser handles SCIM user creation.
func (s *Service) CreateUser(ctx context.Context, tenantID string, req User) (User, error) {
	if req.UserName == "" {
		return User{}, errors.New("userName is required")
	}
	if req.Password != "" && len(req.Password) < 8 {
		return User{}, errors.New("password must be at least 8 characters")
	}
	email := req.UserName
	// If emails present, use primary or first one as well? For now, assume userName is email.
	if len(req.Emails) > 0 {
		for _, e := range req.Emails {
			if e.Primary {
				email = e.Value
				break
			}
		}
	}

	password := req.Password
	if password == "" {
		password = generateInitialPassword()
	}

	dirUser := directory.User{
		Email:    email,
		Status:   "active",
		Password: password,
	}
	if !req.Active {
		dirUser.Status = "inactive"
	}

	id, err := s.dirSvc.CreateUser(ctx, tenantID, dirUser)
	if err != nil {
		return User{}, fmt.Errorf("failed to create user: %w", err)
	}

	req.ID = id
	req.Meta = Meta{
		ResourceType: "User",
		Created:      time.Now().Format(time.RFC3339),
		LastModified: time.Now().Format(time.RFC3339),
		Location:     fmt.Sprintf("/scim/v2/Users/%s", id),
	}
	return req, nil
}

func generateInitialPassword() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "ChangeMe123!"
	}
	return "Ws!" + base64.RawURLEncoding.EncodeToString(buf)
}

// GetUser retrieves a SCIM user by ID.
func (s *Service) GetUser(ctx context.Context, tenantID, id string) (User, error) {
	u, err := s.dirSvc.GetUserByID(ctx, tenantID, id)
	if err != nil {
		return User{}, fmt.Errorf("failed to get user: %w", err)
	}

	return User{
		Schemas:  []string{UserSchema},
		ID:       u.ID,
		UserName: u.Email,
		Active:   u.Status == "active",
		Emails: []Email{
			{Value: u.Email, Type: "work", Primary: true},
		},
		Meta: Meta{
			ResourceType: "User",
			Created:      u.CreatedAt.Format(time.RFC3339),
			LastModified: u.UpdatedAt.Format(time.RFC3339),
			Location:     fmt.Sprintf("/scim/v2/Users/%s", u.ID),
		},
	}, nil
}

// ListUsers handles GET /scim/v2/Users with optional filtering and pagination.
func (s *Service) ListUsers(ctx context.Context, tenantID, filter string, startIndex, count int) (ListResponse, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 || count > 100 {
		count = 100
	}
	offset := startIndex - 1 // SCIM is 1-indexed

	users, total, err := s.dirSvc.ListUsers(ctx, tenantID, count, offset)
	if err != nil {
		return ListResponse{}, fmt.Errorf("failed to list users: %w", err)
	}

	// Convert to SCIM Users
	resources := make([]interface{}, 0, len(users))
	for _, u := range users {
		scimUser := User{
			Schemas:  []string{UserSchema},
			ID:       u.ID,
			UserName: u.Email,
			Active:   u.Status == "active",
			Emails: []Email{
				{Value: u.Email, Type: "work", Primary: true},
			},
			Meta: Meta{
				ResourceType: "User",
				Created:      u.CreatedAt.Format(time.RFC3339),
				LastModified: u.UpdatedAt.Format(time.RFC3339),
				Location:     fmt.Sprintf("/scim/v2/Users/%s", u.ID),
			},
		}
		resources = append(resources, scimUser)
	}

	return ListResponse{
		Schemas:      []string{ListSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}, nil
}

// ReplaceUser handles PUT /scim/v2/Users/{id} - full replacement.
func (s *Service) ReplaceUser(ctx context.Context, tenantID, id string, req User) (User, error) {
	// Map SCIM User to directory User
	email := req.UserName
	if len(req.Emails) > 0 {
		for _, e := range req.Emails {
			if e.Primary {
				email = e.Value
				break
			}
		}
	}

	status := "active"
	if !req.Active {
		status = "inactive"
	}

	dirUser := directory.User{
		Email:  email,
		Status: status,
	}

	if err := s.dirSvc.UpdateUser(ctx, tenantID, id, dirUser); err != nil {
		return User{}, fmt.Errorf("failed to update user: %w", err)
	}

	// Return updated user
	return s.GetUser(ctx, tenantID, id)
}

// PatchUser handles PATCH /scim/v2/Users/{id} - partial update.
// For simplicity, we support only "replace" operation on known attributes.
func (s *Service) PatchUser(ctx context.Context, tenantID, id string, ops []PatchOperation) (User, error) {
	// Get current state
	current, err := s.dirSvc.GetUserByID(ctx, tenantID, id)
	if err != nil {
		return User{}, fmt.Errorf("failed to get user: %w", err)
	}

	// Apply operations
	for _, op := range ops {
		switch op.Op {
		case "replace":
			switch op.Path {
			case "active":
				if active, ok := op.Value.(bool); ok {
					if active {
						current.Status = "active"
					} else {
						current.Status = "inactive"
					}
				}
			case "userName":
				if userName, ok := op.Value.(string); ok {
					current.Email = userName
				}
			}
		}
	}

	// Persist changes
	if err := s.dirSvc.UpdateUser(ctx, tenantID, id, current); err != nil {
		return User{}, fmt.Errorf("failed to patch user: %w", err)
	}

	return s.GetUser(ctx, tenantID, id)
}

// DeleteUser handles DELETE /scim/v2/Users/{id}.
func (s *Service) DeleteUser(ctx context.Context, tenantID, id string) error {
	if err := s.dirSvc.DeleteUser(ctx, tenantID, id); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// ========== SCIM Group Operations ==========

// CreateGroup handles POST /scim/v2/Groups.
func (s *Service) CreateGroup(ctx context.Context, tenantID string, req Group) (Group, error) {
	if req.DisplayName == "" {
		return Group{}, errors.New("displayName is required")
	}

	dirGroup := directory.Group{
		Name: req.DisplayName,
	}

	id, err := s.dirSvc.CreateGroup(ctx, tenantID, dirGroup)
	if err != nil {
		return Group{}, fmt.Errorf("failed to create group: %w", err)
	}

	return s.GetGroup(ctx, tenantID, id)
}

// GetGroup retrieves a SCIM group by ID.
func (s *Service) GetGroup(ctx context.Context, tenantID, id string) (Group, error) {
	g, err := s.dirSvc.GetGroupByID(ctx, tenantID, id)
	if err != nil {
		return Group{}, fmt.Errorf("failed to get group: %w", err)
	}

	return Group{
		Schemas:     []string{GroupSchema},
		ID:          g.ID,
		DisplayName: g.Name,
		Meta: Meta{
			ResourceType: "Group",
			Created:      g.CreatedAt.Format(time.RFC3339),
			LastModified: g.UpdatedAt.Format(time.RFC3339),
			Location:     fmt.Sprintf("/scim/v2/Groups/%s", g.ID),
		},
	}, nil
}

// ListGroups handles GET /scim/v2/Groups with pagination.
func (s *Service) ListGroups(ctx context.Context, tenantID string, startIndex, count int) (ListResponse, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 || count > 100 {
		count = 100
	}
	offset := startIndex - 1

	groups, total, err := s.dirSvc.ListGroups(ctx, tenantID, count, offset)
	if err != nil {
		return ListResponse{}, fmt.Errorf("failed to list groups: %w", err)
	}

	resources := make([]interface{}, 0, len(groups))
	for _, g := range groups {
		scimGroup := Group{
			Schemas:     []string{GroupSchema},
			ID:          g.ID,
			DisplayName: g.Name,
			Meta: Meta{
				ResourceType: "Group",
				Created:      g.CreatedAt.Format(time.RFC3339),
				LastModified: g.UpdatedAt.Format(time.RFC3339),
				Location:     fmt.Sprintf("/scim/v2/Groups/%s", g.ID),
			},
		}
		resources = append(resources, scimGroup)
	}

	return ListResponse{
		Schemas:      []string{ListSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}, nil
}

// ReplaceGroup handles PUT /scim/v2/Groups/{id}.
func (s *Service) ReplaceGroup(ctx context.Context, tenantID, id string, req Group) (Group, error) {
	dirGroup := directory.Group{
		Name: req.DisplayName,
	}

	if err := s.dirSvc.UpdateGroup(ctx, tenantID, id, dirGroup); err != nil {
		return Group{}, fmt.Errorf("failed to update group: %w", err)
	}

	return s.GetGroup(ctx, tenantID, id)
}

// PatchGroup handles PATCH /scim/v2/Groups/{id}.
func (s *Service) PatchGroup(ctx context.Context, tenantID, id string, ops []PatchOperation) (Group, error) {
	current, err := s.dirSvc.GetGroupByID(ctx, tenantID, id)
	if err != nil {
		return Group{}, fmt.Errorf("failed to get group: %w", err)
	}

	for _, op := range ops {
		if op.Op == "replace" && op.Path == "displayName" {
			if name, ok := op.Value.(string); ok {
				current.Name = name
			}
		}
	}

	if err := s.dirSvc.UpdateGroup(ctx, tenantID, id, current); err != nil {
		return Group{}, fmt.Errorf("failed to patch group: %w", err)
	}

	return s.GetGroup(ctx, tenantID, id)
}

// DeleteGroup handles DELETE /scim/v2/Groups/{id}.
func (s *Service) DeleteGroup(ctx context.Context, tenantID, id string) error {
	if err := s.dirSvc.DeleteGroup(ctx, tenantID, id); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	return nil
}
