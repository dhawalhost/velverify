package scim

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dhawalhost/wardseal/internal/audit"
	"github.com/dhawalhost/wardseal/internal/directory"
)

// Service defines the business logic for SCIM operations.
type Service struct {
	dirSvc   directory.Service
	auditSvc audit.Service
}

// NewService creates a new SCIM service.
func NewService(dirSvc directory.Service, auditSvc audit.Service) *Service {
	return &Service{
		dirSvc:   dirSvc,
		auditSvc: auditSvc,
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
	if req.PrimaryEmail != "" {
		email = req.PrimaryEmail
	}
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
		Email:        email,
		DisplayName:  &req.DisplayName,
		Status:       "active",
		Password:     password,
		ExternalID:   &req.ExternalID,
		PhoneNumbers: mapSCIMPhonesToDir(req.PhoneNumbers),
		Department:   &req.Department,
		Title:        &req.Title,
		Timezone:     &req.Timezone,
	}
	if !req.Active {
		dirUser.Status = "inactive"
	}

	id, err := s.dirSvc.CreateUser(ctx, tenantID, dirUser)
	if err != nil {
		return User{}, fmt.Errorf("failed to create user: %w", err)
	}

	// Process Group Memberships
	for _, g := range req.Groups {
		if g.Value != "" {
			_ = s.dirSvc.AddUserToGroup(ctx, tenantID, id, g.Value)
		}
	}

	req.ID = id
	req.Meta = Meta{
		ResourceType: "User",
		Created:      time.Now().Format(time.RFC3339),
		LastModified: time.Now().Format(time.RFC3339),
		Location:     fmt.Sprintf("/scim/v2/Users/%s", id),
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.LogInput{
			TenantID:     tenantID,
			Action:       "scim.user.create",
			ResourceType: "user",
			ResourceID:   &id,
			ResourceName: &email,
			Outcome:      "success",
			Details: map[string]interface{}{
				"userName": req.UserName,
				"active":   req.Active,
				"groups":   len(req.Groups),
			},
		})
	}

	req.Password = ""
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

	groups, _ := s.dirSvc.ListUserGroups(ctx, tenantID, id)
	scimGroups := make([]GroupRef, 0, len(groups))
	for _, g := range groups {
		scimGroups = append(scimGroups, GroupRef{
			Value:   g.ID,
			Display: g.Name,
		})
	}

	return User{
		Schemas:     []string{UserSchema},
		ID:          u.ID,
		UserName:    u.Email,
		DisplayName: stringValue(u.DisplayName),
		ExternalID:  stringValue(u.ExternalID),
		Active:      u.Status == "active",
		Emails: []Email{
			{Value: u.Email, Type: "work", Primary: true},
		},
		PhoneNumbers: mapDirPhonesToSCIM(u.PhoneNumbers),
		Department:   stringValue(u.Department),
		Title:        stringValue(u.Title),
		Timezone:     stringValue(u.Timezone),
		Groups:       scimGroups,
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

	// Handle basic filtering (e.g., userName eq "john@example.com")
	if filter != "" {
		attr, val, ok := parseFilter(filter)
		if ok && strings.EqualFold(attr, "userName") {
			u, err := s.dirSvc.GetUserByEmail(ctx, tenantID, val)
			if err != nil {
				// SCIM expects an empty list for filter misses, not an error
				return ListResponse{
					Schemas:      []string{ListSchema},
					TotalResults: 0,
					StartIndex:   startIndex,
					Resources:    []interface{}{},
				}, err
			}
			scimUser := s.mapToSCIMUser(ctx, tenantID, u)
			return ListResponse{
				Schemas:      []string{ListSchema},
				TotalResults: 1,
				StartIndex:   1,
				ItemsPerPage: 1,
				Resources:    []interface{}{scimUser},
			}, nil
		}
	}

	users, total, err := s.dirSvc.ListUsers(ctx, tenantID, count, offset)
	if err != nil {
		return ListResponse{}, fmt.Errorf("failed to list users: %w", err)
	}

	// Convert to SCIM Users
	resources := make([]interface{}, 0, len(users))
	for _, u := range users {
		resources = append(resources, s.mapToSCIMUser(ctx, tenantID, u))
	}

	return ListResponse{
		Schemas:      []string{ListSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}, nil
}

var filterRegex = regexp.MustCompile(`(?i)(\w+)\s+eq\s+"([^"]+)"`)

func parseFilter(filter string) (string, string, bool) {
	matches := filterRegex.FindStringSubmatch(filter)
	if len(matches) == 3 {
		return matches[1], matches[2], true
	}
	return "", "", false
}

func (s *Service) mapToSCIMUser(ctx context.Context, tenantID string, u directory.User) User {
	groups, _ := s.dirSvc.ListUserGroups(ctx, tenantID, u.ID)
	scimGroups := make([]GroupRef, 0, len(groups))
	for _, g := range groups {
		scimGroups = append(scimGroups, GroupRef{
			Value:   g.ID,
			Display: g.Name,
		})
	}

	return User{
		Schemas:     []string{UserSchema},
		ID:          u.ID,
		UserName:    u.Email,
		DisplayName: stringValue(u.DisplayName),
		ExternalID:  stringValue(u.ExternalID),
		Active:      u.Status == "active",
		Emails: []Email{
			{Value: u.Email, Type: "work", Primary: true},
		},
		PhoneNumbers: mapDirPhonesToSCIM(u.PhoneNumbers),
		Department:   stringValue(u.Department),
		Title:        stringValue(u.Title),
		Timezone:     stringValue(u.Timezone),
		Groups:       scimGroups,
		Meta: Meta{
			ResourceType: "User",
			Created:      u.CreatedAt.Format(time.RFC3339),
			LastModified: u.UpdatedAt.Format(time.RFC3339),
			Location:     fmt.Sprintf("/scim/v2/Users/%s", u.ID),
		},
	}
}

func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ReplaceUser handles PUT /scim/v2/Users/{id} - full replacement.
func (s *Service) ReplaceUser(ctx context.Context, tenantID, id string, req User) (User, error) {
	// Map SCIM User to directory User
	email := req.UserName
	if req.PrimaryEmail != "" {
		email = req.PrimaryEmail
	}
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
		Email:        email,
		DisplayName:  &req.DisplayName,
		Status:       status,
		Password:     req.Password,
		ExternalID:   &req.ExternalID,
		PhoneNumbers: mapSCIMPhonesToDir(req.PhoneNumbers),
		Department:   &req.Department,
		Title:        &req.Title,
		Timezone:     &req.Timezone,
	}

	if err := s.dirSvc.UpdateUser(ctx, tenantID, id, dirUser); err != nil {
		return User{}, fmt.Errorf("failed to update user: %w", err)
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.LogInput{
			TenantID:     tenantID,
			Action:       "scim.user.update",
			ResourceType: "user",
			ResourceID:   &id,
			ResourceName: &email,
			Outcome:      "success",
		})
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
			case "password":
				if password, ok := op.Value.(string); ok {
					current.Password = password
				}
			case "displayName":
				if displayName, ok := op.Value.(*string); ok {
					current.DisplayName = displayName
				}
			case "externalId":
				if externalID, ok := op.Value.(*string); ok {
					current.ExternalID = externalID
				}
			case "title":
				if title, ok := op.Value.(*string); ok {
					current.Title = title
				}
			case "department":
				if department, ok := op.Value.(*string); ok {
					current.Department = department
				}
			case "timezone":
				if timezone, ok := op.Value.(*string); ok {
					current.Timezone = timezone
				}
			}
		}
	}

	// Persist changes
	if err := s.dirSvc.UpdateUser(ctx, tenantID, id, current); err != nil {
		return User{}, fmt.Errorf("failed to patch user: %w", err)
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.LogInput{
			TenantID:     tenantID,
			Action:       "scim.user.patch",
			ResourceType: "user",
			ResourceID:   &id,
			ResourceName: &current.Email,
			Outcome:      "success",
			Details:      map[string]interface{}{"ops_count": len(ops)},
		})
	}

	return s.GetUser(ctx, tenantID, id)
}

// DeleteUser handles DELETE /scim/v2/Users/{id}.
func (s *Service) DeleteUser(ctx context.Context, tenantID, id string) error {
	if err := s.dirSvc.DeleteUser(ctx, tenantID, id); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.LogInput{
			TenantID:     tenantID,
			Action:       "scim.user.delete",
			ResourceType: "user",
			ResourceID:   &id,
			Outcome:      "success",
		})
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

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.LogInput{
			TenantID:     tenantID,
			Action:       "scim.group.create",
			ResourceType: "group",
			ResourceID:   &id,
			ResourceName: &req.DisplayName,
			Outcome:      "success",
		})
	}

	return s.GetGroup(ctx, tenantID, id)
}

// GetGroup retrieves a SCIM group by ID.
func (s *Service) GetGroup(ctx context.Context, tenantID, id string) (Group, error) {
	g, err := s.dirSvc.GetGroupByID(ctx, tenantID, id)
	if err != nil {
		return Group{}, fmt.Errorf("failed to get group: %w", err)
	}

	// Fetch members
	members, err := s.dirSvc.ListGroupMembers(ctx, tenantID, id)
	if err != nil {
		// Non-critical, just log it? For now, proceed with empty members
		members = []directory.User{}
	}

	scimMembers := make([]Member, 0, len(members))
	for _, m := range members {
		scimMembers = append(scimMembers, Member{
			Value:   m.ID,
			Display: m.Email,
			Type:    "User",
		})
	}

	return Group{
		Schemas:     []string{GroupSchema},
		ID:          g.ID,
		DisplayName: g.Name,
		Members:     scimMembers,
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

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.LogInput{
			TenantID:     tenantID,
			Action:       "scim.group.replace",
			ResourceType: "group",
			ResourceID:   &id,
			ResourceName: &req.DisplayName,
			Outcome:      "success",
		})
	}

	return s.GetGroup(ctx, tenantID, id)
}

// PatchGroup handles PATCH /scim/v2/Groups/{id}.
func (s *Service) PatchGroup(ctx context.Context, tenantID, id string, ops []PatchOperation) (Group, error) {
	for _, op := range ops {
		switch op.Op {
		case "replace":
			if op.Path == "displayName" {
				if name, ok := op.Value.(string); ok {
					_ = s.dirSvc.UpdateGroup(ctx, tenantID, id, directory.Group{Name: name})
					if s.auditSvc != nil {
						_ = s.auditSvc.Log(ctx, audit.LogInput{
							TenantID:     tenantID,
							Action:       "scim.group.update",
							ResourceType: "group",
							ResourceID:   &id,
							ResourceName: &name,
							Outcome:      "success",
						})
					}
				}
			}
		case "add":
			// SCIM 'add' members
			if op.Path == "members" || op.Path == "" {
				if members, ok := op.Value.([]interface{}); ok {
					for _, m := range members {
						if mv, ok := m.(map[string]interface{}); ok {
							if val, ok := mv["value"].(string); ok {
								_ = s.dirSvc.AddUserToGroup(ctx, tenantID, val, id)
								if s.auditSvc != nil {
									_ = s.auditSvc.Log(ctx, audit.LogInput{
										TenantID:     tenantID,
										Action:       "scim.group.membership_add",
										ResourceType: "group",
										ResourceID:   &id,
										Details:      map[string]interface{}{"user_id": val},
										Outcome:      "success",
									})
								}
							}
						}
					}
				}
			}
		case "remove":
			// SCIM 'remove' members
			// Format: Members[value eq "id"]
			if op.Path != "" {
				// Very basic parsing for Members[value eq "id"]
				if strings.Contains(op.Path, "value eq") {
					parts := strings.Split(op.Path, "\"")
					if len(parts) >= 2 {
						userID := parts[1]
						_ = s.dirSvc.RemoveUserFromGroup(ctx, tenantID, userID, id)
						if s.auditSvc != nil {
							_ = s.auditSvc.Log(ctx, audit.LogInput{
								TenantID:     tenantID,
								Action:       "scim.group.membership_remove",
								ResourceType: "group",
								ResourceID:   &id,
								Details:      map[string]interface{}{"user_id": userID},
								Outcome:      "success",
							})
						}
					}
				}
			}
		}
	}

	return s.GetGroup(ctx, tenantID, id)
}

// DeleteGroup handles DELETE /scim/v2/Groups/{id}.
func (s *Service) DeleteGroup(ctx context.Context, tenantID, id string) error {
	if err := s.dirSvc.DeleteGroup(ctx, tenantID, id); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.LogInput{
			TenantID:     tenantID,
			Action:       "scim.group.delete",
			ResourceType: "group",
			ResourceID:   &id,
			Outcome:      "success",
		})
	}

	return nil
}

func mapSCIMPhonesToDir(scimPhones []PhoneNumber) directory.PhoneNumbers {
	if len(scimPhones) == 0 {
		return nil
	}
	var dirPhones directory.PhoneNumbers
	for _, p := range scimPhones {
		dirPhones = append(dirPhones, directory.PhoneNumber{
			Value:   p.Value,
			Type:    p.Type,
			Primary: p.Primary,
		})
	}
	return dirPhones
}

func mapDirPhonesToSCIM(dirPhones directory.PhoneNumbers) []PhoneNumber {
	if len(dirPhones) == 0 {
		return nil
	}
	var scimPhones []PhoneNumber
	for _, p := range dirPhones {
		scimPhones = append(scimPhones, PhoneNumber{
			Value:   p.Value,
			Type:    p.Type,
			Primary: p.Primary,
		})
	}
	return scimPhones
}
