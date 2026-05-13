package directory

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

// User represents a user in the system.
// User represents a user in the system.
type User struct {
	ID          string    `json:"id,omitempty" db:"id" validate:"omitempty,uuid"`
	TenantID    string    `json:"tenant_id,omitempty" db:"tenant_id" validate:"omitempty,uuid"`
	Email       string    `json:"email" db:"email" validate:"required,email"`
	DisplayName *string    `json:"display_name,omitempty" db:"display_name" validate:"omitempty"`
	Password    string    `json:"password,omitempty" db:"-" validate:"omitempty,min=8"` // Ignore password for db scan, normally not selected or manual
	Status      string    `json:"status,omitempty" db:"status" validate:"omitempty,oneof=active inactive suspended pending_deletion"`
	ExternalID   *string        `json:"external_id,omitempty" db:"external_id"`
	PhoneNumbers PhoneNumbers `json:"phone_numbers,omitempty" db:"phone_numbers"`
	Department   *string        `json:"department,omitempty" db:"department"`
	Title        *string        `json:"title,omitempty" db:"title"`
	Timezone     *string        `json:"timezone,omitempty" db:"timezone"`
	MFAEnforced  *bool          `json:"mfa_enforced" db:"mfa_enforced"`
	CreatedAt   time.Time `json:"created_at,omitempty" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

type PhoneNumber struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type PhoneNumbers []PhoneNumber

func (p *PhoneNumbers) Scan(value interface{}) error {
	if value == nil {
		*p = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, p)
}

func (p PhoneNumbers) Value() (driver.Value, error) {
	if len(p) == 0 {
		return nil, nil
	}
	return json.Marshal(p)
}

// Group represents a group in the system.
type Group struct {
	ID        string    `json:"id,omitempty" db:"id" validate:"omitempty,uuid"`
	TenantID  string    `json:"tenant_id,omitempty" db:"tenant_id" validate:"omitempty,uuid"`
	Name      string    `json:"name" db:"name" validate:"required"`
	CreatedAt time.Time `json:"created_at,omitempty" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

// HealthCheckResponse holds the response values for the HealthCheck endpoint.
type HealthCheckResponse struct {
	Healthy bool `json:"healthy"`
}

// CreateUserRequest holds the request parameters for the CreateUser endpoint.
type CreateUserRequest struct {
	User User `json:"user" validate:"required"`
}

// CreateUserResponse holds the response values for the CreateUser endpoint.
type CreateUserResponse struct {
	UserID string `json:"user_id"`
}

// GetUserByEmailRequest holds the request parameters for the GetUserByEmail endpoint.
type GetUserByEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// GetUserByEmailResponse holds the response values for the GetUserByEmail endpoint.
type GetUserByEmailResponse struct {
	User User `json:"user"`
}

// ListUsersRequest holds the request parameters for listing users.
type ListUsersRequest struct {
	Limit  int `form:"limit"`
	Offset int `form:"offset"`
}

// ListUsersResponse holds the response values for listing users.
type ListUsersResponse struct {
	Users []User `json:"users"`
	Total int    `json:"total"`
}

// GetUserByIDRequest holds the request parameters for the GetUserByID endpoint.
type GetUserByIDRequest struct {
	ID string `json:"id" validate:"required,uuid"`
}

// GetUserByIDResponse holds the response values for the GetUserByID endpoint.
type GetUserByIDResponse struct {
	User User `json:"user"`
}

// UpdateUserRequest holds the request parameters for the UpdateUser endpoint.
type UpdateUserRequest struct {
	ID   string `json:"id" validate:"required,uuid"`
	User User   `json:"user" validate:"required"`
}

// UpdateUserResponse holds the response values for the UpdateUser endpoint.
type UpdateUserResponse struct{}

// DeleteUserRequest holds the request parameters for the DeleteUser endpoint.
type DeleteUserRequest struct {
	ID string `json:"id" validate:"required,uuid"`
}

// DeleteUserResponse holds the response values for the DeleteUser endpoint.
type DeleteUserResponse struct{}

// CreateGroupRequest holds the request parameters for the CreateGroup endpoint.
type CreateGroupRequest struct {
	Group Group `json:"group" validate:"required"`
}

// CreateGroupResponse holds the response values for the CreateGroup endpoint.
type CreateGroupResponse struct {
	GroupID string `json:"group_id"`
}

// ListGroupsRequest holds the request parameters for listing groups.
type ListGroupsRequest struct {
	Limit  int `form:"limit"`
	Offset int `form:"offset"`
}

// ListGroupsResponse holds the response values for listing groups.
type ListGroupsResponse struct {
	Groups []Group `json:"groups"`
	Total  int     `json:"total"`
}

// GetGroupByIDRequest holds the request parameters for the GetGroupByID endpoint.
type GetGroupByIDRequest struct {
	ID string `json:"id" validate:"required,uuid"`
}

// GetGroupByIDResponse holds the response values for the GetGroupByID endpoint.
type GetGroupByIDResponse struct {
	Group Group `json:"group"`
}

// UpdateGroupRequest holds the request parameters for the UpdateGroup endpoint.
type UpdateGroupRequest struct {
	ID    string `json:"id" validate:"required,uuid"`
	Group Group  `json:"group" validate:"required"`
}

// UpdateGroupResponse holds the response values for the UpdateGroup endpoint.
type UpdateGroupResponse struct{}

// DeleteGroupRequest holds the request parameters for the DeleteGroup endpoint.
type DeleteGroupRequest struct {
	ID string `json:"id" validate:"required,uuid"`
}

// DeleteGroupResponse holds the response values for the DeleteGroup endpoint.
type DeleteGroupResponse struct{}

// AddUserToGroupRequest holds the request parameters for the AddUserToGroup endpoint.
type AddUserToGroupRequest struct {
	UserID  string `json:"user_id" validate:"required,uuid"`
	GroupID string `json:"group_id" validate:"required,uuid"`
}

// AddUserToGroupResponse holds the response values for the AddUserToGroup endpoint.
type AddUserToGroupResponse struct{}

// RemoveUserFromGroupRequest holds the request parameters for the RemoveUserFromGroup endpoint.
type RemoveUserFromGroupRequest struct {
	UserID  string `json:"user_id" validate:"required,uuid"`
	GroupID string `json:"group_id" validate:"required,uuid"`
}

// RemoveUserFromGroupResponse holds the response values for the RemoveUserFromGroup endpoint.
type RemoveUserFromGroupResponse struct{}

// ListGroupMembersResponse holds the response values for listing group members.
type ListGroupMembersResponse struct {
	Users []User `json:"users"`
}

// VerifyCredentialsRequest holds the request parameters for credential verification.
type VerifyCredentialsRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// VerifyCredentialsResponse holds the response values for credential verification.
type VerifyCredentialsResponse struct {
	User User `json:"user"`
}
