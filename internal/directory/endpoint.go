package directory

// User represents a user in the system.
type User struct {
	ID        string `json:"id,omitempty" validate:"omitempty,uuid"`
	TenantID  string `json:"tenant_id,omitempty" validate:"omitempty,uuid"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password,omitempty" validate:"required,min=8"`
	Status    string `json:"status,omitempty" validate:"required,oneof=active inactive suspended"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Group represents a group in the system.
type Group struct {
	ID        string `json:"id,omitempty" validate:"omitempty,uuid"`
	TenantID  string `json:"tenant_id,omitempty" validate:"omitempty,uuid"`
	Name      string `json:"name" validate:"required"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
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

// VerifyCredentialsRequest holds the request parameters for credential verification.
type VerifyCredentialsRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// VerifyCredentialsResponse holds the response values for credential verification.
type VerifyCredentialsResponse struct {
	User User `json:"user"`
}
