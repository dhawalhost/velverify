package connector

import (
	"context"
	"time"
)

// Connector defines the interface that all identity connectors must implement.
// This enables pluggable integrations with external identity systems like
// Active Directory, Azure AD, Google Workspace, etc.
type Connector interface {
	// Metadata
	ID() string
	Name() string
	Type() string // ldap, scim, graph, etc.

	// Lifecycle
	Initialize(ctx context.Context, config Config) error
	HealthCheck(ctx context.Context) error
	Close() error

	// User operations
	CreateUser(ctx context.Context, user User) (string, error)
	GetUser(ctx context.Context, id string) (User, error)
	UpdateUser(ctx context.Context, id string, user User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, filter string, limit, offset int) ([]User, int, error)

	// Group operations
	CreateGroup(ctx context.Context, group Group) (string, error)
	GetGroup(ctx context.Context, id string) (Group, error)
	UpdateGroup(ctx context.Context, id string, group Group) error
	DeleteGroup(ctx context.Context, id string) error
	ListGroups(ctx context.Context, filter string, limit, offset int) ([]Group, int, error)

	// Group membership
	AddUserToGroup(ctx context.Context, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID string) error
	// Discovery
	DiscoverResources(ctx context.Context) ([]Resource, error)
}

// Config holds connector configuration.
type Config struct {
	ID          string            `json:"id" db:"id"`
	TenantID    string            `json:"tenant_id" db:"tenant_id"`
	Name        string            `json:"name" db:"name"`
	Type        string            `json:"type" db:"type"` // ldap, azure-ad, google, scim
	Enabled     bool              `json:"enabled" db:"enabled"`
	Endpoint    string            `json:"endpoint" db:"endpoint"`
	Credentials map[string]string `json:"credentials" db:"-"` // Encrypted at rest
	Settings    map[string]string `json:"settings" db:"-"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
}

// User represents a user in an external system.
type User struct {
	ExternalID  string            `json:"external_id"`
	InternalID  string            `json:"internal_id,omitempty"` // WardSeal user ID
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	DisplayName string            `json:"display_name,omitempty"`
	Active      bool              `json:"active"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// Resource represents a discovered asset in an external system.
type Resource struct {
	ExternalID string            `json:"external_id"`
	Type       string            `json:"type"` // app, server, group, ou
	Name       string            `json:"name"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Group represents a group in an external system.
type Group struct {
	ExternalID  string `json:"external_id"`
	InternalID  string `json:"internal_id,omitempty"` // WardSeal group ID
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ProvisioningTask represents an async provisioning job.
type ProvisioningTask struct {
	ID           string      `json:"id"`
	TenantID     string      `json:"tenant_id"`
	ConnectorID  string      `json:"connector_id"`
	Operation    string      `json:"operation"` // create_user, delete_user, add_to_group, etc.
	ResourceType string      `json:"resource_type"`
	ResourceID   string      `json:"resource_id"`
	Payload      interface{} `json:"payload"`
	Status       string      `json:"status"` // pending, processing, completed, failed
	ErrorMessage string      `json:"error_message,omitempty"`
	RetryCount   int         `json:"retry_count"`
	MaxRetries   int         `json:"max_retries"`
	CreatedAt    time.Time   `json:"created_at"`
	ProcessedAt  *time.Time  `json:"processed_at,omitempty"`
}

// Registry manages connector instances.
type Registry interface {
	Register(connectorType string, factory Factory)
	Create(connectorType string, config Config) (Connector, error)
	Get(connectorID string) (Connector, bool)
	List() []Connector
	Remove(connectorID string) error
}

// Factory creates connector instances.
type Factory func(config Config) (Connector, error)
