package connector

import (
	"context"

	"github.com/dhawalhost/wardseal/internal/connector/model"
)

// Re-export types from model as aliases for backward compatibility and convenience.
type Connector = model.Connector
type Config = model.Config
type User = model.User
type Resource = model.Resource
type Group = model.Group
type ProvisioningTask = model.ProvisioningTask
type Factory = model.Factory

// Registry manages connector instances.
type Registry interface {
	Register(connectorType string, factory Factory)
	Create(connectorType string, config Config) (Connector, error)
	Get(connectorID string) (Connector, bool)
	List() []Connector
	Remove(connectorID string) error
}

// ProvisioningService manages async provisioning tasks.
type ProvisioningService interface {
	EnqueueTask(ctx context.Context, task ProvisioningTask) (string, error)
	Start(ctx context.Context)
	ExecuteTask(ctx context.Context, taskID string) error
}
