package connector

import (
	"fmt"
	"sync"

	"github.com/dhawalhost/wardseal/internal/connector/scim"
	"github.com/dhawalhost/wardseal/internal/connector/slack"
)

// registry implements the Registry interface.
type registry struct {
	factories  map[string]Factory
	connectors map[string]Connector
	mu         sync.RWMutex
}

// NewRegistry creates a new connector registry with default factories.
func NewRegistry() Registry {
	r := &registry{
		factories:  make(map[string]Factory),
		connectors: make(map[string]Connector),
	}

	// Register default factories
	r.Register("scim", scim.New)
	r.Register("slack", slack.New)

	return r
}

func (r *registry) Register(connectorType string, factory Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[connectorType] = factory
}

func (r *registry) Create(connectorType string, config Config) (Connector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	factory, ok := r.factories[connectorType]
	if !ok {
		return nil, fmt.Errorf("unknown connector type: %s", connectorType)
	}

	conn, err := factory(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	r.connectors[config.ID] = conn
	return conn, nil
}

func (r *registry) Get(connectorID string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	conn, ok := r.connectors[connectorID]
	return conn, ok
}

func (r *registry) List() []Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Connector, 0, len(r.connectors))
	for _, c := range r.connectors {
		result = append(result, c)
	}
	return result
}

func (r *registry) Remove(connectorID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn, ok := r.connectors[connectorID]
	if !ok {
		return fmt.Errorf("connector not found: %s", connectorID)
	}

	if err := conn.Close(); err != nil {
		return fmt.Errorf("failed to close connector: %w", err)
	}

	delete(r.connectors, connectorID)
	return nil
}
