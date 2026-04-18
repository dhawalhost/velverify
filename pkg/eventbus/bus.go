package eventbus

import "context"

// Event represents a generic event message traversing the event bus.
type Event struct {
	Topic   string
	Payload []byte
}

// Publisher defines the contract for sending events.
type Publisher interface {
	// Publish sends an event payload to the specified topic.
	Publish(ctx context.Context, topic string, payload []byte) error
}

// Handler defines the function signature for processing consumed events.
type Handler func(ctx context.Context, payload []byte) error

// Subscriber defines the contract for receiving events.
type Subscriber interface {
	// Subscribe registers a handler to consume events from a specific topic.
	Subscribe(ctx context.Context, topic string, handler Handler) error
}

// EventBus acts as a complete brokering interface combining Publisher and Subscriber logic,
// and allowing for graceful termination or connection drains.
type EventBus interface {
	Publisher
	Subscriber

	// Close gracefully shuts down the connection to the event bus system.
	Close() error
}
