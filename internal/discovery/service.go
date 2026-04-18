package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dhawalhost/wardseal/internal/connector"
	"github.com/dhawalhost/wardseal/pkg/eventbus"
	"go.uber.org/zap"
)

// DiscoveredResource represents a resource found by a scanner.
type DiscoveredResource struct {
	ID               string                 `json:"id" db:"id"`
	TenantID         string                 `json:"tenant_id" db:"tenant_id"`
	ConnectorID      string                 `json:"connector_id" db:"connector_id"`
	Type             string                 `json:"type" db:"type"`
	Name             string                 `json:"name" db:"name"`
	ExternalID       string                 `json:"external_id" db:"external_id"`
	Metadata         map[string]interface{} `json:"metadata" db:"metadata"`
	Status           string                 `json:"status" db:"status"`
	LastDiscoveredAt time.Time              `json:"last_discovered_at" db:"last_discovered_at"`
}

// Repository defines the storage interface for discovered resources.
type Repository interface {
	Upsert(ctx context.Context, r DiscoveredResource) error
	List(ctx context.Context, tenantID string, filter string) ([]DiscoveredResource, error)
}

// Service manages the resource discovery lifecycle.
type Service interface {
	Start(ctx context.Context)
	RunDiscovery(ctx context.Context, tenantID string) error
	RunDiscoveryJob(ctx context.Context, jobID, tenantID string) error
}

type discoveryService struct {
	repo       Repository
	jobs       JobStore
	registry   connector.Registry
	subscriber eventbus.Subscriber
	log        *zap.Logger
}

func NewService(repo Repository, jobs JobStore, registry connector.Registry, sub eventbus.Subscriber, log *zap.Logger) Service {
	return &discoveryService{
		repo:       repo,
		jobs:       jobs,
		registry:   registry,
		subscriber: sub,
		log:        log,
	}
}

func (s *discoveryService) Start(ctx context.Context) {
	s.log.Info("Starting resource discovery background worker")

	// 1. Subscribe to scan requested events
	if s.subscriber != nil {
		err := s.subscriber.Subscribe(ctx, TopicDiscoveryScanRequested, func(ctx context.Context, payload []byte) error {
			var event ScanRequestedEvent
			if err := json.Unmarshal(payload, &event); err != nil {
				s.log.Error("Failed to unmarshal discovery event", zap.Error(err))
				return nil // Don't retry malformed events
			}

			// Run the job in a background goroutine to not block the subscriber
			go func() {
				// Use a fresh context for the background job
				jobCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				
				if err := s.RunDiscoveryJob(jobCtx, event.JobID, event.TenantID); err != nil {
					s.log.Error("Discovery job failed", 
						zap.String("job_id", event.JobID), 
						zap.String("tenant_id", event.TenantID), 
						zap.Error(err))
				}
			}()

			return nil
		})

		if err != nil {
			s.log.Error("Failed to subscribe to discovery events", zap.Error(err))
		} else {
			s.log.Info("Discovery event subscription active")
		}
	}

	// 2. Scheduled global discovery (Legacy sweep)
	ticker := time.NewTicker(12 * time.Hour)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.log.Info("Running scheduled global resource discovery sweep...")
				// In a full implementation, we would iterate tenants here.
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *discoveryService) RunDiscovery(ctx context.Context, tenantID string) error {
	// Legacy synchronous wrapper
	return s.RunDiscoveryJob(ctx, "legacy-sync-run", tenantID)
}

func (s *discoveryService) RunDiscoveryJob(ctx context.Context, jobID, tenantID string) error {
	s.log.Info("Processing discovery job", zap.String("job_id", jobID), zap.String("tenant_id", tenantID))

	// Update status to processing
	_ = s.jobs.Update(ctx, jobID, func(state *JobState) {
		state.Status = JobStatusProcessing
		state.Progress = 5
		state.Message = "Scanning infrastructure connectors..."
	})

	connectors := s.registry.List()
	totalConnectors := len(connectors)
	processedCount := 0

	if totalConnectors == 0 {
		_ = s.jobs.Update(ctx, jobID, func(state *JobState) {
			state.Status = JobStatusCompleted
			state.Progress = 100
			state.Message = "No connectors identified for this tenant."
			now := time.Now()
			state.FinishedAt = &now
		})
		return nil
	}

	for _, c := range connectors {
		s.log.Debug("Querying connector", zap.String("connector_id", c.ID()), zap.String("job_id", jobID))

		resources, err := c.DiscoverResources(ctx)
		if err != nil {
			s.log.Warn("Connector discovery failed", 
				zap.String("connector_id", c.ID()), 
				zap.Error(err))
		} else {
			for _, res := range resources {
				// Convert map[string]string to map[string]interface{} for metadata
				metadata := make(map[string]interface{})
				for k, v := range res.Metadata {
					metadata[k] = v
				}

				dr := DiscoveredResource{
					TenantID:         tenantID,
					ConnectorID:      c.ID(),
					Type:             res.Type,
					Name:             res.Name,
					ExternalID:       res.ExternalID,
					Metadata:         metadata,
					Status:           "discovered",
					LastDiscoveredAt: time.Now(),
				}
				if err := s.repo.Upsert(ctx, dr); err != nil {
					s.log.Error("Failed to store discovered resource", zap.Error(err))
				}
			}
		}

		processedCount++
		progress := 5 + int((float64(processedCount)/float64(totalConnectors))*90)
		_ = s.jobs.Update(ctx, jobID, func(state *JobState) {
			state.Progress = progress
			state.Message = fmt.Sprintf("Processed %d/%d connectors...", processedCount, totalConnectors)
		})
	}

	// Finalize Job
	now := time.Now()
	err := s.jobs.Update(ctx, jobID, func(state *JobState) {
		state.Status = JobStatusCompleted
		state.Progress = 100
		state.Message = fmt.Sprintf("Discovery complete. Detected resources across %d connectors.", totalConnectors)
		state.FinishedAt = &now
	})

	return err
}
