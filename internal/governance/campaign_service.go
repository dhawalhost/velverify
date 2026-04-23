package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dhawalhost/wardseal/pkg/eventbus"
)

type CampaignService interface {
	SetGovernanceService(svc Service)
	CreateCampaign(ctx context.Context, tenantID string, input CreateCampaignInput) (Campaign, error)
	GetCampaign(ctx context.Context, tenantID, id string) (Campaign, error)
	ListCampaigns(ctx context.Context, tenantID, status string) ([]Campaign, error)
	StartCampaign(ctx context.Context, tenantID, id string) error
	CompleteCampaign(ctx context.Context, tenantID, id string) error
	CancelCampaign(ctx context.Context, tenantID, id string) error
	DeleteCampaign(ctx context.Context, tenantID, id string) error

	// Review items
	AddReviewItem(ctx context.Context, tenantID, campaignID string, item CertificationItem) (CertificationItem, error)
	ListPendingItems(ctx context.Context, campaignID string) ([]CertificationItem, error)
	ListReviewItems(ctx context.Context, tenantID, reviewerID string) ([]CertificationItem, error)
	ApproveItem(ctx context.Context, itemID, comment string) error
	RevokeItem(ctx context.Context, itemID, comment string) error

	// Automation
	GenerateRecertificationCampaign(ctx context.Context, tenantID, name string) error
}

type campaignService struct {
	store     CampaignRepository
	dirClient DirectoryClient
	bus       eventbus.EventBus
	govSvc    Service
}

// NewCampaignService creates a new campaign service.
func NewCampaignService(store CampaignRepository, dirClient DirectoryClient, bus eventbus.EventBus) CampaignService {
	s := &campaignService{store: store, dirClient: dirClient, bus: bus}
	// Note: govSvc will be set later to avoid circular initialization issues in main.go
	if bus != nil {
		s.initSubscriptions()
	}
	return s
}

func (s *campaignService) SetGovernanceService(svc Service) {
	s.govSvc = svc
}

func (s *campaignService) initSubscriptions() {
	_ = s.bus.Subscribe(context.Background(), "UserDeactivated", func(ctx context.Context, payload []byte) error {
		var event struct {
			TenantID string `json:"tenant_id"`
			UserID   string `json:"user_id"`
		}
		if err := json.Unmarshal(payload, &event); err != nil {
			return err
		}

		// One-Click Offboarding trigger (Safe Mode):
		// Fetch tracked access and propose a safety action in the DB.
		orgIDs, err := s.dirClient.ListUserOrganizations(ctx, event.TenantID, event.UserID)
		if err == nil && len(orgIDs) > 0 && s.govSvc != nil {
			metadata, _ := json.Marshal(map[string]interface{}{
				"org_ids": orgIDs,
			})
			_, _ = s.govSvc.ProposeSafetyAction(ctx, event.TenantID, ProposeSafetyActionInput{
				ActionType: "revoke_all_access",
				TargetID:   event.UserID,
				Metadata:   metadata,
				Reason:     "User deactivation safety check",
			})
		}

		// In a fully automated system, we might also auto-cancel or auto-revoke pending campaign items here.
		return nil
	})
}

func (s *campaignService) CreateCampaign(ctx context.Context, tenantID string, input CreateCampaignInput) (Campaign, error) {
	if input.Name == "" {
		return Campaign{}, fmt.Errorf("campaign name is required")
	}
	if input.ReviewerID == "" {
		return Campaign{}, fmt.Errorf("reviewer_id is required")
	}

	c := Campaign{
		TenantID:    tenantID,
		Name:        input.Name,
		Description: input.Description,
		ReviewerID:  input.ReviewerID,
		StartDate:   input.StartDate,
		EndDate:     input.EndDate,
	}

	id, err := s.store.CreateCampaign(ctx, c)
	if err != nil {
		return Campaign{}, fmt.Errorf("failed to create campaign: %w", err)
	}

	return s.store.GetCampaign(ctx, tenantID, id)
}

func (s *campaignService) GetCampaign(ctx context.Context, tenantID, id string) (Campaign, error) {
	return s.store.GetCampaign(ctx, tenantID, id)
}

func (s *campaignService) ListCampaigns(ctx context.Context, tenantID, status string) ([]Campaign, error) {
	return s.store.ListCampaigns(ctx, tenantID, status)
}

func (s *campaignService) StartCampaign(ctx context.Context, tenantID, id string) error {
	c, err := s.store.GetCampaign(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if c.Status != "draft" {
		return fmt.Errorf("can only start campaigns in draft status")
	}
	return s.store.UpdateCampaignStatus(ctx, id, "active")
}

func (s *campaignService) CompleteCampaign(ctx context.Context, tenantID, id string) error {
	c, err := s.store.GetCampaign(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if c.Status != "active" {
		return fmt.Errorf("can only complete active campaigns")
	}
	return s.store.UpdateCampaignStatus(ctx, id, "completed")
}

func (s *campaignService) CancelCampaign(ctx context.Context, tenantID, id string) error {
	return s.store.UpdateCampaignStatus(ctx, id, "cancelled")
}

func (s *campaignService) DeleteCampaign(ctx context.Context, tenantID, id string) error {
	return s.store.DeleteCampaign(ctx, tenantID, id)
}

func (s *campaignService) AddReviewItem(ctx context.Context, tenantID, campaignID string, item CertificationItem) (CertificationItem, error) {
	item.TenantID = tenantID
	item.CampaignID = campaignID

	id, err := s.store.CreateItem(ctx, item)
	if err != nil {
		return CertificationItem{}, fmt.Errorf("failed to add review item: %w", err)
	}
	item.ID = id
	return item, nil
}

func (s *campaignService) ListPendingItems(ctx context.Context, campaignID string) ([]CertificationItem, error) {
	return s.store.ListItems(ctx, campaignID, "")
}

func (s *campaignService) ListReviewItems(ctx context.Context, tenantID, reviewerID string) ([]CertificationItem, error) {
	return s.store.ListItemsByReviewer(ctx, tenantID, reviewerID)
}

func (s *campaignService) ApproveItem(ctx context.Context, itemID, comment string) error {
	return s.store.UpdateItemDecision(ctx, itemID, "approve", comment)
}

func (s *campaignService) RevokeItem(ctx context.Context, itemID, comment string) error {
	item, err := s.store.GetItem(ctx, itemID)
	if err != nil {
		return fmt.Errorf("failed to get item for revocation: %w", err)
	}

	if item.ResourceType == "group" && s.dirClient != nil {
		if err := s.dirClient.RemoveUserFromGroup(ctx, item.TenantID, item.UserID, item.ResourceID); err != nil {
			return fmt.Errorf("failed to revoke directory access: %w", err)
		}
	}

	return s.store.UpdateItemDecision(ctx, itemID, "revoke", comment)
}

func (s *campaignService) GenerateRecertificationCampaign(ctx context.Context, tenantID, name string) error {
	now := time.Now()
	endDate := now.AddDate(0, 0, 14) // 2 weeks review window

	// 1. Create the campaign
	campaign, err := s.CreateCampaign(ctx, tenantID, CreateCampaignInput{
		Name:        name,
		Description: "Auto-generated quarterly access review.",
		ReviewerID:  "admin", // Placeholder for actual security officer ID
		StartDate:   &now,
		EndDate:     &endDate,
	})
	if err != nil {
		return err
	}

	// 2. Fetch list of something to review (e.g. all users in the organization)
	// For MVP, we'll just log and assume items are added via other event hooks
	// or we could query dirClient here.

	return s.StartCampaign(ctx, tenantID, campaign.ID)
}
