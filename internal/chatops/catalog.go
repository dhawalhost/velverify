package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dhawalhost/wardseal/internal/governance"
)

// CatalogService handles the visualization of corporate apps/resources in Slack.
type CatalogService struct {
	govSvc governance.Service
}

func NewCatalogService(govSvc governance.Service) *CatalogService {
	return &CatalogService{govSvc: govSvc}
}

// HandleCatalogCommand processes the /wardseal catalog slash command.
func (h *SlackHandler) HandleCatalogCommand(ctx context.Context, tenantID, triggerID string) error {
	// 1. Fetch Apps from Governance Service
	apps, err := h.govSvc.ListOAuthClients(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to list apps: %w", err)
	}

	// 2. Build Block-Kit Modal as a raw map
	blocks := []interface{}{
		map[string]interface{}{
			"type": "header",
			"text": map[string]interface{}{
				"type": "plain_text",
				"text": "WardSeal App Catalog",
			},
		},
		map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": "Search for corporate applications and request just-in-time access.",
			},
		},
		map[string]interface{}{"type": "divider"},
	}

	if len(apps) == 0 {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": "_No applications available for your organization yet._",
			},
		})
	} else {
		for _, app := range apps {
			blocks = append(blocks, map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*%s*\n%s", app.Name, app.Description.String),
				},
				"accessory": map[string]interface{}{
					"type":      "button",
					"action_id": "request_access_app:" + app.ClientID,
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "Request Access",
					},
					"value": app.ClientID,
				},
			})
		}
	}

	modal := map[string]interface{}{
		"trigger_id": triggerID,
		"view": map[string]interface{}{
			"type":   "modal",
			"title":  map[string]interface{}{"type": "plain_text", "text": "App Catalog"},
			"close":  map[string]interface{}{"type": "plain_text", "text": "Close"},
			"blocks": blocks,
		},
	}

	// 3. Resolve Slack client for this tenant
	config, err := h.repo.GetByTenant(ctx, tenantID)
	if err != nil {
		return err
	}

	// 4. Send to Slack views.open API
	payload, _ := json.Marshal(modal)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://slack.com/api/views.open", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+config.BotToken)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack API error: status %d", resp.StatusCode)
	}

	return nil
}
