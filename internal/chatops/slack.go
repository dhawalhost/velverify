package chatops

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dhawalhost/wardseal/internal/governance"
	"go.uber.org/zap"
)

// SlackHandler handles incoming Slack slash commands and interactions.
type SlackHandler struct {
	govSvc governance.Service
	dirSvc governance.DirectoryClient
	repo   Repository
	log    *zap.Logger
	client *http.Client
	uiURL  string
	env    string
}

// NewSlackHandler creates a new SlackHandler with dynamic repository lookups.
func NewSlackHandler(govSvc governance.Service, dirSvc governance.DirectoryClient, repo Repository, uiURL string, env string, log *zap.Logger) *SlackHandler {
	return &SlackHandler{
		govSvc: govSvc,
		dirSvc: dirSvc,
		repo:   repo,
		log:    log,
		client: &http.Client{Timeout: 10 * time.Second},
		uiURL:  uiURL,
		env:    env,
	}
}

// HandleCommand processes slash commands like /wardseal request <app>
func (h *SlackHandler) HandleCommand(w http.ResponseWriter, r *http.Request) {
	// 1. Capture raw body for signature verification
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read request body", http.StatusInternalServerError)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body)) // Restore body for ParseForm

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	teamID := r.FormValue("team_id")
	if teamID == "" {
		http.Error(w, "missing team_id", http.StatusBadRequest)
		return
	}

	// Dynamic lookup of tenant configuration
	integ, err := h.repo.GetByTeamID(r.Context(), teamID)
	if err != nil || !integ.IsEnabled {
		msg := "Slack integration is not configured or disabled for this workspace."
		if err != nil {
			h.log.Error("Failed to lookup slack integration", zap.String("team_id", teamID), zap.Error(err))
		}
		h.sendEphemeralResponse(w, msg)
		return
	}

	// 2. CRYPTOGRAPHIC VERIFICATION
	if err := h.verifySignature(r, body, integ.SigningSecret); err != nil {
		h.log.Warn("invalid slack signature received", zap.String("team_id", teamID), zap.Error(err))
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	command := r.FormValue("command")
	text := r.FormValue("text")
	userID := r.FormValue("user_id")
	tenantID := r.Header.Get("X-Tenant-ID")

	if tenantID == "" {
		tenantID = "default" 
	}

	h.log.Info("received slack command", 
		zap.String("command", command),
		zap.String("text", text),
		zap.String("user", userID),
	)

	parts := strings.Fields(text)
	if len(parts) < 2 || parts[0] != "request" {
		h.sendEphemeralResponse(w, "Usage: `/wardseal request <app_name> [reason]`")
		return
	}

	appName := parts[1]
	reason := "Requested via Slack"
	if len(parts) > 2 {
		reason = strings.Join(parts[2:], " ")
	}

	// PROACTIVE ENHANCEMENT: If the app name is 'any' or vague, we could list options.
	// For now, we'll try to find a match.
	
	// Create access request in governance service
	req, err := h.govSvc.CreateAccessRequest(r.Context(), tenantID, governance.CreateAccessRequest{
		RequesterID:  userID,
		ResourceType: "app",
		ResourceID:   appName,
		Reason:       reason,
	})
	if err != nil {
		h.sendEphemeralResponse(w, fmt.Sprintf("❌ *Request Failed:* We couldn't find or request access to '%s'.\n_Hint: Try the exact app name from your dashboard._", appName))
		return
	}

	resp := map[string]interface{}{
		"response_type": "ephemeral",
		"blocks": []interface{}{
			map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("✅ *Access Request Created*\n*Resource:* %s\n*Reason:* %s\n*Request ID:* `%s`", appName, reason, req.ID),
				},
			},
		},
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *SlackHandler) sendEphemeralResponse(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"response_type": "ephemeral",
		"text":          text,
	})
}

// HandleInteraction processes button clicks from Slack.
func (h *SlackHandler) HandleInteraction(w http.ResponseWriter, r *http.Request) {
	// 1. Capture raw body for signature verification
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read request body", http.StatusInternalServerError)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body)) // Restore body for ParseForm

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	payloadRaw := r.FormValue("payload")
	if payloadRaw == "" {
		http.Error(w, "missing payload", http.StatusBadRequest)
		return
	}

	var payload struct {
		Type string `json:"type"`
		Team struct {
			ID string `json:"id"`
		} `json:"team"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Actions []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
	}

	if err := json.Unmarshal([]byte(payloadRaw), &payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	teamID := payload.Team.ID
	if teamID == "" {
		http.Error(w, "missing team_id in interaction", http.StatusBadRequest)
		return
	}

	// Dynamic lookup
	integ, err := h.repo.GetByTeamID(r.Context(), teamID)
	if err != nil || !integ.IsEnabled {
		h.log.Warn("interaction received for unconfigured slack team", zap.String("team_id", teamID))
		return
	}

	// 2. CRYPTOGRAPHIC VERIFICATION
	if err := h.verifySignature(r, body, integ.SigningSecret); err != nil {
		h.log.Warn("invalid slack signature received", zap.String("team_id", teamID), zap.Error(err))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if len(payload.Actions) == 0 {
		return
	}

	action := payload.Actions[0]
	requestID := action.Value
	approverID := payload.User.ID
	tenantID := integ.TenantID 

	h.log.Info("received slack interaction", 
		zap.String("tenant", tenantID),
		zap.String("action", action.ActionID),
		zap.String("request_id", requestID),
		zap.String("approver", approverID),
	)

	msg := ""
	switch action.ActionID {
	case "approve_request":
		err = h.govSvc.ApproveAccessRequest(r.Context(), tenantID, requestID, approverID, "Approved via Slack")
		msg = "Approved"
	case "reject_request":
		err = h.govSvc.RejectAccessRequest(r.Context(), tenantID, requestID, approverID, "Rejected via Slack")
		msg = "Rejected"
	case "confirm_offboard":
		err = h.govSvc.ConfirmSafetyAction(r.Context(), tenantID, action.Value, approverID, "Approved via Slack")
		if err == nil {
			msg = "User Offboarding Confirmed"
		}
	case "ignore_offboard":
		err = h.govSvc.RejectSafetyAction(r.Context(), tenantID, action.Value, approverID, "Rejected via Slack")
		if err == nil {
			msg = "User Offboarding Cancelled (Access Retained)"
		}
	}

	if err != nil {
		h.sendEphemeralResponse(w, fmt.Sprintf("Error processing %s: %v", action.ActionID, err))
		return
	}

	h.sendEphemeralResponse(w, fmt.Sprintf("Action processed: %s", msg))
}

// NotifyProposedRevocation sends a Slack message with interactive blocks.
func (h *SlackHandler) NotifyProposedRevocation(ctx context.Context, action governance.SafetyAction) error {
	integ, err := h.repo.GetByTenant(ctx, action.TenantID)
	if err != nil || !integ.IsEnabled {
		return nil // Not integrated or error
	}

	user, err := h.dirSvc.GetUserByID(ctx, action.TenantID, action.TargetID)
	userEmail := action.TargetID
	if err == nil {
		userEmail = user.Email
	}

	safetyURL := fmt.Sprintf("%s/safety", h.uiURL)

	blocks := []interface{}{
		map[string]interface{}{
			"type": "header",
			"text": map[string]interface{}{
				"type": "plain_text",
				"text": "🛡️ WardSeal Safety Alert",
				"emoji": true,
			},
		},
		map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Manual Revocation Required*\nSystem identified a high-risk security event in the *%s* environment.", h.env),
			},
		},
		map[string]interface{}{
			"type": "section",
			"fields": []interface{}{
				map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*User:*\n%s", userEmail),
				},
				map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Action:*\n%s", action.ActionType),
				},
				map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Trigger:*\n%s", action.Reason),
				},
				map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Status:*\n`Pending Confirmation`"),
				},
			},
		},
		map[string]interface{}{
			"type": "actions",
			"elements": []interface{}{
				map[string]interface{}{
					"type": "button",
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "✅ Approve & Revoke",
					},
					"style":     "danger",
					"action_id": "confirm_offboard",
					"value":     action.ID,
					"confirm": map[string]interface{}{
						"title": map[string]interface{}{"type": "plain_text", "text": "Are you sure?"},
						"text":  map[string]interface{}{"type": "plain_text", "text": "This will immediately revoke all organizational access for this user."},
						"confirm": map[string]interface{}{"type": "plain_text", "text": "Revoke Access"},
						"deny":    map[string]interface{}{"type": "plain_text", "text": "Cancel"},
					},
				},
				map[string]interface{}{
					"type": "button",
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "❌ Keep Access",
					},
					"action_id": "ignore_offboard",
					"value":     action.ID,
				},
				map[string]interface{}{
					"type": "button",
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "🌐 View in Dashboard",
					},
					"url": safetyURL,
				},
			},
		},
		map[string]interface{}{
			"type": "context",
			"elements": []interface{}{
				map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("Action ID: `%s` | Timestamp: %s", action.ID, time.Now().Format(time.RFC822)),
				},
			},
		},
	}

	payload := map[string]interface{}{
		"blocks": blocks,
	}

	if integ.WebhookURL == "" {
		h.log.Warn("Slack is enabled but no WebhookURL configured for tenant. Logging payload only.", 
			zap.String("tenant_id", action.TenantID),
			zap.String("action_id", action.ID))
		payloadJSON, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Printf("[SLACK SIMULATION] Tenant: %s | Payload:\n%s\n", action.TenantID, string(payloadJSON))
		return nil
	}

	// Real Webhook Post
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", integ.WebhookURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned non-200 status: %d", resp.StatusCode)
	}

	return nil
}

// NotifyAccessAvailable pushes a proactive suggestion to a user when new matching resources are found.
func (h *SlackHandler) NotifyAccessAvailable(ctx context.Context, tenantID, slackUserID, resourceName, reason string) error {
	integ, err := h.repo.GetByTenant(ctx, tenantID)
	if err != nil || !integ.IsEnabled {
		return nil
	}

	blocks := []interface{}{
		map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("👋 *New Access Available!*\nWe noticed you might need access to *%s* for your role.\n_%s_", resourceName, reason),
			},
		},
		map[string]interface{}{
			"type": "actions",
			"elements": []interface{}{
				map[string]interface{}{
					"type": "button",
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "Request Access",
					},
					"style":     "primary",
					"action_id": "request_suggested_access",
					"value":     resourceName,
				},
				map[string]interface{}{
					"type": "button",
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "Dismiss",
					},
					"action_id": "dismiss_suggestion",
				},
			},
		},
	}

	payload := map[string]interface{}{
		"channel": slackUserID, // Direct message to user
		"blocks":  blocks,
	}

	// Post to Slack API (using a hypothetical 'chat.postMessage' endpoint logic)
	// In a real implementation we would use a Bot Token.
	h.log.Info("sending proactive access notification", zap.String("user", slackUserID), zap.String("resource", resourceName))
	
	// Simulation for now
	payloadJSON, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Printf("[SLACK PROACTIVE] To: %s | Payload:\n%s\n", slackUserID, string(payloadJSON))
	
	return nil
}
func (h *SlackHandler) verifySignature(r *http.Request, body []byte, secret string) error {
	signature := r.Header.Get("X-Slack-Signature")
	timestamp := r.Header.Get("X-Slack-Request-Timestamp")

	if signature == "" || timestamp == "" {
		return fmt.Errorf("missing slack signature headers")
	}

	// Prevent replay attacks (5 minute window)
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp")
	}
	if time.Now().Unix()-ts > 300 {
		return fmt.Errorf("timestamp too old (replay attack?)")
	}

	// Construction base string: v0:timestamp:payload
	baseString := fmt.Sprintf("v0:%s:%s", timestamp, string(body))
	
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}
