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

	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/internal/governance"
	"github.com/dhawalhost/wardseal/pkg/llm"
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
	llm    llm.Provider
}

// NewSlackHandler creates a new SlackHandler with dynamic repository lookups and LLM support.
func NewSlackHandler(govSvc governance.Service, dirSvc governance.DirectoryClient, repo Repository, llm llm.Provider, uiURL string, env string, log *zap.Logger) *SlackHandler {
	return &SlackHandler{
		govSvc: govSvc,
		dirSvc: dirSvc,
		repo:   repo,
		llm:    llm,
		log:    log,
		client: &http.Client{Timeout: 10 * time.Second},
		uiURL:  uiURL,
		env:    env,
	}
}

// HandleCommand processes slash commands like /wardseal request <app>
func (h *SlackHandler) HandleCommand(w http.ResponseWriter, r *http.Request) {
	// G120: Limit request body size to 32KB for slash commands
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)

	// 1. Capture raw body for signature verification
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.log.Error("failed to read request body", zap.Error(err))
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
	if len(parts) == 0 {
		h.sendEphemeralResponse(w, "Usage: `/wardseal catalog` or `/wardseal request <app_name>`")
		return
	}

	if parts[0] == "catalog" {
		err := h.HandleCatalogCommand(r.Context(), tenantID, r.FormValue("trigger_id"))
		if err != nil {
			h.log.Error("failed to open catalog", zap.Error(err))
			h.sendEphemeralResponse(w, "❌ We couldn't open the App Catalog right now.")
		}
		return
	}

	if parts[0] == "ask" {
		if len(parts) < 2 {
			h.sendEphemeralResponse(w, "Usage: `/wardseal ask <your question>`")
			return
		}
		question := strings.Join(parts[1:], " ")
		go h.HandleAskCommand(context.Background(), tenantID, question, r.FormValue("response_url"))
		h.sendEphemeralResponse(w, "⌛ _Analyzing the identity graph..._")
		return
	}

	if parts[0] == "agent" {
		if len(parts) < 3 || parts[1] != "request" {
			h.sendEphemeralResponse(w, "Usage: `/wardseal agent request <workload_id> <scopes...>`")
			return
		}
		workloadID := parts[2]
		scopes := parts[3:]
		
		req, err := h.govSvc.CreateAgentAccessRequest(r.Context(), tenantID, workloadID, scopes, "Requested via Slack agent command", "4h")
		if err != nil {
			h.log.Error("failed to create agent request", zap.Error(err))
			h.sendEphemeralResponse(w, "❌ Failed to create agent access request.")
			return
		}
		
		h.sendEphemeralResponse(w, fmt.Sprintf("✅ *Agent Access Request Created*\nID: `%s`\nWorkload: `%s`\nScopes: `%s`", req.ID, workloadID, strings.Join(scopes, ", ")))
		return
	}

	if len(parts) < 2 || parts[0] != "request" {
		h.sendEphemeralResponse(w, "Usage: `/wardseal catalog`, `/wardseal request <app_name>`, or `/wardseal ask <question>`")
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
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		h.log.Error("failed to encode response", zap.Error(err))
	}
}

func (h *SlackHandler) sendEphemeralResponse(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]interface{}{
		"response_type": "ephemeral",
		"text":          text,
	})
	if err != nil {
		h.log.Error("failed to encode response", zap.Error(err))
	}
}

// HandleInteraction processes button clicks from Slack.
func (h *SlackHandler) HandleInteraction(w http.ResponseWriter, r *http.Request) {
	// G120: Limit request body size for interactions
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

	// 1. Capture raw body for signature verification
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.log.Error("failed to read interaction body", zap.Error(err))
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
	default:
		if strings.HasPrefix(action.ActionID, "request_access_app:") {
			appID := strings.TrimPrefix(action.ActionID, "request_access_app:")
			_, err = h.govSvc.CreateAccessRequest(r.Context(), tenantID, governance.CreateAccessRequest{
				RequesterID:  approverID, // In this context, the user interacting is the requester
				ResourceType: "app",
				ResourceID:   appID,
				Reason:       "Requested via Slack App Catalog",
			})
			msg = "Access Requested via Catalog"
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
				"type":  "plain_text",
				"text":  "🛡️ WardSeal Safety Alert",
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
					"text": "*Status:*\n`Pending Confirmation`",
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
						"title":   map[string]interface{}{"type": "plain_text", "text": "Are you sure?"},
						"text":    map[string]interface{}{"type": "plain_text", "text": "This will immediately revoke all organizational access for this user."},
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned non-200 status: %d", resp.StatusCode)
	}

	return nil
}

// NotifyAccessRequest sends an interactive Slack message for a new access request.
func (h *SlackHandler) NotifyAccessRequest(ctx context.Context, req governance.AccessRequest) error {
	integ, err := h.repo.GetByTenant(ctx, req.TenantID)
	if err != nil || !integ.IsEnabled {
		return nil
	}

	blocks := []interface{}{
		map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("🔔 *New Access Request*\n*Requester:* %s\n*Resource:* %s (%s)\n*Reason:* %s",
					req.RequesterID, req.ResourceID, req.ResourceType, req.Reason),
			},
		},
		map[string]interface{}{
			"type": "actions",
			"elements": []interface{}{
				map[string]interface{}{
					"type": "button",
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "Approve",
					},
					"style":     "primary",
					"action_id": "approve_request",
					"value":     req.ID,
				},
				map[string]interface{}{
					"type": "button",
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "Reject",
					},
					"style":     "danger",
					"action_id": "reject_request",
					"value":     req.ID,
				},
			},
		},
	}

	payload := map[string]interface{}{
		"blocks": blocks,
	}

	if integ.WebhookURL == "" {
		h.log.Warn("Slack integration active but no WebhookURL for tenant", zap.String("tenant_id", req.TenantID))
		return nil
	}

	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", integ.WebhookURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}

// NotifyAccessAvailable pushes a proactive suggestion to a user when new matching resources are found.
func (h *SlackHandler) NotifyAccessAvailable(ctx context.Context, tenantID, slackUserID, resourceName, reason string) error {
	integ, err := h.repo.GetByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if !integ.IsEnabled {
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
// HandleAskCommand performs a conversational audit using LLM.
func (h *SlackHandler) HandleAskCommand(ctx context.Context, tenantID, question, responseURL string) {
	if h.llm == nil {
		h.sendDelayedResponse(responseURL, "❌ LLM support is not configured for this environment.")
		return
	}

	// 1. Gather Context from platform services
	contextData, err := h.govSvc.GatherAuditContext(ctx, tenantID)
	if err != nil {
		h.log.Error("failed to gather audit context", zap.Error(err))
		h.sendDelayedResponse(responseURL, "❌ Failed to analyze identity data. Please try again later.")
		return
	}

	// 2. Build System Prompt
	systemPrompt := fmt.Sprintf(`
You are WardSeal AI, an expert Identity & Governance auditor. 
You have access to the identity relationship graph and governance state for tenant "%s".
Use the following context to answer the user's question accurately. 

SAFETY RULES:
- NEVER disclose passwords, secret keys, tokens, or any literal authentication credentials.
- If the user asks for credentials, inform them that you do not have access to secrets, only governance metadata.
- If you see any data that appears to be a raw secret in the context, redact it as [REDACTED].

If you don't know the answer, say so. Keep responses concise and use slack markdown.

CONTEXT:
%s
`, tenantID, contextData)

	// 3. Generate Response
	answer, err := h.llm.GenerateResponse(ctx, systemPrompt, question)
	if err != nil {
		h.log.Error("llm generation failed", zap.Error(err))
		h.sendDelayedResponse(responseURL, "❌ I encountered an error while processing your request.")
		return
	}

	// 4. Send Response back to Slack
	h.sendDelayedResponse(responseURL, answer)
}


func (h *SlackHandler) sendDelayedResponse(responseURL, text string) {
	payload := map[string]interface{}{
		"replace_original": false,
		"text":             text,
	}
	body, _ := json.Marshal(payload)
	resp, err := h.client.Post(responseURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		h.log.Error("failed to send delayed slack response", zap.Error(err))
		return
	}
	defer resp.Body.Close()
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
