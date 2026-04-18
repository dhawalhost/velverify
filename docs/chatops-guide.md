# WardSeal ChatOps Technical Guide

## Overview
WardSeal provides a production-grade, multi-tenant ChatOps integration layer that allows organizations to manage access requests directly from Slack. The architecture is designed for cryptographic isolation and high-trust interactions.

## 1. Multi-Tenant Architecture
Unlike simple Slack bots, WardSeal is a **SaaS-First Integration**. 

- **Dynamic Resolution**: All incoming callbacks from Slack contain a `team_id`. WardSeal uses this ID to resolve the tenant's configuration (Bot Token, Signing Secret) from the encrypted database.
- **Stateless Handlers**: The `chatops.SlackHandler` does not store session state, allowing it to scale horizontally across multiple instances.

## 2. Security & Signature Verification
To prevent request spoofing, WardSeal enforces mandatory HMAC-SHA256 signature verification for every request coming from Slack.

### The Verification Protocol
1. **Timestamp Check**: Rejects any request with a timestamp (`X-Slack-Request-Timestamp`) older than 5 minutes to prevent replay attacks.
2. **Signature Generation**:
   - Concatenate `v0`, the timestamp, and the raw request body with colons: `v0:timestamp:payload`.
   - Compute the HMAC-SHA256 hash using the tenant's unique **Signing Secret**.
3. **Comparison**: Compares the computed hash against the `X-Slack-Signature` header using `hmac.Equal` (constant-time comparison).

> [!IMPORTANT]
> Incoming requests that fail verification are dropped immediately with a `401 Unauthorized` status. No tenant data is leaked.

## 3. Secret Protection (KMS)
All sensitive integration credentials are encrypted at rest using the platform's **KMS (Key Management Service)** layer.
- **Bot Tokens**: Encrypted via AES-256-GCM.
- **Signing Secrets**: Encrypted via AES-256-GCM.
- **Decryption**: Decryption happens just-in-time (JIT) during request processing and never touches persistent logs.

## 4. Slack App Configuration
To onboard a new tenant, the following scopes and configurations are required:

### Required Scopes
- `commands`: To handle `/wardseal` slash commands.
- `chat:write`: To send responses and approval notifications.
- `users:read`: To resolve Slack User IDs to email addresses.

### Event Subscriptions
- `interaction_payload`: Required for button clicks and modal submissions.

## 5. Slash Commands
| Command | Usage | Description |
| :--- | :--- | :--- |
| `/wardseal request <app>` | `/wardseal request production-db` | Initiates an access request. |
| `/wardseal help` | `/wardseal help` | Displays list of available commands. |
