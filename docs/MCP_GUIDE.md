# WardSeal MCP Server Guide

The WardSeal Model Context Protocol (MCP) server allows AI agents (like Claude Desktop, GitHub Copilot, or custom agents) to securely interact with the WardSeal Identity Governance platform.

## 🛠️ Tool Catalog

The following tools are available to AI agents:

### 📊 Governance & Stats
- `wardseal_get_stats`: Retrieve security metrics (users, workloads, hygiene score).
- `wardseal_list_requests`: Audit pending access requests.
- `wardseal_approve_request`: Approve a pending access request.
- `wardseal_list_organizations`: Audit organizational structure.

### 🔍 Discovery & Graph
- `wardseal_list_identities`: Search for users and groups in the directory.
- `wardseal_get_graph`: Visualize relationship tuples in the identity graph.
- `wardseal_list_clients`: Manage OAuth2 applications.

### 🛡️ Safety & Policy
- `wardseal_evaluate_policy`: Simulate a policy evaluation for an actor and resource.
- `wardseal_propose_action`: Propose reactive safety actions (e.g., account lock/revocation).
- `wardseal_list_ip_policies`: List network-level Reachability rules.
- `wardseal_create_ip_policy`: Add new IP allow/block policies.

### 💻 Machine & Device Identity
- `wardseal_list_workloads`: Manage non-human service accounts.
- `wardseal_list_devices`: View trust status of registered endpoints.
- `wardseal_update_device_status`: Manually promote or demote device trust.

## 🚀 Connecting to AI Agents

### Claude Desktop
Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wardseal": {
      "command": "/usr/local/go/bin/go",
      "args": ["run", "./cmd/mcpsvc/main.go"],
      "cwd": "/path/to/wardseal",
      "env": {
        "APP_ENVIRONMENT": "dev",
        "LLM_PROVIDER": "openrouter",
        "OPENROUTER_API_KEY": "your-key-here",
        "OPENROUTER_MODEL": "openai/gpt-4o",
        "WARDSEAL_API_KEY": "ClientID:Secret"
      }
    }
  }
}
```

### Local Execution
You can run the server directly for testing:

```bash
make mcp
```

The server uses **Stdio transport**, meaning it reads from `stdin` and writes to `stdout`. Logs are automatically directed to `stderr` to avoid interfering with the JSON-RPC stream.

## 🔒 Security & Authentication

The WardSeal MCP server enforces strict authentication to ensure only authorized agents can access governance resources. 

### 🔑 Authentication Methods

1.  **Workload API Key (`ClientID:Secret`)**: The recommended method. Associate your AI agent with a specific `Workload` in WardSeal. The agent will only be able to access resources within that workload's `TenantID`.
2.  **Master Service Token**: Use your platform's `APP_AUTH_SERVICE_AUTH_TOKEN`. This grants the agent full administrative access to all tenants (use with caution during development).

### 🛡️ Multi-Tenancy Isolation
If an agent is authenticated via a Workload API Key, the MCP server automatically validates every tool call. If the AI attempt to access a `tenant_id` that does not match the key's authorized tenant, the request will be blocked with an `Unauthorized` error.
