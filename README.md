# WardSeal 🛡️
## Modern Identity Infrastructure & Autonomous Governance

WardSeal is an **Open Core** Identity & Access Management (IAM) and Governance (IGA) platform designed for the modern enterprise. It bridges the gap between traditional identity management and zero-trust security through autonomous risk evaluation and AI-driven governance.

---

## ✨ Core Capabilities

### 🛡️ Identity & Access (IAM)
- **OIDC & OAuth 2.0**: Full OIDC provider with Authorization Code + PKCE & Refresh Token support.
- **Enterprise SSO**: Seamless integration with SAML IdPs and Social providers.
- **Adaptive MFA**: Native support for **WebAuthn (Passkeys)** and TOTP with context-aware step-up.
- **Secure Provisioning**: SCIM 2.0-compliant engine for synchronizing identities across your ecosystem.

### ⚖️ Autonomous Governance (IGA)
- **Zero-Trust Access Requests**: Automated and manual approval workflows with temporal access (Time-Bound Roles).
- **AI-Powered Discovery**: Autonomous scanning for "Shadow AI" and unauthorized service accounts using LLMs (OpenRouter/GPT-4).
- **Compliance Campaigns**: Automated access reviews and hygiene scoring for your entire organization.
- **Machine Identity**: Specialized lifecycle management for workloads and non-human identities.

### 🔒 Enterprise Security
- **Dynamic Policy Engine**: Tiered policy support using Simple ABAC, Google CEL, and Rego.
- **Risk Evaluation Engine**: Real-time scoring based on device posture, travel velocity, and historical behavior.
- **KMS Integration**: Native support for HashiCorp Vault and AES-GCM field-level encryption.
- **ChatOps**: First-class Slack integration for approvals, notifications, and safety actions.

---

## 🎨 Clean Modernist: The Admin Experience

WardSeal features a premium **Admin Console** built on a "Clean Modernist" design system. 
- **Glassmorphism UI**: High-contrast, vibrant components for maximum clarity.
- **Identity Graph**: Visual exploration of complex human-to-resource relationships.
- **Real-time Hygiene**: Instant visibility into organization-wide security posture.

---

## 🏛️ Architectural Excellence

WardSeal is built with Go, emphasizing **SOLID** principles and high-concurrency performance.
- **Microservices Architecture**: Decoupled services for Auth, Directory, and Governance.
- **Interface-First Design**: Agnostic to storage (SQL/Redis) and LLM providers.
- **Multi-Tenant core**: Logical isolation and row-level security built into every layer.

> [!NOTE]
> For deep technical details on service communication and multitenancy, see [Service Details](docs/architecture/SERVICE_DETAILS.md).

---

## 🚀 Quick Start

WardSeal is designed to be developer-friendly. Get the full stack running in minutes.

### 1. Prerequisite
Ensure Docker and `make` are installed, and add the local DNS entries:
```text
127.0.0.1 wardseal.local help.wardseal.local manage.wardseal.local auth.wardseal.local api.wardseal.local
```

### 2. Launch
```bash
# Start the full orchestration stack
make dev
```

| Component | Endpoint |
|---|---|
| **Admin Console** | [http://manage.wardseal.local](http://manage.wardseal.local) |
| **Landing UI** | [http://wardseal.local](http://wardseal.local) |
| **API Gateway** | [http://api.wardseal.local](http://api.wardseal.local) |

---

## 📖 Documentation
- [Architecture & Diagrams](docs/ARCHITECTURE.md)
- [Deployment Guide](docs/DEPLOYMENT_GUIDE.md)
- [API Reference](docs/api-reference.md)
- [Contributing](CONTRIBUTING.md)

---

## 📄 License
WardSeal core is available under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.
