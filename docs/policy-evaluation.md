# WardSeal Policy Evaluation Manual

## Overview
WardSeal uses a **Tiered Policy Engine** that balances ease-of-use with extreme flexibility. This manual explains how policies are structured, validated, and evaluated by the governance service.

## 1. The Tiered Model
The platform supports three distinct rule types to accommodate different organizational needs:

### Tier 1: Simple (ABAC)
- **Format**: JSON/YAML
- **Evaluator**: `SimpleEvaluator`
- **Use Case**: Basic attribute-based access control (e.g., "MFA must be enabled," "User must be in the Admin group").
- **Pros**: Highly performant, easy to generate via GUI.

### Tier 2: Advanced (CEL)
- **Format**: Common Expression Language (Google CEL)
- **Evaluator**: `CELEvaluator`
- **Use Case**: Complex boolean logic involving lists or time-based constraints (e.g., `subject.roles.contains('admin') && request.time.hour() < 18`).
- **Pros**: Type-safe, fast, and secure embedded execution.

### Tier 3: Enterprise (Rego)
- **Format**: Open Policy Agent (OPA) DSL
- **Use Case**: Full compliance auditing and cross-service authorization.
- **Status**: *Planned Enhancement*.

---

## 2. Simple Rule Specification
A "Simple" rule consists of a logical operator and a list of conditions.

### JSON Schema
```json
{
  "logical_op": "AND", // OR "OR"
  "conditions": [
    {
      "attribute": "subject.roles",
      "operator": "contains",
      "value": "devops"
    },
    {
      "attribute": "context.device_trust",
      "operator": "equals",
      "value": "trusted"
    }
  ]
}
```

### Supported Operators
- `equals`: Strict string/numeric equality.
- `not_equals`: Inequality.
- `contains`: Checks if a string or list contains the target value.
- `matches`: Regular expression matching.

---

## 3. Evaluation Context
Every policy is evaluated against an **Evaluation Input** object. Attributes in rules are resolved using dot-notation.

| Category | Path | Description |
| :--- | :--- | :--- |
| **Subject** | `subject.id` | The unique ID (email/UUID) of the requester. |
| | `subject.roles` | List of roles assigned to the user. |
| **Resource** | `resource.type` | e.g., "app", "cloud_env", "database". |
| | `resource.id` | The unique identifier of the target resource. |
| **Context** | `context.ip` | The source IP address. |
| | `context.device_trust`| Trust level (trusted/untrusted/unknown). |
| | `context.mfa_status` | Status of MFA verification (verified/pending). |

---

## 4. Evaluation Flow
1. **Selection**: The `Engine` identifies all active policies for the tenant and resource type.
2. **Hydration**: The `govsvc` hydrates the input context with real-world data (e.g., looking up the user's roles and current device posture).
3. **Execution**: Each policy is processed by its respective evaluator (`Simple`, `CEL`).
4. **Final Decision**: All policies must pass (Deny-by-Default architecture). A single "False" result terminates the chain and returns a descriptive violation reason.
