# WardSeal Policy Pack

This folder contains customer-facing and internal policy templates for WardSeal.

> These templates are operationally aligned to the current product architecture, but they are not legal advice. Final versions should be reviewed by legal counsel before publication.

## What to publish publicly

1. `privacy-policy.md`
2. `terms-of-service.md`
3. `cookie-policy.md`
4. `acceptable-use-policy.md`
5. `security-and-trust.md`
6. `vulnerability-disclosure-policy.md`
7. `subprocessors-and-international-transfers.md`

### Regional addenda (publish when targeting those markets)

1. `addenda/eu-eea-privacy-and-dpa-addendum.md`
2. `addenda/india-dpdp-addendum.md`
3. `addenda/us-state-privacy-addendum.md`

## What to sign with customers (B2B / enterprise)

1. `data-processing-addendum-dpa.md`
2. `service-level-policy-sla.md`
3. `data-retention-and-deletion-policy.md`
4. `incident-response-and-breach-notification-policy.md`

## What to use internally

1. `records-of-processing-template.md`
2. `policy-launch-checklist.md`
3. `jurisdiction-compliance-matrix-india-us-eu.md`

## Product context baked into these templates

- Multi-tenant architecture and tenant isolation controls
- Authentication with OIDC/SAML/WebAuthn support
- Audit logging and security hardening controls
- SaaS and self-hosted enterprise deployment modes

## Publishing notes

- Replace all placeholders (for example: `[LEGAL_ENTITY_NAME]`, `[EFFECTIVE_DATE]`, `[DPA_CONTACT_EMAIL]`).
- Keep commitments conservative and true to current implementation.
- Where a control is roadmap-only, avoid claiming it as currently active.
- Version every policy and keep an archive of prior versions.
- Recommended publish order: baseline policies first, then applicable regional addendum(s), then jurisdiction matrix for internal signoff.

## Jurisdiction focus

This pack is prepared for a target audience in:

- India (DPDP Act, 2023)
- European Union / EEA (GDPR)
- United States (state privacy law baseline, including CCPA/CPRA where applicable)

Use `jurisdiction-compliance-matrix-india-us-eu.md` to finalize region-specific language before launch.
