# Data Retention and Deletion Policy

**Effective Date:** 15 March 2026

This policy defines retention and deletion handling for WardSeal data categories.

## 1. Principles

- Retain only what is necessary for service delivery, security, and legal obligations
- Support tenant/customer-controlled deletion where applicable
- Document retention schedules and deletion workflows

## 2. Data categories and baseline retention

| Category | Examples | Baseline Retention | Notes |
|---|---|---|---|
| Identity profile data | user identifiers, profile attributes | Contract term + 30 days | customer-configurable where supported |
| Authentication events | login attempts, MFA events | 12 months | used for security monitoring |
| Audit logs | admin actions, governance events | 24 months | may be required for compliance evidence |
| Token/session artifacts | refresh tokens, auth codes | short-lived (minutes to days) | rotated/revoked per security model |
| Support records | support tickets and communication | 24 months | contractual/legal support needs |
| Billing/financial records | invoices, payment records | 7 years | per legal and accounting requirements |

## 3. Deletion and deprovisioning

- Customer-initiated deletion requests are processed according to agreement and technical feasibility.
- Deletion propagates through active systems within 30 days.
- Backup media is deleted or aged out per backup retention cycles.

## 4. Legal holds and exceptions

Data may be retained beyond standard periods when required by legal obligation, dispute preservation, or security investigation.

## 5. Self-hosted deployments

For self-hosted deployments, customers control infrastructure-level retention, backup lifecycle, and storage deletion semantics.

## 6. Contact

Retention/privacy contact: privacy@wardseal.com
