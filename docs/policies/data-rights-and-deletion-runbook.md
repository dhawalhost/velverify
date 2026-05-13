# Data Principal Rights and Deletion Runbook

**Effective Date:** 15 March 2026

This operational runbook defines the internal procedures for handling Data Principal (user) rights requests, including data export, account erasure, and identity verification under DPDP, GDPR, and US State Privacy Laws.

## 1. Rights Request Intake & Identity Verification Workflow

When a user exercises their rights (e.g., via the WardSeal User Portal or by emailing privacy@wardseal.com):

1. **Intake:** 
   - Requests triggered via the User Portal are automatically logged in the audit system with the authenticated user's context.
   - Emailed requests trigger a support ticket assigned to the Privacy Operations team.

2. **Identity Verification:**
   - **Portal Requests:** Inherently verified via the user's authenticated session (including MFA if enabled).
   - **Email Requests:** The Privacy Operations team must verify the requestor by sending a secure confirmation link to the email address on file or requiring the user to authenticate through the Portal to confirm the request.

3. **Triage & Timelines:**
   - Requests must be acknowledged within 48 hours.
   - Fulfillment must be completed within 30 days (extensions subject to applicable regional laws).

## 2. Data Portability & Export Workflow

1. **Initiation:** User requests data export.
2. **Compilation:** The system runs an asynchronous job to aggregate:
   - User profile attributes (Name, Email, Phone, external IDs).
   - Group memberships and assigned roles.
   - Access and authentication logs for the past 90 days.
3. **Delivery:** The compiled data is formatted as a secure, encrypted JSON archive. The user receives an email with a time-limited, signed URL to download the archive.

## 3. Account Deletion Workflow

When a user requests account erasure ("Right to be Forgotten"):

1. **Soft Delete (Days 1-30):**
   - The user account is immediately disabled (access revoked).
   - The record in the primary directory database is marked with a `deleted_at` timestamp.
   - The user can contact support to cancel the deletion during this 30-day grace period.

2. **Hard Delete (Day 31):**
   - A background worker permanently purges the user record and associated PII from the primary databases.
   - Identifiers in audit logs (if required to be kept for security/legal compliance) are irreversibly anonymized.

## 4. Backup-Aging Statement

WardSeal maintains encrypted database backups for disaster recovery purposes.
- **Backup Retention:** Full backups are retained for a maximum of **90 days**.
- **Erasure Propagation:** When a user's data is hard-deleted from the primary database on Day 31, the data will still exist in historical backups. It will naturally "age out" and be permanently destroyed when the 90-day backup rotation completes.
- If a backup needs to be restored during this 90-day window, the Privacy Operations team will re-apply the deletion log to ensure erased data is not inadvertently restored to the live environment.

## 5. Contact and Escalation

- **Privacy Operations:** privacy@wardseal.com
- **Grievance Officer (India):** grievance@wardseal.com
- **Escalation Path:** Support -> Privacy Ops -> Legal / DPO
