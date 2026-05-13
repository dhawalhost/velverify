# Zero Trust: EDR/MDM Integration Design

This document outlines the design for integrating WardSeal with Endpoint Detection and Response (EDR) and Mobile Device Management (MDM) solutions (e.g., CrowdStrike Falcon, Jamf Pro).

## 1. Objectives
- Automatically update device posture in WardSeal based on external security telemetry.
- Enforce Zero Trust policies using real-time device health signals.

## 2. Inbound Webhook Receiver
WardSeal will expose a unified webhook ingestion endpoint:
`POST /api/v1/devices/webhooks/{provider}`

### Payload Mapping
The receiver will translate provider-specific payloads into WardSeal's internal posture schema.

#### Example: CrowdStrike Falcon
CrowdStrike ZTA (Zero Trust Assessment) score ranges from 1-100.
- **Rule**: If ZTA score < 50, set `trust_status = "untrusted"`.

#### Example: Jamf Pro
Jamf Smart Groups can flag non-compliant devices.
- **Rule**: If `compliance_status == "NonCompliant"`, set `trust_status = "untrusted"`.

## 3. Automated Enforcement
Upon receiving a critical signal (e.g., device becomes untrusted):
1. The `SignalStore` records the event.
2. Continuous Access Evaluation (CAE) logic in `authsvc` evaluates future token requests.
3. Active sessions originating from the device are marked for MFA step-up or immediate revocation.
