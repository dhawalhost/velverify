# Jurisdiction Compliance Matrix (India / US / EU)

Use this matrix to finalize policy language and operational controls for your target markets.

> Template only. Validate with legal counsel before publication.

## 1) Regional legal baseline

| Region | Primary Framework | Key Policy Impacts |
|---|---|---|
| India | DPDP Act, 2023 (+ rules as notified) | consent notice language, grievance redressal contact, data principal rights workflows |
| EU/EEA | GDPR (+ ePrivacy as applicable) | legal bases, DPA/SCCs, transfer safeguards, data subject rights, DPO/rep obligations |
| US | State privacy law baseline (CCPA/CPRA + other state laws as applicable) | privacy notice rights, consumer request workflows, contract role language |

## 2) Policy-by-policy checklist

| Policy | India | EU/EEA | US |
|---|---|---|---|
| Privacy Policy | add grievance contact and DPDP rights | add GDPR rights + supervisory authority language | add state-rights language and request workflow |
| Terms of Service | mandatory-law carve-out | mandatory-law carve-out | mandatory-law carve-out + state notices as needed |
| DPA | role mapping and safeguards | SCCs + transfer mechanism details | service provider/processor terms as applicable |
| Cookie Policy | consent model if required by deployment | consent model + ePrivacy alignment | state disclosure alignment where applicable |
| Incident Policy | breach workflow + legal timing check | GDPR breach notification handling | state breach law timing references by applicable law |
| Subprocessor List | transfer notice and disclosures | transfer mechanism + list transparency | vendor transparency + contractual flow-down |

## 3) Open placeholders to complete

- Wardseal
- Vapi, Gujarat
- privacy@wardseal.com
- dpa@wardseal.com
- security@wardseal.com
- privacy@wardseal.com
- privacy@wardseal.com (if required)
- Region-specific (India: laws of India; EU/EEA and US: as per regional order form/addendum)
- Region-specific (India: courts having jurisdiction over Vapi, Gujarat; EU/EEA and US: as per regional order form/addendum)
- 15 March 2026

## 4) Operational controls to confirm before go-live

- [x] Rights request intake and identity verification workflow (See `data-rights-and-deletion-runbook.md`)
- [x] Deletion workflow and backup-aging statement (See `data-rights-and-deletion-runbook.md`)
- [ ] Subprocessor list publication and update mechanism
- [ ] Incident escalation and external notification runbook
- [ ] Regional contract packet (ToS + DPA addendum + SLA)

## 5) Recommended release model

- One global baseline policy set
- Region-specific addenda where required (India, EU/EEA, US)
- Versioned policy changelog and notice process
