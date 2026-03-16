# Security and Trust Overview

**Effective Date:** 15 March 2026

This document summarizes WardSeal’s security posture at a high level for customers and evaluators.

## 1. Security principles

- Least privilege access
- Defense in depth
- Secure-by-default platform controls
- Auditability and traceability

## 2. Platform controls (high level)

WardSeal includes controls such as:

- Strong authentication and MFA support
- Modern authentication protocols (OIDC/SAML)
- Tenant-aware data isolation patterns
- Session and token lifecycle protections
- Audit logging for administrative and security events
- Security headers and API hardening patterns

## 3. Operational security

- Access to production systems is restricted and reviewed
- Security events are monitored and investigated
- Vulnerability management and patching processes are maintained
- Incident response procedures are documented and exercised

## 4. Shared responsibility

For self-hosted deployments, customers are responsible for infrastructure, runtime hardening, and operational controls in their environment.

## 5. Security contact

Security inquiries: security@wardseal.com

Vulnerability reports: see `vulnerability-disclosure-policy.md`
