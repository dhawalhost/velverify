# WardSeal Grafana Dashboard

This folder contains a ready-to-import Grafana dashboard for WardSeal service metrics.

## File

- `wardseal-overview-dashboard.json`

## Import Steps

1. In Grafana, go to **Dashboards → New → Import**.
2. Upload `wardseal-overview-dashboard.json`.
3. Choose your Prometheus datasource.
4. Save the dashboard.

## Expected Metrics

The dashboard expects these Prometheus metrics exposed by WardSeal services:

- `http_requests_total`
- `http_request_duration_seconds_bucket`
- `auth_tokens_issued_total`
- `auth_token_errors_total`
- `auth_token_introspections_total`
- `auth_token_revocations_total`
