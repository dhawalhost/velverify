# WardSeal Landing Site

Public marketing website for [WardSeal](https://wardseal.com) — the enterprise identity and access management platform.

## Overview

This directory is **fully self-contained** and has no dependency on the rest of the WardSeal
monorepo. At any point it can be:

- Extracted to its own repository (`wardseal-landing`) without any code changes.
- Deployed independently via its own CI/CD pipeline.
- Served at `wardseal.com` or any other domain without touching the platform.

## Tech stack

React + Vite SPA served via `nginx:1.27-alpine`.

- Client routes:
  - `/` (marketing home)
  - `/policies` (policy index)
- Nginx handles SPA fallback (`try_files ... /index.html`).

## Local development

```bash
# Install dependencies
npm install

# Run dev server
npm run dev

# Serve with Docker
docker build -t wardseal-landingui:local -f Dockerfile . \
  && docker run --rm -p 8080:80 wardseal-landingui:local
# Then open http://localhost:8080
```

## Build

```bash
npm run build
```

Output is generated in `dist/`.

## Environment configuration

The landing SPA uses a centralized config module in `src/siteConfig.js`.

It supports three environments:

- `local`
- `staging`
- `production`

Optional Vite build variables:

```bash
VITE_ENVIRONMENT=staging
VITE_SITE_BASE_URL=https://staging.wardseal.com
VITE_CONSOLE_BASE_URL=https://console-staging.wardseal.com
VITE_SUPPORT_EMAIL=support@wardseal.com
```

If these are not provided, the app falls back to hostname-based detection:

- `*.local` → local
- `*-staging.wardseal.com` → staging
- everything else → production

## Deploying inside WardSeal Helm chart

The `landingui` sub-chart is **disabled by default**, so enterprise self-hosted installs never
see it. To enable it:

```yaml
# values-local.yaml (or your SaaS overlay)
landingui:
  enabled: true
  image:
    tag: "local"   # or your OCI tag
```

And build the image:

```bash
DEPLOY_LANDING=true ./scripts/deploy_local_k8s.sh
```

## Extraction to its own repo

When the time comes to move this out:

1. `git subtree split --prefix web/landing -b landing-split`
2. Push that branch to the new `wardseal-landing` repository.
3. Remove `web/landing/` from this repo and update the umbrella chart to reference the
   new external image registry path.
4. The `Helm` sub-chart (`deploy/charts/landingui/`) can move with it or stay in the
   platform chart — either works.

## Content

| Section        | File location |
|----------------|---------------|
| Home page      | `src/pages/HomePage.jsx` |
| Policies page  | `src/pages/PoliciesPage.jsx` |
| Header/Footer  | `src/components/` |
| Styling        | `src/styles.css` |

## License

See the root `LICENSE` file in the WardSeal platform repository.
