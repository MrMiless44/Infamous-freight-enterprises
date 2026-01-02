# Secrets & Provider Setup Checklist

This checklist lists exact GitHub secret names, expected formats, and quick provider steps to configure Fly.io, Vercel, and Render for this repo.

Important: never paste real secrets into chat. Add secrets via GitHub Settings → Secrets or use CLI tools (`gh`, `flyctl`, `vercel`, etc.).

## Required GitHub secrets (exact names)

- `FLY_API_TOKEN` — Fly API token used by `superfly/flyctl-actions`.
- `PROD_API_BASE_URL` — Public API base URL, e.g. `https://api.example.com`.
- `PROD_WEB_BASE_URL` — Public web URL, e.g. `https://example.com`.
- `VERCEL_TOKEN` — Vercel personal token (if using the Vercel Action).
- `VERCEL_ORG_ID` — Vercel organization ID for the project.
- `VERCEL_PROJECT_ID` — Vercel project ID for the web app.
- `RENDER_API_KEY` — Render API key (if using Render deploy trigger).
- `RENDER_SERVICE_ID` — Render service ID to trigger deploys.
- `DATABASE_URL` — Production Postgres connection string (URI format, include password).
- `JWT_SECRET` — Strong application JWT secret.
- `REDIS_URL` — Redis connection string (e.g., `redis://:<password>@host:port`).
- `SMOKE_ENDPOINTS` — (optional) comma-separated relative API paths for extended smoke tests (e.g. `/api/auth/login,/api/shipments/create`).

Optional provider secrets (examples):

- `SENTRY_DSN`, `STRIPE_SECRET_KEY`, `SENDGRID_API_KEY`, etc.

## Fly.io setup (API)

1. Install `flyctl`: https://fly.io/docs/hands-on/install-flyctl/
2. Login locally and create app (one-time):

```bash
flyctl auth login
cd api
flyctl launch --name infamous-api --region iad --no-deploy
```

3. Configure `fly.toml` (repo already includes `fly.toml` and `Dockerfile.fly`).
4. Set production secrets on Fly (example):

```bash
flyctl secrets set DATABASE_URL="postgres://user:pass@host:5432/db" JWT_SECRET="<your-jwt-secret>" REDIS_URL="redis://:pass@host:6379"
```

5. Add `FLY_API_TOKEN` to **GitHub repository secrets** (used in CI). Create a Fly token at https://fly.io/user/personal_access_tokens

## Vercel setup (Web)

Preferred: Use Vercel's GitHub integration (connect repo → select project) — this avoids storing tokens in the repo.

If using the Vercel Action in CI, add these secrets to GitHub:

- `VERCEL_TOKEN` — create at https://vercel.com/account/tokens
- `VERCEL_ORG_ID` and `VERCEL_PROJECT_ID` — found in Vercel project settings

CLI example to set env on Vercel (optional):

```bash
# Install vercel CLI
npm i -g vercel
vercel login
vercel env add DATABASE_URL production
# Follow prompts to input value
```

## Render setup (optional)

If you prefer Render for web or services, create service in Render dashboard and set `RENDER_API_KEY` and `RENDER_SERVICE_ID` in GitHub Secrets.

Trigger deploy via workflow uses:

```
curl -X POST "https://api.render.com/v1/services/${RENDER_SERVICE_ID}/deploys" \
  -H "Authorization: Bearer ${RENDER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"clearCache":true}'
```

## How to add GitHub secrets (UI)

1. Go to your repo on GitHub → Settings → Secrets and variables → Actions → New repository secret.
2. Add each secret name and value from the list above.

## How to add GitHub secrets (CLI - `gh`)

Install GitHub CLI and run (example):

```bash
gh auth login
gh secret set FLY_API_TOKEN --body "$FLY_API_TOKEN" --repo YOUR_OWNER/Infamous-freight-enterprises
gh secret set PROD_API_BASE_URL --body "https://api.example.com" --repo YOUR_OWNER/Infamous-freight-enterprises
# repeat for each secret
```

## Quick verification after adding secrets

- In GitHub Actions → Secrets, confirm secrets appear.
- Merge `chore/fix/shared-workspace-ci` to `main` or push to `main` to trigger `.github/workflows/deploy-fly.yml` and `.github/workflows/deploy-vercel.yml`.
- Watch Actions; upon successful deploys, the smoke-tests workflow (`.github/workflows/smoke-tests.yml`) will run and use `PROD_API_BASE_URL`/`PROD_WEB_BASE_URL` to validate endpoints.

## Security notes

- Use GitHub Secrets to store sensitive values; never commit secrets to the repo.
- Limit token scopes (e.g., Fly personal access token only to required permissions).
- Rotate credentials regularly and document rotation steps in a secure internal doc.

If you want, I can now:

- generate `gh` CLI commands for all required secrets (skeleton commands you can run locally), or
- prepare a short script to set secrets via `gh` (you run locally), or
- automatically open a PR updating `DEPLOYMENT_README.md` with final hostnames once you provide `PROD_API_BASE_URL`/`PROD_WEB_BASE_URL` values.
