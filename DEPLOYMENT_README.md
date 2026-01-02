# Deployment Guide — Infamous Freight Enterprises

This document describes the recommended production deployment of this monorepo.

Overview

- API: Fly.io (Docker-first, multi-region, low-latency)
- Web: Vercel (first-class Next.js support)
- Mobile: Expo / EAS (managed builds and OTA)
- DB: Managed Postgres (Fly Postgres, Supabase, or Render Postgres)
- Cache: Managed Redis (Upstash, Render Redis)

Required GitHub repository secrets

- `FLY_API_TOKEN` — Fly CLI/API token
- `VERCEL_TOKEN`, `VERCEL_ORG_ID`, `VERCEL_PROJECT_ID` — for Vercel Action (optional if using Vercel GitHub integration)
- `DATABASE_URL` — production Postgres connection string
- `JWT_SECRET` — application JWT secret
- `REDIS_URL` — connection string for Redis
- Any provider-specific keys (Stripe, Sentry, etc.)

Local Fly deploy (quick)

1. Install `flyctl`: https://fly.io/docs/hands-on/install-flyctl/
2. Login and deploy from `api/`:

```bash
flyctl auth login
cd api
flyctl launch --name infamous-api --region ord --no-deploy
# verify fly.toml, then:
flyctl deploy
```

3. Set secrets on Fly:

```bash
flyctl secrets set DATABASE_URL="postgres://..." JWT_SECRET="..." REDIS_URL="..."
```

Notes about CI workflows added

- `.github/workflows/deploy-fly.yml` — builds `api` and deploys to Fly on pushes to `main`.
- `.github/workflows/deploy-vercel.yml` — builds `web` and deploys to Vercel on pushes to `main` (requires Vercel secrets).

Post-deploy smoke checks (recommended)

- Call `/api/health` and a couple of critical endpoints (login/create shipment) via a small test script or GitHub Actions job.

Smoke test configuration

- Add the following repository secrets to enable automated smoke tests after deploys:
  - `PROD_API_BASE_URL` — e.g. https://api.yourdomain.com
  - `PROD_WEB_BASE_URL` — e.g. https://yourdomain.com

The repository includes `tools/smoke/check.js` and `.github/workflows/smoke-tests.yml` which run after successful deploy workflows and will fail the workflow if health checks do not return 2xx.

Extended smoke tests

- To run E2E-style smoke checks after deploys, set the `SMOKE_ENDPOINTS` repository secret to a comma-separated list of relative API paths, for example:
  - `SMOKE_ENDPOINTS=/api/auth/login,/api/shipments/create`

- The workflow `.github/workflows/pr-smoke-report.yml` runs after a merged PR, executes `tools/smoke/extended_check.js` (which uses `PROD_API_BASE_URL`/`PROD_WEB_BASE_URL` and `SMOKE_ENDPOINTS`) and posts a comment on the PR with the result.

## Setting up GitHub secrets

Refer to `SECRETS_CHECKLIST.md` for details on each secret and provider setup.

Quick start:

1. Install GitHub CLI: https://cli.github.com/
2. Run: `bash scripts/set-secrets.sh` (interactive prompts for each secret)
3. Or use: `gh secret set <KEY> --body "<VALUE>" --repo MrMiless44/Infamous-freight-enterprises`
4. Copy/paste commands from `GH_SECRET_COMMANDS.md` for quick setup

## Merging and triggering deployments

Once all secrets are configured:

1. Merge branch `chore/fix/shared-workspace-ci` to `main`:

   ```bash
   git checkout main
   git merge chore/fix/shared-workspace-ci
   git push origin main
   ```

   Or merge via GitHub PR #268 UI.

2. This triggers three workflows in parallel:
   - `.github/workflows/deploy-fly.yml` — builds and deploys API to Fly.io
   - `.github/workflows/deploy-vercel.yml` — builds and deploys Web to Vercel
   - `.github/workflows/deploy-render.yml` — (optional) triggers Render deploy if secrets provided

3. After successful deploys, `.github/workflows/smoke-tests.yml` runs and validates:
   - `PROD_API_BASE_URL/api/health` returns 2xx
   - `PROD_WEB_BASE_URL/` returns 2xx
   - Any custom endpoints in `SMOKE_ENDPOINTS`

4. After PR merge, `.github/workflows/pr-smoke-report.yml` runs and posts a comment on PR #268 with smoke-test results.

## Monitoring deployments

- Watch **Actions** tab in GitHub to see live deploy status.
- Once API is deployed, verify: `curl https://api.example.com/api/health`
- Once Web is deployed, verify: `curl https://example.com/`
- Check Fly.io logs: `flyctl logs --app infamous-freight-api`
- Check Vercel logs: Visit Vercel project dashboard → Deployments

## Rollback and troubleshooting

- **Fly rollback**: `flyctl releases --app infamous-freight-api` and `flyctl releases rollback --app infamous-freight-api`
- **Vercel rollback**: Via Vercel dashboard → Deployments → select previous build → Rollback
- **Check API logs**: `flyctl logs --app infamous-freight-api | tail -100`
- **Health check failures**: Verify env vars are set correctly on provider (flyctl secrets list, Vercel env vars dashboard)
