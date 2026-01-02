# 🎯 Quick Start Checklist — 5-Minute Setup

Follow these steps in order to deploy Infamous Freight Enterprises to production.

## Step 1️⃣: Install GitHub CLI (if needed)

```bash
# macOS
brew install gh

# Linux (Alpine in devcontainer)
apk add gh

# Windows
choco install gh

# Or download: https://cli.github.com/
```

Verify installation:

```bash
gh --version
```

## Step 2️⃣: Authenticate to GitHub

```bash
gh auth login
# Follow prompts to authenticate
```

Verify authentication:

```bash
gh auth status
```

## Step 3️⃣: Run Quick Start Script

This script will interactively set all GitHub secrets and merge to main:

```bash
bash QUICKSTART.sh
```

**What it does:**

1. ✅ Verifies GitHub CLI is installed and authenticated
2. ✅ Prompts for each secret value (12 total)
3. ✅ Sets secrets in GitHub repository
4. ✅ Asks if you want to merge `chore/fix/shared-workspace-ci` to `main`
5. ✅ Merges and pushes to main (triggers deployments)

**Required secrets to have ready:**

- `FLY_API_TOKEN` — from https://fly.io/user/personal_access_tokens
- `PROD_API_BASE_URL` — e.g., `https://api.example.com`
- `PROD_WEB_BASE_URL` — e.g., `https://example.com`
- `VERCEL_TOKEN` — from https://vercel.com/account/tokens
- `VERCEL_ORG_ID` — from Vercel project settings
- `VERCEL_PROJECT_ID` — from Vercel project settings
- `DATABASE_URL` — Postgres connection string
- `JWT_SECRET` — strong random string
- `REDIS_URL` — Redis connection string
- `RENDER_API_KEY`, `RENDER_SERVICE_ID` (optional)
- `SMOKE_ENDPOINTS` (optional)

## Step 4️⃣: Monitor GitHub Actions

After merge, watch deployments:

```bash
# View status in terminal
gh run list --repo MrMiless44/Infamous-freight-enterprises --limit 5

# Or visit in browser
open https://github.com/MrMiless44/Infamous-freight-enterprises/actions
```

**Expected workflows to run:**

1. `deploy-fly.yml` → builds & deploys API to Fly.io (5-10 min)
2. `deploy-vercel.yml` → builds & deploys Web to Vercel (3-5 min)
3. `smoke-tests.yml` → validates health endpoints (1 min)
4. `pr-smoke-report.yml` → posts PR comment with results (1 min)

## Step 5️⃣: Validate Deployments

Once all workflows pass, run the validation script:

```bash
bash VALIDATE.sh
```

**What it checks:**

- ✅ API `/api/health` endpoint returns 200
- ✅ Web `/` root returns 200
- ✅ API `/api/shipments` returns 401 (protected, good!)
- ✅ Summary of pass/fail

## ⏱️ Total Time

- Setup: 5 minutes (running QUICKSTART.sh)
- Deploy: 15-30 minutes (GitHub Actions)
- Validation: 2 minutes (running VALIDATE.sh)

**Total: ~30-40 minutes from start to production**

---

## 🆘 If Something Goes Wrong

### Merge failed / git conflicts

```bash
# Manual merge steps:
git checkout main
git pull origin main
git merge chore/fix/shared-workspace-ci
# Resolve any conflicts, then:
git add .
git commit -m "merge: chore/fix/shared-workspace-ci"
git push origin main
```

### Deployment failed

1. Check GitHub Actions logs for error message
2. Verify all secrets are set: `gh secret list --repo MrMiless44/Infamous-freight-enterprises`
3. Check provider logs:
   - **Fly.io**: `flyctl logs --app infamous-freight-api`
   - **Vercel**: Visit dashboard → Deployments tab
4. If DB/Redis issue: ensure `DATABASE_URL` and `REDIS_URL` are correct

### Health check failed

1. Wait 30-60 seconds (services may be starting)
2. Manual check: `curl https://api.example.com/api/health`
3. Check logs: `flyctl logs --app infamous-freight-api | tail -50`

### Smoke tests failed

1. Verify `PROD_API_BASE_URL` and `PROD_WEB_BASE_URL` are set correctly
2. Ensure URLs are publicly accessible (not localhost)
3. Check `.github/workflows/smoke-tests.yml` logs in GitHub Actions

---

## 📞 Support

**Quick reference docs:**

- [FINAL_DEPLOYMENT_SUMMARY.md](FINAL_DEPLOYMENT_SUMMARY.md) — Full overview
- [DEPLOYMENT_README.md](DEPLOYMENT_README.md) — Deploy, monitor, rollback
- [SECRETS_CHECKLIST.md](SECRETS_CHECKLIST.md) — Secrets provider setup
- [GH_SECRET_COMMANDS.md](GH_SECRET_COMMANDS.md) — Copy/paste `gh` commands

**Commands to troubleshoot:**

```bash
# List all secrets
gh secret list --repo MrMiless44/Infamous-freight-enterprises

# View recent actions/deployments
gh run list --repo MrMiless44/Infamous-freight-enterprises --limit 10

# Check git log for merge
git log --oneline -5

# View Fly logs (requires flyctl auth login first)
flyctl logs --app infamous-freight-api
```

---

**Ready?** → Run `bash QUICKSTART.sh` now! 🚀
