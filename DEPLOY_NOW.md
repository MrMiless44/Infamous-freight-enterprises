# 🚀 AUTO DEPLOY NOW — One-Command Production Deployment

**Status**: ✅ All infrastructure ready. Execute below to go live.

**Time to live**: ~30-40 minutes total (5 min setup + 20-30 min deployments)

---

## 🎯 Quick Deploy (Choose One Option)

### Option A: Full Auto (Recommended)

Runs everything interactively (secrets setup + merge + deploy):

```bash
bash QUICKSTART.sh
```

What it does:

1. ✅ Prompts for all 12 GitHub secrets
2. ✅ Sets secrets in GitHub repository
3. ✅ Merges `chore/fix/shared-workspace-ci` to `main`
4. ✅ Pushes to origin (triggers all deploy workflows)
5. ✅ Shows you where to watch deployments

**Recommended for most users** — Interactive, safe, no silent failures.

---

### Option B: Manual Merge (Fast)

If secrets are already set in GitHub:

```bash
# Merge locally
git checkout main
git pull origin main
git merge chore/fix/shared-workspace-ci
git push origin main

# Watch deployments
open https://github.com/MrMiless44/Infamous-freight-enterprises/actions
```

---

### Option C: Direct GitHub Merge (Fastest)

If you want to merge via GitHub PR UI:

1. Go to: https://github.com/MrMiless44/Infamous-freight-enterprises/pull/268
2. Scroll to bottom → "Merge pull request"
3. Confirm merge
4. Deployments auto-start

---

## 📝 Pre-Deploy Checklist (Before Running Above)

- [ ] GitHub CLI installed: `brew install gh` or download https://cli.github.com/
- [ ] Logged in to GitHub: `gh auth login`
- [ ] Have Fly.io API token ready: https://fly.io/user/personal_access_tokens
- [ ] Have Vercel secrets ready (or skip if using Vercel GitHub integration)
- [ ] Production URLs ready (e.g., `https://api.example.com`)
- [ ] Postgres connection string ready
- [ ] Redis connection string ready
- [ ] JWT secret generated (strong random string)

---

## ⏱️ Timeline

```
T+0 min:   Run bash QUICKSTART.sh (or merge manually)
T+5 min:   All secrets set, branch merged to main
T+5 min:   GitHub Actions auto-triggers deploy workflows
T+10 min:  Fly.io API build completes, deployment starts
T+15 min:  Vercel Web build completes, deployment starts
T+20 min:  API live at PROD_API_BASE_URL
T+23 min:  Web live at PROD_WEB_BASE_URL
T+24 min:  Smoke tests run and validate health endpoints
T+25 min:  PR comment posted with smoke test results
T+30 min:  Total setup → production live

Then: Run bash VALIDATE.sh to verify
```

---

## 🔍 What Gets Deployed

**API (Fly.io)**

- Express.js server from `src/apps/api/`
- Shared packages from `src/packages/shared/`
- Prisma ORM + database migrations
- Health checks at `/api/health`
- All environment variables from GitHub Secrets

**Web (Vercel)**

- Next.js 14 app from `src/apps/web/`
- SSR/SSG optimized builds
- Image optimization enabled
- Analytics & performance monitoring
- All environment variables from Vercel dashboard

**Monitoring**

- Smoke tests on every deploy
- PR comments with results
- Health endpoint validation
- Logs available in provider dashboards

---

## 📊 What Happens Automatically

Once you run the deploy command:

1. ✅ **CI Pipeline Runs** (GitHub Actions)
   - Install dependencies
   - Run tests (if any)
   - Build shared packages
   - Build API for Docker
   - Build Web for Node/Vercel

2. ✅ **Deployment Workflows Execute**
   - Fly.io: Build Docker image → deploy API
   - Vercel: Build Next.js → deploy Web
   - Render: Trigger deploy (if configured)

3. ✅ **Health Checks Run**
   - Validate `/api/health` returns 200
   - Validate `/` returns 200
   - Custom endpoints (if SMOKE_ENDPOINTS set)

4. ✅ **PR Comment Posted**
   - Results posted to PR #268
   - Shows pass/fail status
   - Links to deployments

5. ✅ **Services Live**
   - API available at PROD_API_BASE_URL
   - Web available at PROD_WEB_BASE_URL
   - All logs in provider dashboards

---

## 🛑 If Something Fails

### During setup (bash QUICKSTART.sh)

- **"gh not found"** → Install GitHub CLI: https://cli.github.com/
- **"Not authenticated"** → Run: `gh auth login`
- **"Secret set failed"** → Check permissions on GitHub (must be repo owner/admin)

### During deploy (GitHub Actions)

- **"FLY_API_TOKEN not found"** → Secret not set correctly
- **"Build failed"** → Check logs in GitHub Actions tab
- **"Deploy failed"** → Check Fly.io logs: `flyctl logs --app infamous-freight-api`

### After deploy (endpoints down)

- **"Connection refused"** → Services still starting, wait 30 seconds
- **"502 Bad Gateway"** → Check logs, verify env vars
- **"Smoke tests failed"** → Verify PROD\_\* URLs are correct and publicly accessible

---

## 📞 Next Steps After Deploy

1. **Immediately after merge (watch Actions)**

   ```bash
   gh run list --repo MrMiless44/Infamous-freight-enterprises --limit 5
   ```

2. **Once all workflows pass (15-30 min)**

   ```bash
   bash VALIDATE.sh
   ```

3. **Verify live endpoints**

   ```bash
   curl https://api.example.com/api/health
   curl https://example.com/
   ```

4. **Check logs**

   ```bash
   # API logs
   flyctl logs --app infamous-freight-api

   # Web logs
   # → Visit Vercel dashboard → Deployments tab
   ```

5. **Manual smoke tests (recommended)**
   - Test user login/registration
   - Create a test shipment
   - Track delivery in real-time

---

## ✨ Success Criteria

✅ **Deployment is successful when:**

- All GitHub Actions workflows show green checkmarks
- `/api/health` returns HTTP 200
- Web root `/` returns HTTP 200
- PR #268 has smoke-test comment with all tests passing
- Services are responding to requests
- Logs show no ERROR level messages

---

**Ready?** → Run one of the commands above now! 🚀

```bash
# Most recommended:
bash QUICKSTART.sh
```
