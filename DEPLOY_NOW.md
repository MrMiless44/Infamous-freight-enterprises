# 🚀 LIVE DEPLOYMENT GUIDE

**Target Time**: 15 minutes | **Status**: Ready to Deploy

---

## 📋 Pre-Deployment Checklist

Before starting, verify everything is ready:

```bash
# ✅ All code committed
git log --oneline | head -5
# Should show your deployment commits

# ✅ All dependencies installed
ls api/node_modules/compression
# Should exist

# ✅ Repository is public
# (required for Vercel/Fly.io to access)
```

---

## 🌐 STEP 1: Deploy Web to Vercel (3-5 minutes)

### 1.1 Go to Vercel

- Open: https://vercel.com
- Click: **Login** (or Sign Up)
- Select: **GitHub** authentication

### 1.2 Import Repository

- Click: **"Add New..."** → **Project**
- Select: **GitHub** as source
- Search: `Infamous-freight-enterprises`
- Click: **Import**

### 1.3 Configure Project

```
Framework: Next.js ✅ (auto-detected)
Root Directory: ./web ✅ (auto-detected)
Environment Variables:
  - NEXT_PUBLIC_API_URL: (leave blank for now, add later)
  - NEXT_PUBLIC_ENV: production
```

### 1.4 Deploy

- Click: **Deploy**
- Wait: ~3-5 minutes for build
- Look for: ✅ **Deployment successful!**

### 1.5 Get Your URL

- Copy the deployment URL: `https://infamous-freight-enterprises-XXXXX.vercel.app`
- Save for later (needed for API config)

**Status After Step 1**: ✅ Web is live!

```
Your web app is now at: https://infamous-freight-enterprises-XXXXX.vercel.app
```

---

## 🔧 STEP 2: Deploy API to Fly.io (5-10 minutes)

### 2.1 Go to Fly.io

- Open: https://fly.io
- Click: **Sign Up** or **Login** with GitHub
- Authorize GitHub access

### 2.2 Create App from GitHub

- Click: **"Create an app"**
- Select: **GitHub** repository
- Search: `Infamous-freight-enterprises`
- Click: **Select**

### 2.3 Choose App Name

```
Suggested: infamous-freight-api-prod
Or: infamous-api-<yourname>
```

### 2.4 Choose Region

```
Recommended: Pick closest to your users
- us-west: For US West Coast
- us-east: For US East Coast
- eu-west: For Europe
- ap-northeast: For Asia
```

### 2.5 Select Environment Variables

Set these required variables:

```env
# Database (you'll add after)
DATABASE_URL=postgresql://...

# JWT Secret (IMPORTANT: Generate new one)
JWT_SECRET=your-super-secret-key-generate-a-new-one

# Monitoring
DD_TRACE_ENABLED=true
DD_SERVICE=infamous-freight-api
DD_ENV=production

# API
NODE_ENV=production
API_PORT=8080

# AI
AI_PROVIDER=synthetic

# Optional but recommended
SENTRY_DSN=https://key@sentry.io/projectid
LOG_LEVEL=info
```

### 2.6 Deploy

- Click: **Deploy**
- Wait: ~5-10 minutes for build
- Look for: ✅ **Deployment successful!**

### 2.7 Get Your URL

- Copy the deployment URL: `https://infamous-freight-api-prod.fly.dev`
- This is your API URL

**Status After Step 2**: ✅ API is live!

```
Your API is now at: https://infamous-freight-api-prod.fly.dev
```

---

## 🔗 STEP 3: Connect Web to API (2 minutes)

### 3.1 Update Web Environment Variables

- Go back to **Vercel Dashboard**
- Select your project
- Settings → **Environment Variables**
- Add:

```
Name: NEXT_PUBLIC_API_URL
Value: https://infamous-freight-api-prod.fly.dev
```

### 3.2 Redeploy Web

- Go to **Deployments**
- Click the three dots on latest deployment
- Click: **Redeploy**
- Wait: ~2-3 minutes

**Status After Step 3**: ✅ Web and API are connected!

---

## 💾 STEP 4: Setup Database (5-10 minutes)

### 4.1 Option A: Use External PostgreSQL (Recommended for Speed)

**Vercel PostgreSQL** (easiest):

```
1. Go to Vercel dashboard
2. Storage → Create Database → PostgreSQL
3. Copy connection string
4. Add to Fly.io environment variables:
   DATABASE_URL=<connection-string>
```

**Or Railway.app**:

```
1. Go to railway.app
2. Create new project
3. Add PostgreSQL database
4. Copy connection string
5. Add to Fly.io secrets
```

### 4.2 Option B: Create Database on Fly.io

```bash
# If you have Fly CLI installed
flyctl postgres create --name infamous-db
flyctl postgres attach --app infamous-freight-api-prod

# Copy the connection string from output
# Add to environment variables
```

### 4.3 Option C: Use Existing Database

If you already have a database, just add the connection string to Fly.io:

- Fly.io Dashboard → Settings → Secrets
- Add: `DATABASE_URL=postgresql://...`

### 4.4 Run Migrations

Once DATABASE_URL is set on Fly.io:

```bash
# Option 1: Use Fly CLI (if installed)
flyctl ssh console --app infamous-freight-api-prod
cd api && pnpm prisma:migrate:prod

# Option 2: Via GitHub Actions (if configured)
# Just push to main and it runs automatically

# Option 3: Manual via psql
psql $DATABASE_URL < scripts/db-indexes.sql
```

**Status After Step 4**: ✅ Database is connected!

---

## ✅ STEP 5: Verify Everything is Working (5 minutes)

### 5.1 Test Web App

```bash
# Open in browser
https://infamous-freight-enterprises-XXXXX.vercel.app

# Should see:
# ✅ Your web app loads
# ✅ No 404 errors
# ✅ Images load
# ✅ UI responsive
```

### 5.2 Test API Health

```bash
# In terminal or browser
curl https://infamous-freight-api-prod.fly.dev/api/health

# Expected response:
# {
#   "success": true,
#   "data": {
#     "status": "ok",
#     "uptime": 123.45,
#     "database": "connected"
#   }
# }
```

### 5.3 Test Compression

```bash
# Check response compression is working
curl -v https://infamous-freight-api-prod.fly.dev/api/health 2>&1 | grep -i "content-encoding"

# Should show:
# content-encoding: gzip
```

### 5.4 Monitor Logs

```bash
# Vercel
# Dashboard → Deployments → Function Logs
# Look for: compression middleware, Web Vitals tracking

# Fly.io
# flyctl logs --app infamous-freight-api-prod
# Look for: listening on, compression middleware, DD_TRACE_ENABLED
```

**Status After Step 5**: ✅ Everything is working!

---

## 🎯 Success Indicators

After deployment, you should see:

### ✅ Web (Vercel)

- [ ] Site loads at https://infamous-freight-enterprises-XXXXX.vercel.app
- [ ] No console errors
- [ ] Images load correctly
- [ ] Can navigate between pages
- [ ] API calls to /api/health succeed

### ✅ API (Fly.io)

- [ ] Health check returns 200: `/api/health`
- [ ] Compression working: `Content-Encoding: gzip`
- [ ] Database connected: `"database": "connected"`
- [ ] Monitoring active: Check Datadog dashboard
- [ ] Logs show: `listening on 0.0.0.0:8080`

### ✅ Monitoring

- [ ] Datadog APM dashboard shows traces
- [ ] Vercel Analytics shows page views
- [ ] Web Vitals data appearing in Vercel

---

## 📊 Deployment Checklist

### Pre-Deployment

- [ ] All code committed to main
- [ ] Dependencies installed
- [ ] Repository is public

### Vercel (Web)

- [ ] Project imported
- [ ] Framework auto-detected
- [ ] Deploy clicked
- [ ] Deployment successful
- [ ] URL noted

### Fly.io (API)

- [ ] Project created
- [ ] Environment variables set
- [ ] Deploy clicked
- [ ] Deployment successful
- [ ] URL noted

### Connection

- [ ] Web environment variables updated
- [ ] Web redeployed
- [ ] API and Web can communicate

### Database

- [ ] Database created or connected
- [ ] CONNECTION_STRING set
- [ ] Migrations run
- [ ] Indexes created

### Verification

- [ ] Web loads in browser
- [ ] API health check works
- [ ] Compression is active
- [ ] Monitoring is reporting

---

## 🚨 Troubleshooting

### Web Won't Deploy

**Issue**: Build fails on Vercel
**Solution**:

```bash
# Check build locally
cd web
pnpm build

# Fix any errors
# Commit and push to main
# Vercel will auto-redeploy
```

### API Won't Start

**Issue**: Deployment fails on Fly.io
**Solution**:

```bash
# Check logs
flyctl logs --app infamous-freight-api-prod

# Common issues:
# - DATABASE_URL not set → Add to secrets
# - JWT_SECRET not set → Add to secrets
# - Port binding issue → Should use port 8080

# Fix and retry
flyctl deploy
```

### API Returns 500

**Issue**: API is running but returns errors
**Solution**:

```bash
# Check logs
flyctl logs --app infamous-freight-api-prod

# Common issues:
# - Database connection failed → Check DATABASE_URL
# - Prisma migration not run → Run: pnpm prisma:migrate:prod
# - Insufficient permissions → Check JWT_SECRET

# Fix in code, commit, push
# Fly.io auto-redeploys
```

### Web Can't Reach API

**Issue**: Web app loads but API calls fail
**Solution**:

```bash
# Check environment variable
# Vercel Dashboard → Environment Variables
# NEXT_PUBLIC_API_URL should be set

# Should be:
NEXT_PUBLIC_API_URL=https://infamous-freight-api-prod.fly.dev

# Redeploy web
# This will rebuild and pick up the new variable
```

### Database Connection Fails

**Issue**: "Error: connect ECONNREFUSED"
**Solution**:

```bash
# Test connection string locally
psql $DATABASE_URL -c "SELECT 1"

# If fails:
# - DATABASE_URL syntax is wrong
# - Database doesn't exist
# - Connection string is invalid

# Get correct connection string:
# - Vercel Postgres: Copy from dashboard
# - Railway: Copy from dashboard
# - Fly Postgres: Output from setup
# - External: Get from provider

# Update on Fly.io
flyctl secrets set DATABASE_URL=correct-string
```

---

## 📞 Quick Reference

### Links

- **Vercel Dashboard**: https://vercel.com/dashboard
- **Fly.io Dashboard**: https://fly.io/dashboard
- **GitHub Repo**: https://github.com/MrMiless44/Infamous-freight-enterprises

### After Deployment

- **Web URL**: https://infamous-freight-enterprises-XXXXX.vercel.app
- **API URL**: https://infamous-freight-api-prod.fly.dev
- **Health Check**: https://infamous-freight-api-prod.fly.dev/api/health

### Environment Variables (Remember These)

```
Web (Vercel):
- NEXT_PUBLIC_API_URL=<your-api-url>
- NEXT_PUBLIC_ENV=production

API (Fly.io):
- DATABASE_URL=<your-db-connection>
- JWT_SECRET=<generate-new-secret>
- DD_TRACE_ENABLED=true
- NODE_ENV=production
```

---

## 🎉 You're Done!

Once all 5 steps are complete:

✅ **Your application is LIVE!**

- Web: https://infamous-freight-enterprises-XXXXX.vercel.app
- API: https://infamous-freight-api-prod.fly.dev
- Database: Connected and indexed
- Monitoring: Active (Datadog, Vercel Analytics)
- Updates: Auto-deploy on git push

**Total Time**: ~15-20 minutes

---

## 📊 What's Deployed

### Performance Features ✅

- Response compression (60-70% reduction)
- Request caching
- Database indexes (9 optimized)
- Image optimization

### Monitoring ✅

- Datadog APM (automatic tracing)
- Vercel Analytics (web metrics)
- Web Vitals tracking (LCP/FID/CLS)
- Sentry error tracking (when DSN added)

### Security ✅

- JWT authentication
- Rate limiting
- CORS headers
- Security headers
- Input validation

---

**🚀 Ready to go live? Follow the steps above!**

**Questions?** Check:

- NEXT_STEPS.md - Quick reference
- QUICK_DEPLOYMENT.md - Detailed guide
- PERFORMANCE_MONITORING_COMPLETE.md - Full documentation
