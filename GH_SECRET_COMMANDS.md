# GitHub Secrets Setup — Copy/Paste Commands

Use these `gh` CLI commands to set secrets. Run each locally after `gh auth login`.

Replace example values with your actual credentials.

```bash
# Fly.io
gh secret set FLY_API_TOKEN --body "YOUR_FLY_API_TOKEN" --repo MrMiless44/Infamous-freight-enterprises

# Production URLs
gh secret set PROD_API_BASE_URL --body "https://api.example.com" --repo MrMiless44/Infamous-freight-enterprises
gh secret set PROD_WEB_BASE_URL --body "https://example.com" --repo MrMiless44/Infamous-freight-enterprises

# Vercel
gh secret set VERCEL_TOKEN --body "YOUR_VERCEL_TOKEN" --repo MrMiless44/Infamous-freight-enterprises
gh secret set VERCEL_ORG_ID --body "YOUR_VERCEL_ORG_ID" --repo MrMiless44/Infamous-freight-enterprises
gh secret set VERCEL_PROJECT_ID --body "YOUR_VERCEL_PROJECT_ID" --repo MrMiless44/Infamous-freight-enterprises

# Render (optional)
gh secret set RENDER_API_KEY --body "YOUR_RENDER_API_KEY" --repo MrMiless44/Infamous-freight-enterprises
gh secret set RENDER_SERVICE_ID --body "YOUR_RENDER_SERVICE_ID" --repo MrMiless44/Infamous-freight-enterprises

# Database & Auth
gh secret set DATABASE_URL --body "postgres://user:password@host:5432/dbname" --repo MrMiless44/Infamous-freight-enterprises
gh secret set JWT_SECRET --body "YOUR_STRONG_JWT_SECRET" --repo MrMiless44/Infamous-freight-enterprises
gh secret set REDIS_URL --body "redis://:password@host:6379" --repo MrMiless44/Infamous-freight-enterprises

# Smoke tests (optional)
gh secret set SMOKE_ENDPOINTS --body "/api/auth/login,/api/shipments/create" --repo MrMiless44/Infamous-freight-enterprises
```

Or run the interactive script:

```bash
bash scripts/set-secrets.sh
```

Verify secrets were added:

```bash
gh secret list --repo MrMiless44/Infamous-freight-enterprises
```
