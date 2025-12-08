# Vercel Environment Variables

## Required
NEXT_PUBLIC_APP_NAME=Infamous Freight
NEXT_PUBLIC_ENV=production
NEXT_PUBLIC_API_BASE=https://your-api.fly.dev/api

## Optional
STRIPE_PUBLIC_KEY=
PAYPAL_CLIENT_ID=

## Notes
- Only the web app deploys to Vercel.
- API calls should route to Fly.io or Render via `NEXT_PUBLIC_API_BASE`.
- Update `vercel.json` rewrites if you add custom domains.
