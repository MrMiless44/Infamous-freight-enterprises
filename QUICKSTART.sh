#!/bin/bash
# QUICKSTART.sh — Automated setup for Infamous Freight Enterprises deployment
# Run this script to set GitHub secrets and merge to main (requires GitHub CLI)
# Usage: bash QUICKSTART.sh

set -e

echo "🚀 Infamous Freight Enterprises — Deployment Quick Start"
echo "============================================================"
echo ""
echo "This script will:"
echo "  1. Verify GitHub CLI is installed"
echo "  2. Verify you're authenticated to GitHub"
echo "  3. Set all required repository secrets interactively"
echo "  4. Prepare branch for merge to main"
echo ""
echo "Prerequisites:"
echo "  - GitHub CLI installed: https://cli.github.com/"
echo "  - Logged in to GitHub: gh auth login"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 1
fi

# Check GitHub CLI is installed
if ! command -v gh &> /dev/null; then
  echo "❌ GitHub CLI not found. Install from: https://cli.github.com/"
  exit 1
fi
echo "✓ GitHub CLI found"

# Check authenticated
if ! gh auth status &> /dev/null; then
  echo "❌ Not authenticated to GitHub. Run: gh auth login"
  exit 1
fi
echo "✓ Authenticated to GitHub"

# Repository
REPO="MrMiless44/Infamous-freight-enterprises"
echo "✓ Using repo: $REPO"
echo ""

# Array of required secrets and descriptions
declare -A SECRETS=(
  ["FLY_API_TOKEN"]="Fly.io API token (from https://fly.io/user/personal_access_tokens)"
  ["PROD_API_BASE_URL"]="Production API base URL (e.g., https://api.example.com)"
  ["PROD_WEB_BASE_URL"]="Production web URL (e.g., https://example.com)"
  ["VERCEL_TOKEN"]="Vercel personal access token (from https://vercel.com/account/tokens)"
  ["VERCEL_ORG_ID"]="Vercel organization ID"
  ["VERCEL_PROJECT_ID"]="Vercel web project ID"
  ["RENDER_API_KEY"]="Render API key (optional, leave blank to skip)"
  ["RENDER_SERVICE_ID"]="Render service ID (optional, leave blank to skip)"
  ["DATABASE_URL"]="Production Postgres connection string (postgres://user:pass@host:5432/db)"
  ["JWT_SECRET"]="Application JWT secret (strong, random string)"
  ["REDIS_URL"]="Redis connection string (redis://:password@host:6379)"
  ["SMOKE_ENDPOINTS"]="Optional: comma-separated API paths (/api/auth/login,/api/shipments/create)"
)

echo "📝 Setting GitHub Secrets..."
echo ""

set_secret() {
  local key=$1
  local description=$2
  echo ""
  echo "Enter value for: $key"
  echo "  Description: $description"
  read -p "Value (or press Enter to skip): " value

  if [ -n "$value" ]; then
    echo "Setting $key..."
    gh secret set "$key" --body "$value" --repo "$REPO"
    echo "✓ $key set successfully"
  else
    echo "⊘ Skipped $key"
  fi
}

for secret in "${!SECRETS[@]}"; do
  set_secret "$secret" "${SECRETS[$secret]}"
done

echo ""
echo "✓ Secrets configured!"
echo ""
echo "📋 Current secrets:"
gh secret list --repo "$REPO" || echo "Could not list secrets"
echo ""

# Merge to main
echo ""
read -p "Ready to merge chore/fix/shared-workspace-ci to main? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "🔀 Merging to main..."
  git checkout main
  git pull origin main
  git merge chore/fix/shared-workspace-ci -m "merge: chore/fix/shared-workspace-ci into main (deployment setup complete)"
  git push origin main
  echo "✓ Merged to main!"
  echo ""
  echo "✨ Deployment triggered! Watch GitHub Actions:"
  echo "   https://github.com/$REPO/actions"
  echo ""
  echo "Once deploys complete, run:"
  echo "  bash VALIDATE.sh"
else
  echo "⊘ Skipped merge. Merge manually when ready:"
  echo "  git checkout main"
  echo "  git merge chore/fix/shared-workspace-ci"
  echo "  git push origin main"
fi

echo ""
echo "✅ Quick start complete!"
