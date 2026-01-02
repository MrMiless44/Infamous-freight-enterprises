#!/bin/bash
# set-secrets.sh — Interactive script to set GitHub repository secrets via gh CLI
# Run this locally after installing GitHub CLI: https://cli.github.com/
# Usage: bash scripts/set-secrets.sh

set -e

REPO="${1:-MrMiless44/Infamous-freight-enterprises}"
echo "Setting secrets for repository: $REPO"
echo ""
echo "Ensure you have logged in with GitHub CLI:"
echo "  gh auth login"
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
  ["DATABASE_URL"]="Production Postgres connection string (e.g., postgres://user:pass@host:5432/db)"
  ["JWT_SECRET"]="Application JWT secret (strong, random string)"
  ["REDIS_URL"]="Redis connection string (e.g., redis://:password@host:6379)"
  ["SMOKE_ENDPOINTS"]="Optional: comma-separated API paths for smoke tests (e.g., /api/auth/login,/api/shipments/create)"
)

# Function to prompt and set a secret
set_secret() {
  local key=$1
  local description=$2
  echo ""
  echo "Enter value for $key:"
  echo "  ($description)"
  read -p "Value (or leave blank to skip): " value

  if [ -n "$value" ]; then
    echo "Setting $key..."
    gh secret set "$key" --body "$value" --repo "$REPO"
    echo "✓ $key set successfully"
  else
    echo "⊘ Skipped $key"
  fi
}

# Loop through all secrets
for secret in "${!SECRETS[@]}"; do
  set_secret "$secret" "${SECRETS[$secret]}"
done

echo ""
echo "✓ All secrets configured!"
echo ""
echo "Next steps:"
echo "  1. Verify secrets were added: gh secret list --repo $REPO"
echo "  2. Merge branch chore/fix/shared-workspace-ci to main"
echo "  3. Watch GitHub Actions for deploy workflows"
echo "  4. Verify production endpoints using smoke tests"
