#!/usr/bin/env bash
set -euo pipefail

# Quick Start for Infamous Freight Enterprises
# Run this script on your local machine after cloning the repo

echo "🚀 Infamous Freight Enterprises - Quick Start"
echo "=============================================="
echo ""

# Step 1: Verify environment
echo "✓ Verifying Node, pnpm, and PATH..."
node -v
pnpm -v
which tsc || echo "  ℹ️  tsc will be available after deps install"

# Step 2: Set environment variables
echo ""
echo "✓ Setting environment variables..."
export NEXT_PUBLIC_API_URL=http://localhost:4000/api
export API_BASE_URL=http://localhost:4000/api
echo "  NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL"
echo "  API_BASE_URL=$API_BASE_URL"

# Step 3: Type check
echo ""
echo "✓ Running type checks..."
pnpm check:types

# Step 4: Start dev servers
echo ""
echo "✓ Starting dev servers (API, Web, Shared)..."
echo "  API:    http://localhost:4000"
echo "  Web:    http://localhost:3000"
echo "  Health: http://localhost:3000/health"
echo ""

pnpm -r --parallel --filter infamous-freight-api --filter infamous-freight-web --filter @infamous-freight/shared dev
