#!/bin/bash
# VALIDATE.sh — Post-deployment validation script
# Run this after successful deploys to verify endpoints are live and healthy
# Usage: bash VALIDATE.sh

set -e

echo "🔍 Infamous Freight Enterprises — Post-Deployment Validation"
echo "=============================================================="
echo ""

# Get production URLs from environment or user input
read -p "Enter Production API base URL (e.g., https://api.example.com): " API_BASE
read -p "Enter Production Web URL (e.g., https://example.com): " WEB_BASE

# Trim trailing slashes
API_BASE="${API_BASE%/}"
WEB_BASE="${WEB_BASE%/}"

echo ""
echo "Validating endpoints..."
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

passed=0
failed=0

# Test function
test_endpoint() {
  local name=$1
  local url=$2
  local expected_status=$3
  
  echo -n "Testing $name ... "
  
  response=$(curl -s -w "\n%{http_code}" "$url" 2>/dev/null || echo "error")
  http_code=$(echo "$response" | tail -n 1)
  body=$(echo "$response" | head -n -1)
  
  if [ "$http_code" = "$expected_status" ]; then
    echo -e "${GREEN}✓ OK${NC} (HTTP $http_code)"
    ((passed++))
  else
    echo -e "${RED}✗ FAILED${NC} (expected $expected_status, got $http_code)"
    ((failed++))
  fi
}

echo "📡 Health Checks"
test_endpoint "API Health" "$API_BASE/api/health" "200"
test_endpoint "Web Root" "$WEB_BASE/" "200"

echo ""
echo "🔗 Additional Checks"
test_endpoint "API /api/shipments (unauthorized)" "$API_BASE/api/shipments" "401"
echo ""

# Summary
echo "Summary"
echo "======="
echo -e "${GREEN}Passed: $passed${NC}"
echo -e "${RED}Failed: $failed${NC}"

if [ $failed -eq 0 ]; then
  echo ""
  echo -e "${GREEN}✅ All validation checks passed!${NC}"
  echo ""
  echo "Next steps:"
  echo "  1. Check GitHub Actions logs for any errors"
  echo "  2. Review smoke-test results in PR #268 comments"
  echo "  3. Test critical flows manually:"
  echo "     - User login/registration"
  echo "     - Create new shipment"
  echo "     - Track delivery"
  echo "  4. Monitor logs: flyctl logs --app infamous-freight-api"
  echo "  5. Check Vercel dashboard for web app status"
  exit 0
else
  echo ""
  echo -e "${RED}❌ Validation failed. Check logs and troubleshoot.${NC}"
  echo ""
  echo "Troubleshooting:"
  echo "  1. Check GitHub Actions workflow status"
  echo "  2. Review error logs:"
  echo "     - API: flyctl logs --app infamous-freight-api"
  echo "     - Web: Vercel dashboard → Deployments"
  echo "  3. Verify secrets are set correctly:"
  echo "     - gh secret list --repo MrMiless44/Infamous-freight-enterprises"
  echo "  4. Verify environment variables on providers:"
  echo "     - Fly: flyctl secrets list --app infamous-freight-api"
  echo "     - Vercel: dashboard → Settings → Environment Variables"
  exit 1
fi
