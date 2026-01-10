#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: FRONTEND DEPLOYMENT & TESTING
# Deploys pricing page and tests checkout flow
# ═══════════════════════════════════════════════════════════════════════════════

set -e

echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                     PHASE 3: FRONTEND DEPLOYMENT & TESTING                   ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "📋 PHASE 3 CHECKLIST"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 3.1 VERIFY PRICING PAGE FILES
# ═══════════════════════════════════════════════════════════════════════════════

echo "3.1 VERIFY PRICING PAGE FILES"
echo "───────────────────────────────────────────────────────────────────────────────"

FILES_TO_CHECK=(
  "web/pages/pricing.tsx"
  "web/pages/billing/success.tsx"
  "web/styles/pricing.module.css"
  "web/styles/billing.module.css"
  "api/src/routes/billing.ts"
  "api/src/services/email.ts"
  "api/src/services/trial-email-automation.ts"
)

MISSING_FILES=()

for file in "${FILES_TO_CHECK[@]}"; do
  if [ -f "$PROJECT_ROOT/$file" ]; then
    echo -e "${GREEN}✓ Found: $file${NC}"
  else
    echo -e "${RED}✗ Missing: $file${NC}"
    MISSING_FILES+=("$file")
  fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
  echo ""
  echo -e "${RED}ERROR: Missing ${#MISSING_FILES[@]} required files${NC}"
  echo "Please ensure all revenue system files are in place"
  exit 1
fi

echo -e "${GREEN}✓ All required files present${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 3.2 BUILD FRONTEND
# ═══════════════════════════════════════════════════════════════════════════════

echo "3.2 BUILD FRONTEND"
echo "───────────────────────────────────────────────────────────────────────────────"

cd "$PROJECT_ROOT/web"

echo "Installing dependencies..."
pnpm install

echo "Building Next.js application..."
pnpm build

if [ $? -eq 0 ]; then
  echo -e "${GREEN}✓ Frontend build successful${NC}"
else
  echo -e "${RED}✗ Frontend build failed${NC}"
  exit 1
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 3.3 START LOCAL SERVER FOR TESTING
# ═══════════════════════════════════════════════════════════════════════════════

echo "3.3 START LOCAL SERVER FOR TESTING"
echo "───────────────────────────────────────────────────────────────────────────────"

echo "Starting development server..."
echo ""
echo -e "${YELLOW}The server will start in the background.${NC}"
echo -e "${YELLOW}Visit: http://localhost:3000/pricing${NC}"
echo ""

# Start server in background
cd "$PROJECT_ROOT"
pnpm web:dev &
SERVER_PID=$!

echo "Server PID: $SERVER_PID"
echo "Waiting for server to start..."
sleep 5

# Check if server is running
if kill -0 $SERVER_PID 2>/dev/null; then
  echo -e "${GREEN}✓ Server started successfully${NC}"
else
  echo -e "${RED}✗ Server failed to start${NC}"
  exit 1
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 3.4 TEST PRICING PAGE
# ═══════════════════════════════════════════════════════════════════════════════

echo "3.4 TEST PRICING PAGE"
echo "───────────────────────────────────────────────────────────────────────────────"

# Wait for page to be available
echo "Waiting for page to load..."
sleep 3

# Check if page loads
if curl -f http://localhost:3000/pricing > /dev/null 2>&1; then
  echo -e "${GREEN}✓ Pricing page is accessible${NC}"
else
  echo -e "${RED}✗ Pricing page is not accessible${NC}"
  kill $SERVER_PID
  exit 1
fi

echo ""
echo "MANUAL TESTING CHECKLIST:"
echo "───────────────────────────────────────────────────────────────────────────────"
echo "Open http://localhost:3000/pricing in your browser and verify:"
echo ""
echo "☐ 1. Page loads without errors"
echo "☐ 2. Three pricing tiers are displayed (Starter, Professional, Enterprise)"
echo "☐ 3. Monthly/Annual billing toggle works"
echo "☐ 4. Annual pricing shows '2 months free' discount"
echo "☐ 5. 'Start Free Trial' buttons are visible"
echo "☐ 6. FAQ section is present"
echo "☐ 7. Page is responsive (resize browser to mobile size)"
echo "☐ 8. No console errors in browser DevTools"
echo ""

read -p "Have you verified all items above? (y/n): " VERIFIED

if [ "$VERIFIED" != "y" ]; then
  echo -e "${YELLOW}⚠ Please complete verification before proceeding${NC}"
  echo "Server is still running (PID: $SERVER_PID)"
  echo "Stop it with: kill $SERVER_PID"
  exit 1
fi

echo -e "${GREEN}✓ Pricing page verified${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 3.5 TEST STRIPE CHECKOUT (TEST MODE)
# ═══════════════════════════════════════════════════════════════════════════════

echo "3.5 TEST STRIPE CHECKOUT (TEST MODE)"
echo "───────────────────────────────────────────────────────────────────────────────"

echo ""
echo "STRIPE CHECKOUT TEST:"
echo "───────────────────────────────────────────────────────────────────────────────"
echo "1. Click 'Start Free Trial' on any tier"
echo "2. You should be redirected to Stripe checkout"
echo "3. Use test card: 4242 4242 4242 4242"
echo "4. Expiry: Any future date (e.g., 12/34)"
echo "5. CVC: Any 3 digits (e.g., 123)"
echo "6. Complete checkout"
echo "7. You should be redirected to /billing/success"
echo ""
echo "Expected behavior:"
echo "• Checkout session loads from Stripe"
echo "• Test card is accepted"
echo "• Subscription is created in database"
echo "• Success page shows subscription details"
echo ""

read -p "Have you completed the checkout test? (y/n): " CHECKOUT_TEST

if [ "$CHECKOUT_TEST" != "y" ]; then
  echo -e "${YELLOW}⚠ Please complete checkout test before proceeding${NC}"
  echo "Server is still running (PID: $SERVER_PID)"
  exit 1
fi

echo -e "${GREEN}✓ Checkout test complete${NC}"
echo ""

# Check database for subscription
echo "Checking database for test subscription..."
cd "$PROJECT_ROOT/api"

SUBSCRIPTION_COUNT=$(pnpm prisma db execute --stdin <<SQL | grep -o '[0-9]\+'
SELECT COUNT(*) FROM "Subscription" WHERE "stripeCustomerId" IS NOT NULL;
SQL
)

if [ "$SUBSCRIPTION_COUNT" -gt 0 ]; then
  echo -e "${GREEN}✓ Found $SUBSCRIPTION_COUNT subscription(s) in database${NC}"
else
  echo -e "${YELLOW}⚠ No subscriptions found in database${NC}"
  echo "This might be okay if you haven't completed checkout yet"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 3.6 TEST SUCCESS PAGE
# ═══════════════════════════════════════════════════════════════════════════════

echo "3.6 TEST SUCCESS PAGE"
echo "───────────────────────────────────────────────────────────────────────────────"

echo ""
echo "SUCCESS PAGE VERIFICATION:"
echo "───────────────────────────────────────────────────────────────────────────────"
echo "On /billing/success page, verify:"
echo ""
echo "☐ 1. Success message is displayed"
echo "☐ 2. Subscription tier is shown correctly"
echo "☐ 3. Billing cycle (monthly/annual) is correct"
echo "☐ 4. Price matches selected tier"
echo "☐ 5. Trial end date is 30 days in future"
echo "☐ 6. 'Next steps' section is visible"
echo "☐ 7. No errors in console"
echo ""

read -p "Have you verified the success page? (y/n): " SUCCESS_VERIFIED

if [ "$SUCCESS_VERIFIED" != "y" ]; then
  echo -e "${YELLOW}⚠ Please verify success page before proceeding${NC}"
  echo "Server is still running (PID: $SERVER_PID)"
  exit 1
fi

echo -e "${GREEN}✓ Success page verified${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 3.7 DEPLOYMENT TO PRODUCTION
# ═══════════════════════════════════════════════════════════════════════════════

echo "3.7 DEPLOYMENT TO PRODUCTION"
echo "───────────────────────────────────────────────────────────────────────────────"

echo "Choose your deployment method:"
echo "  1) Vercel (Recommended for Next.js)"
echo "  2) Docker"
echo "  3) Manual deployment"
echo "  4) Skip (deploy manually later)"
read -p "Enter choice [1-4]: " DEPLOY_METHOD

case $DEPLOY_METHOD in
  1)
    echo ""
    echo "VERCEL DEPLOYMENT:"
    echo "───────────────────────────────────────────────────────────────────────────────"
    echo "1. Install Vercel CLI: npm i -g vercel"
    echo "2. Run: cd $PROJECT_ROOT/web && vercel"
    echo "3. Follow prompts to link project"
    echo "4. Set environment variables in Vercel dashboard:"
    echo "   • NEXT_PUBLIC_API_BASE"
    echo "   • NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY"
    echo "5. Run: vercel --prod"
    echo ""
    read -p "Have you deployed to Vercel? (y/n): " VERCEL_DEPLOYED
    if [ "$VERCEL_DEPLOYED" = "y" ]; then
      read -p "Enter your Vercel production URL: " VERCEL_URL
      echo -e "${GREEN}✓ Deployed to Vercel: $VERCEL_URL${NC}"
    fi
    ;;
  2)
    echo ""
    echo "DOCKER DEPLOYMENT:"
    echo "───────────────────────────────────────────────────────────────────────────────"
    echo "Building Docker image..."
    cd "$PROJECT_ROOT"
    docker-compose -f docker-compose.prod.yml build web
    echo "Starting container..."
    docker-compose -f docker-compose.prod.yml up -d web
    echo -e "${GREEN}✓ Docker container started${NC}"
    ;;
  3)
    echo ""
    echo "MANUAL DEPLOYMENT:"
    echo "───────────────────────────────────────────────────────────────────────────────"
    echo "1. Build: cd $PROJECT_ROOT/web && pnpm build"
    echo "2. Copy .next/ folder to your server"
    echo "3. Run: pnpm start on server"
    echo "4. Configure reverse proxy (nginx/Apache)"
    echo ""
    read -p "Press ENTER when deployment is complete... "
    ;;
  4)
    echo -e "${YELLOW}⚠ Skipping production deployment${NC}"
    echo "Remember to deploy before going live!"
    ;;
esac

echo ""

# Stop local server
echo "Stopping local development server..."
kill $SERVER_PID 2>/dev/null || true
echo -e "${GREEN}✓ Local server stopped${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                         PHASE 3 COMPLETE! ✅                                 ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

echo "✅ Pricing page files verified"
echo "✅ Frontend built successfully"
echo "✅ Pricing page tested locally"
echo "✅ Stripe checkout tested"
echo "✅ Success page verified"
echo "✅ Production deployment completed (or ready)"
echo ""

echo "🚀 NEXT STEP: Run Phase 4 to set up email automation"
echo "   ./scripts/revenue-deployment/phase4-verify-payments.sh"
echo ""
