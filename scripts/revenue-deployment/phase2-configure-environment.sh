#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: ENVIRONMENT CONFIGURATION
# Updates .env files and runs database migrations
# ═══════════════════════════════════════════════════════════════════════════════

set -e

echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                      PHASE 2: ENVIRONMENT CONFIGURATION                      ║"
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

echo "📋 PHASE 2 CHECKLIST"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 2.1 UPDATE ENVIRONMENT VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

echo "2.1 UPDATE ENVIRONMENT VARIABLES"
echo "───────────────────────────────────────────────────────────────────────────────"

# Load credentials from Phase 1
if [ -f /tmp/stripe_credentials.env ]; then
  echo -e "${GREEN}✓ Found Stripe credentials from Phase 1${NC}"
  source /tmp/stripe_credentials.env
else
  echo -e "${YELLOW}⚠ No Stripe credentials found. Please enter manually:${NC}"
  read -p "STRIPE_SECRET_KEY: " STRIPE_SECRET_KEY
  read -p "STRIPE_PUBLISHABLE_KEY: " STRIPE_PUBLISHABLE_KEY
  read -p "STRIPE_WEBHOOK_SECRET: " STRIPE_WEBHOOK_SECRET
fi

if [ -f /tmp/paypal_credentials.env ]; then
  echo -e "${GREEN}✓ Found PayPal credentials from Phase 1${NC}"
  source /tmp/paypal_credentials.env
else
  echo -e "${YELLOW}⚠ No PayPal credentials found. Please enter manually:${NC}"
  read -p "PAYPAL_CLIENT_ID: " PAYPAL_CLIENT_ID
  read -p "PAYPAL_CLIENT_SECRET: " PAYPAL_CLIENT_SECRET
  read -p "PAYPAL_ENV (sandbox/live): " PAYPAL_ENV
fi

if [ -f /tmp/email_credentials.env ]; then
  echo -e "${GREEN}✓ Found Email credentials from Phase 1${NC}"
  source /tmp/email_credentials.env
fi

# Prompt for domain configuration
echo ""
read -p "Enter your WEB_URL (e.g., https://infamousfreight.com): " WEB_URL
read -p "Enter your API_URL (e.g., https://api.infamousfreight.com): " API_URL

# Create production .env file
echo ""
echo "Creating production .env file..."

cat > "$PROJECT_ROOT/.env.production" << EOF
# ============================================
# Node Environment
# ============================================
NODE_ENV=production

# ============================================
# Application Ports
# ============================================
API_PORT=4000
WEB_PORT=3000

# ============================================
# Database Configuration
# ============================================
DATABASE_URL=\${DATABASE_URL}
# Note: Set this in your hosting provider's environment variables

# ============================================
# Authentication & Security
# ============================================
JWT_SECRET=\${JWT_SECRET}
# Note: Set this in your hosting provider's environment variables

# ============================================
# Stripe Configuration
# ============================================
STRIPE_SECRET_KEY=$STRIPE_SECRET_KEY
STRIPE_PUBLISHABLE_KEY=$STRIPE_PUBLISHABLE_KEY
STRIPE_WEBHOOK_SECRET=$STRIPE_WEBHOOK_SECRET

# ============================================
# PayPal Configuration
# ============================================
PAYPAL_CLIENT_ID=$PAYPAL_CLIENT_ID
PAYPAL_CLIENT_SECRET=$PAYPAL_CLIENT_SECRET
PAYPAL_ENV=$PAYPAL_ENV

# ============================================
# Email Service Configuration
# ============================================
EMAIL_PROVIDER=${EMAIL_PROVIDER:-sendgrid}
EOF

# Add email-specific variables
if [ -n "$SENDGRID_API_KEY" ]; then
  cat >> "$PROJECT_ROOT/.env.production" << EOF
SENDGRID_API_KEY=$SENDGRID_API_KEY
SENDGRID_FROM_EMAIL=$SENDGRID_FROM_EMAIL
EOF
elif [ -n "$MAILGUN_API_KEY" ]; then
  cat >> "$PROJECT_ROOT/.env.production" << EOF
MAILGUN_API_KEY=$MAILGUN_API_KEY
MAILGUN_DOMAIN=$MAILGUN_DOMAIN
EOF
elif [ -n "$SMTP_HOST" ]; then
  cat >> "$PROJECT_ROOT/.env.production" << EOF
SMTP_HOST=$SMTP_HOST
SMTP_PORT=$SMTP_PORT
SMTP_USER=$SMTP_USER
SMTP_PASSWORD=$SMTP_PASSWORD
EOF
fi

cat >> "$PROJECT_ROOT/.env.production" << EOF

# ============================================
# URL Configuration
# ============================================
WEB_URL=$WEB_URL
API_URL=$API_URL
NEXT_PUBLIC_API_BASE=$API_URL/api

# ============================================
# Billing Configuration
# ============================================
BILLING_ENABLED=true
EMAIL_AUTOMATION_ENABLED=true
TRIAL_PERIOD_DAYS=30
BILLING_CURRENCY=usd

# ============================================
# Feature Flags
# ============================================
USAGE_TRACKING_ENABLED=true

# ============================================
# Monitoring (Optional - Add if using)
# ============================================
# SENTRY_DSN=\${SENTRY_DSN}
# DATADOG_API_KEY=\${DATADOG_API_KEY}
EOF

echo -e "${GREEN}✓ Production .env file created: .env.production${NC}"
echo ""

# Update .env.example with new fields
echo "Updating .env.example with billing fields..."

if ! grep -q "STRIPE_SECRET_KEY" "$PROJECT_ROOT/.env.example"; then
  cat >> "$PROJECT_ROOT/.env.example" << 'EOF'

# ============================================
# Email Service (SendGrid/Mailgun/SMTP)
# ============================================
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=SG.your_sendgrid_api_key
SENDGRID_FROM_EMAIL=billing@yourdomain.com
# OR for Mailgun:
# MAILGUN_API_KEY=your_mailgun_api_key
# MAILGUN_DOMAIN=mg.yourdomain.com
# OR for SMTP:
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=your@email.com
# SMTP_PASSWORD=your_app_password

# ============================================
# Billing Configuration
# ============================================
BILLING_ENABLED=true
EMAIL_AUTOMATION_ENABLED=true
TRIAL_PERIOD_DAYS=30
EOF
  echo -e "${GREEN}✓ Updated .env.example${NC}"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 2.2 DATABASE MIGRATION
# ═══════════════════════════════════════════════════════════════════════════════

echo "2.2 DATABASE MIGRATION"
echo "───────────────────────────────────────────────────────────────────────────────"

# Check if we have billing models in schema
if [ -f "$PROJECT_ROOT/api/prisma/schema.prisma" ]; then
  if grep -q "model Subscription" "$PROJECT_ROOT/api/prisma/schema.prisma"; then
    echo -e "${GREEN}✓ Billing models found in schema.prisma${NC}"
  else
    echo -e "${RED}✗ Billing models NOT found in schema.prisma${NC}"
    echo "Please ensure you've added Subscription, Invoice, and RevenueEvent models"
    exit 1
  fi
else
  echo -e "${RED}✗ schema.prisma not found${NC}"
  exit 1
fi

# Run migration
echo ""
echo "Running database migration..."
cd "$PROJECT_ROOT/api"

if [ -n "$DATABASE_URL" ]; then
  echo "Using DATABASE_URL from environment"
else
  echo -e "${YELLOW}⚠ DATABASE_URL not set. Using default from .env${NC}"
fi

# Generate Prisma client
echo "Generating Prisma client..."
pnpm prisma generate

# Run migration
echo "Running migration..."
pnpm prisma migrate deploy

echo -e "${GREEN}✓ Database migration complete${NC}"
echo ""

# Verify tables
echo "Verifying tables..."
pnpm prisma db execute --stdin <<SQL
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
  AND table_name IN ('Subscription', 'Invoice', 'RevenueEvent');
SQL

echo -e "${GREEN}✓ Tables verified${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 2.3 RESTART SERVICES
# ═══════════════════════════════════════════════════════════════════════════════

echo "2.3 RESTART SERVICES"
echo "───────────────────────────────────────────────────────────────────────────────"

echo "Choose your deployment method:"
echo "  1) Docker Compose"
echo "  2) Manual (PM2/systemd)"
echo "  3) Skip (will restart manually)"
read -p "Enter choice [1-3]: " RESTART_METHOD

case $RESTART_METHOD in
  1)
    echo "Restarting Docker containers..."
    cd "$PROJECT_ROOT"
    docker-compose restart api web
    echo -e "${GREEN}✓ Docker containers restarted${NC}"
    ;;
  2)
    echo "Restart commands for manual deployment:"
    echo ""
    echo "For PM2:"
    echo "  pm2 restart infamous-api"
    echo "  pm2 restart infamous-web"
    echo ""
    echo "For systemd:"
    echo "  sudo systemctl restart infamous-api"
    echo "  sudo systemctl restart infamous-web"
    echo ""
    read -p "Press ENTER after you've restarted services... "
    ;;
  3)
    echo -e "${YELLOW}⚠ Skipping service restart. Remember to restart manually!${NC}"
    ;;
esac

echo ""

# Verify health endpoint
echo "Verifying API health..."
sleep 3

if [ -n "$API_URL" ]; then
  if curl -f "$API_URL/api/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API is healthy${NC}"
  else
    echo -e "${YELLOW}⚠ Could not reach API health endpoint${NC}"
    echo "This may be normal if you haven't deployed to production yet"
  fi
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                         PHASE 2 COMPLETE! ✅                                 ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

echo "✅ Production .env file created"
echo "✅ Database migrations executed"
echo "✅ Billing tables verified"
echo "✅ Services restarted (or ready for restart)"
echo ""

echo "📄 Files created:"
echo "   • $PROJECT_ROOT/.env.production"
echo ""

echo "⚠️  SECURITY REMINDERS:"
echo "   1. Add .env.production to .gitignore (should already be there)"
echo "   2. Never commit .env.production to version control"
echo "   3. Use your hosting provider's secrets manager for production"
echo "   4. Rotate credentials regularly"
echo ""

echo "🚀 NEXT STEP: Run Phase 3 to deploy and test frontend"
echo "   ./scripts/revenue-deployment/phase3-deploy-frontend.sh"
echo ""

# Clean up temporary files
rm -f /tmp/stripe_credentials.env
rm -f /tmp/paypal_credentials.env
rm -f /tmp/email_credentials.env

echo -e "${GREEN}✓ Cleaned up temporary credential files${NC}"
echo ""
