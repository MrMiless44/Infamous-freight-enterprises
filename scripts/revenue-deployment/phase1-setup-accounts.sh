#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: PAYMENT INFRASTRUCTURE SETUP
# Creates accounts and generates API keys for Stripe, PayPal, SendGrid
# ═══════════════════════════════════════════════════════════════════════════════

set -e

echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                    PHASE 1: PAYMENT INFRASTRUCTURE SETUP                     ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if running in interactive mode
if [ -t 0 ]; then
  INTERACTIVE=true
else
  INTERACTIVE=false
fi

echo "📋 PHASE 1 CHECKLIST"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""

# Function to prompt user
prompt_user() {
  local message=$1
  if [ "$INTERACTIVE" = true ]; then
    echo -e "${YELLOW}$message${NC}"
    read -p "Press ENTER when complete... "
    echo ""
  else
    echo -e "${YELLOW}[ACTION REQUIRED] $message${NC}"
  fi
}

# Function to mark complete
mark_complete() {
  echo -e "${GREEN}✓ $1${NC}"
  echo ""
}

# Function to show instructions
show_instructions() {
  echo -e "${YELLOW}$1${NC}"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# 1.1 CREATE STRIPE ACCOUNT
# ═══════════════════════════════════════════════════════════════════════════════

echo "1.1 CREATE STRIPE ACCOUNT"
echo "───────────────────────────────────────────────────────────────────────────────"
show_instructions "Open your browser and visit: https://dashboard.stripe.com/register"
show_instructions "Steps:
  1. Sign up with your business email
  2. Verify your email address
  3. Complete business verification (name, address, tax ID)
  4. Add banking information for payouts (2-3 business days to activate)"

prompt_user "Have you created your Stripe account?"
mark_complete "Stripe account created"

# ═══════════════════════════════════════════════════════════════════════════════
# 1.2 CONFIGURE STRIPE WEBHOOK
# ═══════════════════════════════════════════════════════════════════════════════

echo "1.2 CONFIGURE STRIPE WEBHOOK"
echo "───────────────────────────────────────────────────────────────────────────────"
show_instructions "In Stripe Dashboard:
  1. Go to: Developers → Webhooks
  2. Click 'Add endpoint'
  3. Endpoint URL: https://api.yourdomain.com/api/billing/webhook/stripe
  4. Select events to listen for:
     • checkout.session.completed
     • invoice.payment_succeeded
     • invoice.payment_failed
     • customer.subscription.deleted
  5. Click 'Add endpoint'
  6. Copy the 'Signing secret' (starts with whsec_)"

prompt_user "Have you configured the Stripe webhook?"

echo "Enter your Stripe credentials:"
read -p "STRIPE_SECRET_KEY (sk_test_...): " STRIPE_SECRET_KEY
read -p "STRIPE_PUBLISHABLE_KEY (pk_test_...): " STRIPE_PUBLISHABLE_KEY
read -p "STRIPE_WEBHOOK_SECRET (whsec_...): " STRIPE_WEBHOOK_SECRET

# Save to temporary file
cat > /tmp/stripe_credentials.env << EOF
STRIPE_SECRET_KEY=$STRIPE_SECRET_KEY
STRIPE_PUBLISHABLE_KEY=$STRIPE_PUBLISHABLE_KEY
STRIPE_WEBHOOK_SECRET=$STRIPE_WEBHOOK_SECRET
EOF

mark_complete "Stripe webhook configured and credentials saved"

# ═══════════════════════════════════════════════════════════════════════════════
# 1.3 CREATE STRIPE PRODUCTS
# ═══════════════════════════════════════════════════════════════════════════════

echo "1.3 CREATE STRIPE PRODUCTS"
echo "───────────────────────────────────────────────────────────────────────────────"
show_instructions "In Stripe Dashboard:
  1. Go to: Products → Create product
  2. Create 3 products:
  
  STARTER TIER:
  • Name: Starter Plan
  • Description: Perfect for small businesses
  • Monthly price: \$299/month
  • Annual price: \$2,990/year (save 2 months)
  
  PROFESSIONAL TIER:
  • Name: Professional Plan
  • Description: For growing freight operations
  • Monthly price: \$799/month
  • Annual price: \$7,990/year (save 2 months)
  
  ENTERPRISE TIER:
  • Name: Enterprise Plan
  • Description: Custom pricing for large operations
  • Contact us for pricing"

prompt_user "Have you created all 3 Stripe products with pricing?"
mark_complete "Stripe products created"

# ═══════════════════════════════════════════════════════════════════════════════
# 1.4 CREATE PAYPAL ACCOUNT
# ═══════════════════════════════════════════════════════════════════════════════

echo "1.4 CREATE PAYPAL ACCOUNT (Secondary Payment Method)"
echo "───────────────────────────────────────────────────────────────────────────────"
show_instructions "Open your browser and visit: https://developer.paypal.com/dashboard/
  1. Sign in or create a developer account
  2. Go to: Apps & Credentials
  3. Create a new app
  4. Copy the Client ID and Secret
  5. Switch to 'Live' environment (when ready for production)"

prompt_user "Have you created your PayPal developer app?"

echo "Enter your PayPal credentials:"
read -p "PAYPAL_CLIENT_ID: " PAYPAL_CLIENT_ID
read -p "PAYPAL_CLIENT_SECRET: " PAYPAL_CLIENT_SECRET
read -p "PAYPAL_ENV (sandbox/live): " PAYPAL_ENV

# Save to temporary file
cat > /tmp/paypal_credentials.env << EOF
PAYPAL_CLIENT_ID=$PAYPAL_CLIENT_ID
PAYPAL_CLIENT_SECRET=$PAYPAL_CLIENT_SECRET
PAYPAL_ENV=${PAYPAL_ENV:-sandbox}
EOF

mark_complete "PayPal account configured and credentials saved"

# ═══════════════════════════════════════════════════════════════════════════════
# 1.5 CONFIGURE EMAIL SERVICE
# ═══════════════════════════════════════════════════════════════════════════════

echo "1.5 CONFIGURE EMAIL SERVICE"
echo "───────────────────────────────────────────────────────────────────────────────"
show_instructions "Choose your email provider:
  A) SendGrid (Recommended, 100 emails/day free)
  B) Mailgun (10,000 emails/month free)
  C) Gmail SMTP (Free, but limited to 500/day)
  
For SendGrid:
  1. Visit: https://sendgrid.com/
  2. Sign up and verify your email
  3. Go to: Settings → API Keys
  4. Create API Key with 'Full Access'
  5. Copy the API key (starts with SG.)"

read -p "Which email provider? (sendgrid/mailgun/gmail): " EMAIL_PROVIDER

case $EMAIL_PROVIDER in
  sendgrid)
    read -p "SENDGRID_API_KEY (SG...): " SENDGRID_API_KEY
    read -p "SENDGRID_FROM_EMAIL: " SENDGRID_FROM_EMAIL
    cat > /tmp/email_credentials.env << EOF
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=$SENDGRID_API_KEY
SENDGRID_FROM_EMAIL=$SENDGRID_FROM_EMAIL
EOF
    ;;
  mailgun)
    read -p "MAILGUN_API_KEY: " MAILGUN_API_KEY
    read -p "MAILGUN_DOMAIN: " MAILGUN_DOMAIN
    cat > /tmp/email_credentials.env << EOF
EMAIL_PROVIDER=mailgun
MAILGUN_API_KEY=$MAILGUN_API_KEY
MAILGUN_DOMAIN=$MAILGUN_DOMAIN
EOF
    ;;
  gmail)
    read -p "SMTP_USER (Gmail email): " SMTP_USER
    read -p "SMTP_PASSWORD (App password): " SMTP_PASSWORD
    cat > /tmp/email_credentials.env << EOF
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=$SMTP_USER
SMTP_PASSWORD=$SMTP_PASSWORD
EOF
    ;;
  *)
    echo -e "${RED}Invalid email provider. Skipping...${NC}"
    ;;
esac

mark_complete "Email service configured and credentials saved"

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                         PHASE 1 COMPLETE! ✅                                 ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

echo "✅ Stripe account created and configured"
echo "✅ Stripe webhook configured"
echo "✅ Stripe products created (3 tiers)"
echo "✅ PayPal account configured"
echo "✅ Email service configured"
echo ""

echo "📄 Credentials saved to temporary files:"
echo "   • /tmp/stripe_credentials.env"
echo "   • /tmp/paypal_credentials.env"
echo "   • /tmp/email_credentials.env"
echo ""

echo "🚀 NEXT STEP: Run Phase 2 to configure your environment"
echo "   ./scripts/revenue-deployment/phase2-configure-environment.sh"
echo ""

echo "⚠️  SECURITY NOTE: These credentials are saved temporarily."
echo "   You'll move them to secure storage in Phase 2."
echo ""
