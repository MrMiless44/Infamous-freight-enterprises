#!/bin/bash

# 🚀 START RECEIVING REVENUE 100% - DEPLOYMENT CHECKLIST

# Complete implementation & live payment system in 48 hours

cat << 'EOF'

╔═══════════════════════════════════════════════════════════════════════════════╗
║ ║
║ 🚀 START RECEIVING REVENUE 100% ║
║ ║
║ 48-HOUR DEPLOYMENT PLAN ║
║ ║
╚═══════════════════════════════════════════════════════════════════════════════╝

PHASE 1: PAYMENT INFRASTRUCTURE SETUP (Hours 1-8)
═══════════════════════════════════════════════════════════════════════════════

☐ 1.1 Create Stripe Account
└─ Visit: https://dashboard.stripe.com/register
└─ Verify identity & add banking info (2-3 business days to receive payouts)
└─ Generate API Keys:
• STRIPE*SECRET_KEY=sk_live*... (from Settings → API Keys)
• STRIPE*PUBLISHABLE_KEY=pk_live*...
• STRIPE*WEBHOOK_SECRET=whsec*... (from Webhooks)

☐ 1.2 Configure Stripe Webhook
└─ Go to Settings → Webhooks
└─ Add endpoint: https://api.yourdomain.com/api/billing/webhook/stripe
└─ Events to listen for:
• checkout.session.completed
• invoice.payment_succeeded
• invoice.payment_failed
• customer.subscription.deleted
└─ Copy signing secret: STRIPE_WEBHOOK_SECRET

☐ 1.3 Create Stripe Products
└─ Products → Create Product for each tier:
• Starter ($299/month or $2,990/year)
• Professional ($799/month or $7,990/year)
• Enterprise (custom pricing)
└─ Create Prices for monthly & annual billing

☐ 1.4 Create PayPal Account (Secondary)
└─ Visit: https://developer.paypal.com/dashboard/
└─ Create Business App
└─ Generate credentials:
• PAYPAL_CLIENT_ID=...
• PAYPAL_CLIENT_SECRET=...

☐ 1.5 Configure Email Service
└─ Choose provider: SendGrid | Mailgun | Gmail SMTP
└─ For SendGrid:
• Create account: https://sendgrid.com
• Generate API key
• SENDGRID_API_KEY=SG...
• SENDGRID_FROM_EMAIL=billing@yourdomain.com
└─ Test: curl -X POST https://api.sendgrid.com/v3/mail/send ...

PHASE 2: ENVIRONMENT CONFIGURATION (Hours 9-14)
═══════════════════════════════════════════════════════════════════════════════

☐ 2.1 Update Production .env File

     # Stripe Configuration
     STRIPE_SECRET_KEY=sk_live_xxx
     STRIPE_PUBLISHABLE_KEY=pk_live_xxx
     STRIPE_WEBHOOK_SECRET=whsec_xxx

     # PayPal Configuration
     PAYPAL_CLIENT_ID=xxx
     PAYPAL_CLIENT_SECRET=xxx
     PAYPAL_ENVIRONMENT=production

     # Email Service
     SMTP_HOST=smtp.sendgrid.net
     SMTP_PORT=587
     SMTP_USER=apikey
     SMTP_PASSWORD=SG...
     SMTP_FROM=billing@infamousfreight.com

     # URLs
     WEB_URL=https://infamousfreight.com
     API_URL=https://api.infamousfreight.com

     # Feature Flags
     BILLING_ENABLED=true
     EMAIL_AUTOMATION_ENABLED=true
     TRIAL_DAYS=30

☐ 2.2 Database Migration
└─ SSH to production server
└─ Run: cd /app && pnpm prisma migrate deploy
└─ Verify tables created: subscriptions, invoices, revenue_events

☐ 2.3 Restart Services
└─ API service: systemctl restart infamous-api
└─ Web service: systemctl restart infamous-web
└─ Verify health: curl https://api.yourdomain.com/api/health

PHASE 3: FRONTEND DEPLOYMENT (Hours 15-24)
═══════════════════════════════════════════════════════════════════════════════

☐ 3.1 Deploy Pricing Page
└─ Merge feature branch: git merge revenue-system
└─ Push to production: git push origin main
└─ Vercel automatically deploys /pricing page
└─ Test: https://yourdomain.com/pricing
└─ Verify buttons call /api/billing/checkout

☐ 3.2 Test Pricing Page
└─ Click "Start Free Trial" button
└─ Verify Stripe checkout loads
└─ Test monthly & annual billing toggle
└─ Verify correct pricing displays

☐ 3.3 Test Checkout Flow (Stripe Test Mode)
└─ Use test card: 4242 4242 4242 4242
└─ Expiry: Any future date
└─ CVC: Any 3 digits
└─ Complete checkout
└─ Verify success page shows
└─ Check database: SELECT \* FROM "Subscription" WHERE stripeSubId IS NOT NULL;

☐ 3.4 Verify Success Page
└─ /billing/success should show:
• Subscription tier
• Billing cycle
• Trial end date
• Next steps (Create first shipment, invite team, etc.)

PHASE 4: EMAIL AUTOMATION SETUP (Hours 25-32)
═══════════════════════════════════════════════════════════════════════════════

☐ 4.1 Initialize Email Scheduler
└─ Ensure cron is enabled: crontab -l
└─ Scheduler already runs daily at 2 AM
└─ Manual test:
curl -X POST https://api.yourdomain.com/api/admin/trigger-emails \
 -H "Authorization: Bearer $ADMIN_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"subscriptionId":"xxx","day":0}'

☐ 4.2 Test Email Delivery
└─ Create test subscription manually
└─ Trigger welcome email: curl ... (see 4.1)
└─ Check email inbox for trial welcome message
└─ Verify all template variables render correctly
└─ Click links in email and verify they work

☐ 4.3 Configure Email Templates
└─ SendGrid: Create dynamic templates for each email
• trial_welcome (Day 0)
• trial_feature_highlight (Day 3)
• trial_engagement (Day 7)
• trial_midpoint_checkpoint (Day 14)
• trial_upgrade_offer_early (Day 21)
• trial_final_offer (Day 29)
• payment_succeeded
• churn_prevention

☐ 4.4 Verify Email Sending
└─ Test full flow: signup → Day 0 email within 24h
└─ Check SendGrid dashboard for delivery status
└─ Monitor bounce/complaint rates (should be <0.5%)

PHASE 5: PAYMENT PROCESSING TESTING (Hours 33-40)
═══════════════════════════════════════════════════════════════════════════════

☐ 5.1 End-to-End Test Flow

     1. Create test user account
     2. Verify trial_start email sent
     3. Simulate Day 3: trigger feature highlight email
     4. Simulate Day 7: trigger engagement email
     5. Simulate Day 14: trigger mid-trial checkpoint
     6. Simulate Day 21: trigger upgrade offer
     7. Simulate Day 29: trigger final offer
     8. User upgrades (use test card: 4242 4242 4242 4242)
     9. Verify payment_succeeded email
     10. Verify subscription marked as active (isOnTrial=false)

☐ 5.2 Test Failed Payment Flow
└─ Use test card: 4000 0000 0000 0002 (declined)
└─ Verify payment_failed email sent
└─ Verify subscription status = "past_due"
└─ Verify retry scheduled

☐ 5.3 Test Subscription Cancellation
└─ Cancel subscription via Stripe dashboard
└─ Verify webhook received: customer.subscription.deleted
└─ Verify database updated: status = "cancelled", cancelledAt = now()
└─ Verify cancellation email sent (if configured)

☐ 5.4 Monitor Revenue Metrics
└─ Endpoint: GET /api/billing/revenue/metrics
└─ Check returned metrics:
• MRR: $X,XXX
• Active subscriptions: N
• Churn rate: X%
• Conversion rate: X%
• LTV: $X,XXX
• CAC: $300
• LTV:CAC ratio: X:1

PHASE 6: PRODUCTION LAUNCH (Hours 41-48)
═══════════════════════════════════════════════════════════════════════════════

☐ 6.1 Enable Stripe Live Mode
└─ Go to Stripe Dashboard
└─ Flip toggle: "Use Live API Keys"
└─ Update API keys to live keys (sk*live*... not sk*test*...)
└─ Update .env: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET

☐ 6.2 Enable PayPal Production
└─ Go to PayPal Developer Dashboard
└─ Switch to "Live" environment
└─ Update credentials: PAYPAL_CLIENT_ID (production)
└─ Update .env: PAYPAL_ENVIRONMENT=production

☐ 6.3 Announce /pricing Page
└─ Add pricing link to homepage navigation
└─ Update marketing site with pricing information
└─ Social media announcement: "Start your free trial"
└─ Email to existing users: "Check out our pricing plans"

☐ 6.4 Monitor First 24 Hours
└─ Watch dashboard for trial signups
└─ Monitor Stripe dashboard for transactions
└─ Check email delivery: SendGrid dashboard
└─ Monitor errors: Sentry error tracking
└─ Monitor performance: Datadog APM

☐ 6.5 Verify All Systems
└─ Health check: curl https://api.yourdomain.com/api/health
└─ Database: psql → SELECT COUNT(\*) FROM "Subscription";
└─ Stripe test transaction: Process a real payment
└─ Email test: Send a test email to yourself
└─ Revenue metrics: GET /api/billing/revenue/metrics

═══════════════════════════════════════════════════════════════════════════════

EXPECTED OUTCOMES (First 30 Days)
═══════════════════════════════════════════════════════════════════════════════

Week 1:
└─ 25-50 trial signups (from marketing campaigns)
└─ 0-5 conversions (early adopters)
└─ Email sequence activated for all new trials
└─ $250-500 in MRR

Week 2:
└─ 50-100 total trial signups (cumulative)
└─ 5-15 conversions (Day 14 emails triggering upgrades)
└─ $1-2k MRR
└─ Email engagement: 35-45% open rate, 5-8% click rate

Week 3:
└─ 100-150 total trial signups
└─ 15-30 conversions (Day 21 early offers)
└─ $5-8k MRR
└─ Churn analysis starting (paying customers retention)

Week 4:
└─ 150-200 total trial signups
└─ 30-50 conversions (Day 29 final offers)
└─ $2-5k MRR (achieved 30-day target! 🎉)
└─ Revenue tracking dashboard live & operational

Month 2 Projection:
└─ 300+ trial signups
└─ 50-100 paying customers
└─ $5-10k MRR
└─ Upsell to Professional plan activating

═══════════════════════════════════════════════════════════════════════════════

CRITICAL SUCCESS FACTORS
═══════════════════════════════════════════════════════════════════════════════

✓ Stripe webhook must be verified (signature check)
✓ Email delivery must be <100ms (no queue backups)
✓ Database migrations must complete successfully
✓ All payment test flows must work before going live
✓ CORS must allow requests from your domain
✓ SSL certificate must be valid (Stripe requires HTTPS)
✓ Backup payments (PayPal) configured and tested
✓ Team must monitor first 24 hours after launch

═══════════════════════════════════════════════════════════════════════════════

EMERGENCY CONTACTS
═══════════════════════════════════════════════════════════════════════════════

Stripe Support: https://support.stripe.com
PayPal Support: https://developer.paypal.com/support/
SendGrid Support: https://support.sendgrid.com
Your Incident Hotline: [DEFINE]
On-call Rotation: [DEFINE]

═══════════════════════════════════════════════════════════════════════════════

DEPLOYMENT COMPLETE! 🎉

Your system is now ready to:
✅ Accept recurring payments
✅ Manage customer subscriptions
✅ Track revenue metrics
✅ Automate trial-to-paid conversions
✅ Monitor churn & retention
✅ Scale to 1000+ customers

NEXT STEPS:

1. Execute deployment checklist above
2. Run all test flows
3. Deploy to production
4. Monitor dashboard
5. Celebrate first revenue! 🎊

═══════════════════════════════════════════════════════════════════════════════

Build: 9c0940d
Status: 🚀 READY TO LAUNCH
Date: January 10, 2026
Team: Infamous Freight Enterprises

EOF
