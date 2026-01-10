# 🚀 Revenue System Deployment Scripts

Complete automation for deploying the Infamous Freight Enterprises revenue system with Stripe, PayPal, and email automation.

## 📋 Overview

This directory contains 6 comprehensive deployment phases that take you from zero to live payments in 48 hours.

## 🎯 Quick Start

### Option 1: Run All Phases (Recommended)
```bash
./scripts/deploy-revenue-system.sh
```

### Option 2: Run Individual Phases
```bash
# Phase 1: Set up Stripe, PayPal, SendGrid accounts
./scripts/revenue-deployment/phase1-setup-accounts.sh

# Phase 2: Configure environment variables and run migrations
./scripts/revenue-deployment/phase2-configure-environment.sh

# Phase 3: Deploy frontend pricing page
./scripts/revenue-deployment/phase3-deploy-frontend.sh

# Phase 4: Test payment flows and email automation
./scripts/revenue-deployment/phase4-verify-payments.sh

# Phase 5: Enable live mode and go to production
./scripts/revenue-deployment/phase5-production-launch.sh

# Phase 6: Set up monitoring and documentation
./scripts/revenue-deployment/phase6-monitoring.sh
```

## 📦 What's Included

### Deployment Scripts
- **phase1-setup-accounts.sh** - Create payment processor accounts
- **phase2-configure-environment.sh** - Environment setup & migrations
- **phase3-deploy-frontend.sh** - Frontend deployment & testing
- **phase4-verify-payments.sh** - Payment flow verification
- **phase5-production-launch.sh** - Production launch procedures
- **phase6-monitoring.sh** - Monitoring & documentation setup
- **deploy-revenue-system.sh** - Master script (runs all phases)

### Documentation
- **REVENUE_DASHBOARD_GUIDE.md** - Dashboard usage and KPI explanations
- **REVENUE_OPERATIONS_RUNBOOK.md** - Troubleshooting and procedures
- **REVENUE_SUCCESS_METRICS.md** - Success criteria and tracking
- **monitoring/revenue-alerts.yml** - Alert configuration

## 🔧 Prerequisites

### Required Accounts
- [ ] Stripe account (test mode to start)
- [ ] PayPal developer account
- [ ] SendGrid or SMTP email service
- [ ] Production database (PostgreSQL)
- [ ] Hosting platform (Vercel/Fly.io/Railway)

### Required Tools
- [ ] Node.js 18+ and pnpm
- [ ] PostgreSQL client (psql)
- [ ] Git
- [ ] curl
- [ ] Bash shell

## 📖 Phase Details

### Phase 1: Payment Infrastructure Setup (8 hours)
**What it does:**
- Guides you through Stripe account creation
- Sets up webhook endpoints
- Creates Stripe products (3 pricing tiers)
- Configures PayPal as backup processor
- Sets up email service (SendGrid/Mailgun/SMTP)

**Outputs:**
- Stripe API keys
- PayPal credentials
- Email service credentials

### Phase 2: Environment Configuration (6 hours)
**What it does:**
- Creates .env.production file
- Updates environment variables
- Runs database migrations
- Generates Prisma client
- Restarts services

**Outputs:**
- .env.production (with all credentials)
- Database tables (Subscription, Invoice, RevenueEvent)

### Phase 3: Frontend Deployment (10 hours)
**What it does:**
- Verifies all required files exist
- Builds Next.js application
- Starts local test server
- Tests pricing page UI
- Tests Stripe checkout flow
- Deploys to production (Vercel/Docker/Manual)

**Outputs:**
- Production pricing page
- Success confirmation page
- Verified checkout flow

### Phase 4: Payment Flow Verification (8 hours)
**What it does:**
- Tests email service connectivity
- Verifies email templates
- Tests end-to-end payment flow
- Tests failed payment handling
- Tests subscription cancellation
- Verifies revenue metrics endpoint
- Tests email automation scheduler

**Outputs:**
- Verified payment flows
- Test subscriptions in database
- Confirmed email delivery

### Phase 5: Production Launch (16 hours)
**What it does:**
- Enables Stripe LIVE mode
- Enables PayPal production environment
- Deploys to production
- Verifies production health
- Updates marketing materials
- Enables monitoring
- Processes final production test

**Outputs:**
- Live payment system accepting real money
- Production deployment complete
- Monitoring active

### Phase 6: Monitoring & Documentation (ongoing)
**What it does:**
- Creates revenue dashboard guide
- Creates operations runbook
- Sets up monitoring alerts
- Creates success metrics tracker
- Generates master deployment script

**Outputs:**
- Complete documentation suite
- Monitoring configuration
- Operational procedures

## 📊 Expected Timeline

| Phase | Duration | Can Start |
|-------|----------|-----------|
| Phase 1 | 8 hours | Immediately |
| Phase 2 | 6 hours | After Phase 1 |
| Phase 3 | 10 hours | After Phase 2 |
| Phase 4 | 8 hours | After Phase 3 |
| Phase 5 | 16 hours | After Phase 4 |
| Phase 6 | 2 hours | After Phase 5 |
| **Total** | **48 hours** | |

## 🎯 Success Criteria

After completing all phases:

✅ Stripe accepting live payments  
✅ PayPal configured as backup  
✅ Email automation sending  
✅ Pricing page deployed  
✅ Checkout flow tested  
✅ Monitoring active  
✅ Documentation complete  

## 🚨 Troubleshooting

### Script won't execute
```bash
chmod +x scripts/revenue-deployment/*.sh
chmod +x scripts/deploy-revenue-system.sh
```

### Missing credentials
All credentials are collected interactively. If skipped, you'll be prompted to enter them manually in later phases.

### Database migration fails
```bash
cd api
pnpm prisma migrate reset
pnpm prisma migrate deploy
pnpm prisma generate
```

### Email service not working
Check your credentials in .env:
- SendGrid: SENDGRID_API_KEY
- SMTP: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD

## 📚 Additional Resources

- [START_RECEIVING_REVENUE_100_DEPLOYMENT.md](../../START_RECEIVING_REVENUE_100_DEPLOYMENT.md) - Detailed deployment guide
- [START_RECEIVING_REVENUE_100_COMPLETE.md](../../START_RECEIVING_REVENUE_100_COMPLETE.md) - Complete system overview
- [REVENUE_DASHBOARD_GUIDE.md](../../REVENUE_DASHBOARD_GUIDE.md) - Dashboard usage (created in Phase 6)
- [REVENUE_OPERATIONS_RUNBOOK.md](../../REVENUE_OPERATIONS_RUNBOOK.md) - Operations guide (created in Phase 6)

## 🤝 Support

If you encounter issues:
1. Check the REVENUE_OPERATIONS_RUNBOOK.md
2. Review error logs in /var/log/
3. Contact: billing@infamousfreight.com

## 📈 What Happens After Launch

### First 24 Hours
- Monitor Stripe dashboard for transactions
- Check email delivery rates (>95%)
- Watch error logs
- Verify webhook events processing

### First Week
- Track trial signups (target: 25-50)
- Monitor conversion rate
- Review email open rates
- Test support response time

### First Month
- Achieve $2,500-$5,000 MRR
- 30-50 paying customers
- <15% churn rate
- >10% conversion rate

## 💰 Revenue Projections

### 30 Days
- **Signups:** 500+ trials
- **Conversions:** 30-50 customers
- **MRR:** $2,500-$5,000

### Year 1 (Conservative)
- **Customers:** 500
- **Annual Revenue:** $2.0M-$2.5M
- **Break-even:** Month 4

### Year 1 (Optimistic)
- **Customers:** 1,200
- **Annual Revenue:** $6.0M-$8.0M
- **Break-even:** Month 2

## ⚠️ Security Notes

1. Never commit .env.production to git
2. Rotate credentials every 90 days
3. Use webhook signature verification
4. Enable 2FA on all payment accounts
5. Monitor for suspicious activity
6. Keep backup payment method active

## 🎉 Celebration Milestones

When you hit these, celebrate! 🎊

- First trial signup
- First conversion ($299)
- $1,000 MRR
- $5,000 MRR
- $10,000 MRR
- 100 customers
- $1M ARR

---

**Ready to start receiving revenue?**

```bash
./scripts/deploy-revenue-system.sh
```

Let's make money! 💰🚀
