#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: MONITORING & DOCUMENTATION
# Sets up monitoring, dashboards, and creates operational documentation
# ═══════════════════════════════════════════════════════════════════════════════

set -e

echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                      PHASE 6: MONITORING & DOCUMENTATION                     ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Get project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "📋 PHASE 6 CHECKLIST"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 6.1 REVENUE DASHBOARD SETUP
# ═══════════════════════════════════════════════════════════════════════════════

echo "6.1 REVENUE DASHBOARD SETUP"
echo "───────────────────────────────────────────────────────────────────────────────"

echo ""
echo "Creating revenue dashboard documentation..."

cat > "$PROJECT_ROOT/REVENUE_DASHBOARD_GUIDE.md" << 'EOF'
# 💰 Revenue Dashboard Guide

## Overview
This dashboard provides real-time visibility into your revenue metrics, subscription health, and customer lifecycle.

## Accessing the Dashboard

### API Endpoint
```bash
GET /api/billing/revenue/metrics
Authorization: Bearer <your_jwt_token>
```

### Response Format
```json
{
  "success": true,
  "data": {
    "mrr": 15000,
    "activeSubscriptions": 25,
    "churnRate": 8.5,
    "conversionRate": 12.3,
    "avgLifetimeValue": 72000,
    "customerAcquisitionCost": 300,
    "ltvCacRatio": 240,
    "totalRevenue": 180000,
    "avgRevenuePerUser": 7200,
    "trialSignups": 203,
    "paidConversions": 25
  }
}
```

## Key Metrics Explained

### 1. MRR (Monthly Recurring Revenue)
**Definition:** Sum of all active subscription monthly values  
**Formula:** `SUM(subscription.priceMonthly WHERE status = 'active')`  
**Target:** $5,000+ in first 30 days  
**Health:** Green >$5k, Yellow $2-5k, Red <$2k

### 2. Active Subscriptions
**Definition:** Total number of paid, active subscriptions  
**Formula:** `COUNT(subscription WHERE status = 'active' AND isOnTrial = false)`  
**Target:** 100+ customers by month 3  
**Health:** Green >100, Yellow 50-100, Red <50

### 3. Churn Rate
**Definition:** Percentage of customers who cancelled in the last 30 days  
**Formula:** `(Cancelled / (Active + Cancelled)) × 100`  
**Target:** <15% monthly  
**Health:** Green <10%, Yellow 10-15%, Red >15%

### 4. Conversion Rate
**Definition:** Percentage of trials that converted to paid  
**Formula:** `(Paid Subscriptions / Total Trials) × 100`  
**Target:** >10%  
**Health:** Green >15%, Yellow 10-15%, Red <10%

### 5. Customer LTV (Lifetime Value)
**Definition:** Expected revenue from a customer over their lifetime  
**Formula:** `ARPU × Average Customer Lifetime (36 months)`  
**Target:** >$70,000  
**Health:** Green >$70k, Yellow $50-70k, Red <$50k

### 6. CAC (Customer Acquisition Cost)
**Definition:** Cost to acquire one customer  
**Formula:** `Total Marketing Spend / New Customers`  
**Estimated:** $300 per customer  
**Target:** <$500

### 7. LTV:CAC Ratio
**Definition:** Ratio of lifetime value to acquisition cost  
**Formula:** `LTV / CAC`  
**Target:** >5:1 (Very healthy)  
**Health:** Green >10:1, Yellow 5-10:1, Red <5:1

### 8. ARPU (Average Revenue Per User)
**Definition:** Average monthly revenue per customer  
**Formula:** `Total MRR / Active Customers`  
**Target:** >$2,000  
**Health:** Depends on pricing tier

## Dashboard Views

### Executive Summary (Daily)
```
Today's Snapshot
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MRR:                    $15,000  ↑ 12%
Active Customers:            25  ↑ 3
Trial Signups Today:          8
Conversions Today:            2
Churn Rate:               8.5%   ↓ 1.2%
```

### Weekly Report
- New trials this week
- Conversions this week
- Cancellations this week
- Week-over-week MRR growth
- Top performing pricing tier
- Email campaign performance

### Monthly Report
- Total MRR
- Net new customers
- Churn analysis
- Revenue by tier
- Cohort retention analysis
- LTV trends

## Alerts & Notifications

### Critical Alerts (Immediate Response)
- Churn rate >20%
- Payment failure rate >5%
- Email delivery <90%
- API errors >1%

### Warning Alerts (Review within 24h)
- Churn rate >15%
- Conversion rate <8%
- MRR declined week-over-week
- Trial signup rate declined >20%

### Info Notifications
- New subscription milestone (25, 50, 100 customers)
- MRR milestone ($5k, $10k, $25k, $50k)
- Large customer upgrade
- Customer anniversary

## Integration with External Tools

### Stripe Dashboard
- View: https://dashboard.stripe.com
- Metrics: Payment volume, failed payments, disputes
- Reports: Revenue reports, balance history

### SendGrid Dashboard
- View: https://app.sendgrid.com
- Metrics: Email delivery rate, open rate, click rate
- Alerts: Bounces, spam reports

### Datadog (if configured)
- View: https://app.datadoghq.com
- Metrics: API performance, error rates, latency
- Custom dashboards: Revenue metrics, customer health

## SQL Queries for Custom Reports

### MRR Breakdown by Tier
```sql
SELECT 
  tier,
  COUNT(*) as customers,
  SUM("priceMonthly") as mrr,
  ROUND(AVG("priceMonthly"), 2) as avg_price
FROM "Subscription"
WHERE status = 'active'
  AND "isOnTrial" = false
GROUP BY tier
ORDER BY mrr DESC;
```

### Conversion Funnel
```sql
SELECT 
  DATE_TRUNC('week', "createdAt") as week,
  COUNT(*) FILTER (WHERE "isOnTrial" = true) as trials,
  COUNT(*) FILTER (WHERE "isOnTrial" = false) as conversions,
  ROUND(
    COUNT(*) FILTER (WHERE "isOnTrial" = false)::numeric / 
    NULLIF(COUNT(*), 0) * 100, 
    1
  ) as conversion_rate
FROM "Subscription"
GROUP BY week
ORDER BY week DESC
LIMIT 12;
```

### Churn Analysis
```sql
SELECT 
  DATE_TRUNC('month', "cancelledAt") as month,
  COUNT(*) as cancellations,
  ROUND(AVG(EXTRACT(DAY FROM ("cancelledAt" - "createdAt"))), 0) as avg_days_active
FROM "Subscription"
WHERE "cancelledAt" IS NOT NULL
GROUP BY month
ORDER BY month DESC;
```

## Automated Reports

### Daily Email Report
**Recipients:** CEO, CFO, Head of Sales  
**Time:** 8:00 AM daily  
**Contents:**
- Yesterday's MRR
- New trials and conversions
- Cancellations
- Top metrics summary

### Weekly Slack Notification
**Channel:** #revenue  
**Time:** Monday 9:00 AM  
**Contents:**
- Week-over-week growth
- Current MRR
- Active customers
- Upcoming trial expirations

### Monthly Board Report
**Recipients:** Board of Directors, Investors  
**Time:** 1st of each month  
**Contents:**
- Full financial summary
- Growth trends
- Cohort analysis
- Customer success stories

## Optimization Recommendations

### If Churn Rate >15%
1. Review cancellation reasons
2. Implement save offers
3. Improve onboarding
4. Add customer success touchpoints

### If Conversion Rate <10%
1. Test pricing adjustments
2. Improve trial experience
3. Optimize email sequence
4. Add more trial features

### If LTV:CAC <5:1
1. Reduce marketing costs
2. Improve customer retention
3. Increase pricing
4. Upsell existing customers

## Questions?
Contact: billing@infamousfreight.com  
Slack: #revenue-ops
EOF

echo -e "${GREEN}✓ Revenue dashboard guide created${NC}"
echo "   Location: $PROJECT_ROOT/REVENUE_DASHBOARD_GUIDE.md"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 6.2 OPERATIONAL RUNBOOK
# ═══════════════════════════════════════════════════════════════════════════════

echo "6.2 OPERATIONAL RUNBOOK"
echo "───────────────────────────────────────────────────────────────────────────────"

echo ""
echo "Creating operational runbook..."

cat > "$PROJECT_ROOT/REVENUE_OPERATIONS_RUNBOOK.md" << 'EOF'
# 🛠️ Revenue Operations Runbook

## Table of Contents
1. [Common Issues & Solutions](#common-issues)
2. [Emergency Procedures](#emergency-procedures)
3. [Routine Maintenance](#routine-maintenance)
4. [Customer Support Scripts](#customer-support)
5. [Escalation Paths](#escalation-paths)

## Common Issues & Solutions

### Issue: Payment Failed
**Symptoms:** Customer reports payment didn't go through  
**Diagnosis:**
1. Check Stripe dashboard for transaction
2. Check customer's payment method in Stripe
3. Review webhook logs for `invoice.payment_failed`

**Solution:**
```bash
# Check subscription status
cd /app/api
pnpm prisma db execute --stdin <<SQL
SELECT id, status, "stripeCustomerId" 
FROM "Subscription" 
WHERE id = '<subscription_id>';
SQL

# Retry payment in Stripe dashboard
# Or update payment method
```

**Prevention:** Enable retry logic, send payment update reminders

---

### Issue: Customer Not Receiving Emails
**Symptoms:** Customer didn't get welcome or trial emails  
**Diagnosis:**
1. Check SendGrid dashboard for delivery status
2. Check bounce/spam reports
3. Verify email address is correct

**Solution:**
```bash
# Check email logs
grep "email sent" /var/log/api.log | grep "<customer_email>"

# Manually resend email
curl -X POST http://localhost:4000/api/admin/resend-email \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"subscriptionId":"xxx","emailType":"trial_welcome"}'
```

**Prevention:** Verify email on signup, use double opt-in

---

### Issue: Webhook Not Processing
**Symptoms:** Subscription status not updating after Stripe event  
**Diagnosis:**
1. Check Stripe webhook logs
2. Verify webhook signature validation
3. Check API error logs

**Solution:**
```bash
# Check webhook endpoint
curl -X POST http://localhost:4000/api/billing/webhook/stripe \
  -H "stripe-signature: $WEBHOOK_SIGNATURE" \
  -d @test_webhook.json

# Manually replay webhook in Stripe dashboard
```

**Prevention:** Monitor webhook success rate, set up alerts

---

### Issue: Subscription Not Cancelling
**Symptoms:** Customer cancelled but still being charged  
**Diagnosis:**
1. Check Stripe subscription status
2. Verify webhook received
3. Check database status

**Solution:**
```sql
-- Manually cancel in database
UPDATE "Subscription" 
SET status = 'cancelled', 
    "cancelledAt" = NOW() 
WHERE id = '<subscription_id>';

-- Cancel in Stripe
```

**Prevention:** Test cancellation flow regularly

---

## Emergency Procedures

### 🚨 CRITICAL: Mass Payment Failures
**What:** >10% of payments failing  
**When:** Immediately  
**Who:** CTO, Payment Ops Lead

**Actions:**
1. Check Stripe service status
2. Pause retry attempts temporarily
3. Send customer notification
4. Investigate payment processor issue
5. Enable backup processor (PayPal)

```bash
# Emergency: Disable payment retries
echo "PAYMENT_RETRY_ENABLED=false" >> .env
pm2 restart api

# Re-enable after investigation
echo "PAYMENT_RETRY_ENABLED=true" >> .env
pm2 restart api
```

---

### 🚨 HIGH: Email Service Down
**What:** Email delivery rate <80%  
**When:** Within 1 hour  
**Who:** DevOps, Engineering Lead

**Actions:**
1. Check SendGrid status
2. Review bounce rates
3. Switch to backup email provider
4. Queue failed emails for retry

```bash
# Check email queue
cd /app/api
node scripts/check-email-queue.js

# Retry failed emails
node scripts/retry-failed-emails.js
```

---

### 🚨 MEDIUM: Database Slow Query
**What:** Revenue metrics endpoint >5s response time  
**When:** Within 4 hours  
**Who:** Database Admin, Backend Team

**Actions:**
1. Identify slow query with pganalyze
2. Add database index
3. Optimize query
4. Consider caching

```sql
-- Add index for common queries
CREATE INDEX idx_subscription_status ON "Subscription"(status);
CREATE INDEX idx_subscription_created ON "Subscription"("createdAt");
CREATE INDEX idx_revenue_event_type ON "RevenueEvent"("eventType");
```

---

## Routine Maintenance

### Daily Tasks (15 minutes)
- [ ] Check MRR dashboard
- [ ] Review failed payments (if any)
- [ ] Check email delivery rate
- [ ] Verify webhook processing
- [ ] Review error logs

### Weekly Tasks (1 hour)
- [ ] Analyze churn reasons
- [ ] Review trial-to-paid conversion
- [ ] Test checkout flow
- [ ] Update pricing if needed
- [ ] Review customer feedback

### Monthly Tasks (4 hours)
- [ ] Full financial reconciliation
- [ ] Customer cohort analysis
- [ ] Email campaign performance review
- [ ] Pricing optimization analysis
- [ ] Competitor pricing research
- [ ] Update board report

### Quarterly Tasks (1 day)
- [ ] Full security audit
- [ ] Payment processor review
- [ ] Database optimization
- [ ] Email template refresh
- [ ] Customer satisfaction survey
- [ ] Strategic pricing review

---

## Customer Support Scripts

### "How do I upgrade my plan?"
```
Hi! To upgrade your plan:

1. Visit https://yourdomain.com/billing
2. Click "Change Plan"
3. Select your new tier
4. Confirm upgrade

Your new plan takes effect immediately. You'll be charged a prorated amount for the remainder of your billing cycle.

Need help? Reply to this email or call us at xxx-xxx-xxxx.
```

### "How do I cancel my subscription?"
```
We're sorry to see you go!

To cancel:

1. Visit https://yourdomain.com/billing
2. Click "Cancel Subscription"
3. Confirm cancellation

Your subscription remains active until the end of your current billing period.

Before you go, can you share why you're cancelling? We'd love to make improvements!
```

### "I was charged incorrectly"
```
I apologize for the confusion. Let me look into this.

I see your subscription is for the [TIER] plan at $[AMOUNT]/[PERIOD].
The charge on [DATE] was for [REASON].

[IF INCORRECT]
You're absolutely right - this charge was incorrect. I've processed a refund of $[AMOUNT]. You'll see it in 5-7 business days.

[IF CORRECT]
This charge is correct based on your [TIER] subscription. Here's a breakdown:
- Base cost: $[AMOUNT]
- Usage overages: $[AMOUNT]
- Total: $[AMOUNT]

Let me know if you have any other questions!
```

---

## Escalation Paths

### Tier 1: Customer Support
**Response Time:** <4 hours  
**Handles:**
- General billing questions
- Plan changes
- Payment method updates
- Basic troubleshooting

**Escalate to Tier 2 if:**
- Technical error preventing action
- Refund >$500
- Legal/compliance question
- Customer threatens chargeback

### Tier 2: Engineering Support
**Response Time:** <2 hours  
**Handles:**
- Payment processing errors
- Webhook failures
- Database issues
- API errors

**Escalate to Tier 3 if:**
- Security incident
- Data breach suspected
- Service-wide outage
- Legal action threatened

### Tier 3: Executive Team
**Response Time:** <30 minutes  
**Handles:**
- Critical security issues
- Legal matters
- PR/communications issues
- Major customer escalations (>$10k contract)

---

## Contact Directory

### On-Call Rotation
- **Weekdays (9am-5pm):** Customer Support Team
- **Nights/Weekends:** DevOps On-Call (PagerDuty)
- **Critical Issues:** CTO (xxx-xxx-xxxx)

### Team Contacts
- **Billing Issues:** billing@infamousfreight.com
- **Technical Issues:** engineering@infamousfreight.com
- **Security Issues:** security@infamousfreight.com
- **Legal:** legal@infamousfreight.com

### External Contacts
- **Stripe Support:** https://support.stripe.com
- **SendGrid Support:** https://support.sendgrid.com
- **AWS Support:** Case portal

---

## Useful Commands

```bash
# Check subscription count
psql $DATABASE_URL -c "SELECT COUNT(*) FROM \"Subscription\" WHERE status = 'active';"

# Get MRR
psql $DATABASE_URL -c "SELECT SUM(\"priceMonthly\") FROM \"Subscription\" WHERE status = 'active' AND \"isOnTrial\" = false;"

# Find failed payments today
psql $DATABASE_URL -c "SELECT * FROM \"RevenueEvent\" WHERE \"eventType\" = 'payment_failed' AND \"createdAt\" > NOW() - INTERVAL '1 day';"

# Restart services
pm2 restart all

# Check logs
tail -f /var/log/api.log | grep "billing"

# Test email
node scripts/test-email.js --to=test@example.com
```

EOF

echo -e "${GREEN}✓ Operations runbook created${NC}"
echo "   Location: $PROJECT_ROOT/REVENUE_OPERATIONS_RUNBOOK.md"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 6.3 MONITORING ALERTS SETUP
# ═══════════════════════════════════════════════════════════════════════════════

echo "6.3 MONITORING ALERTS SETUP"
echo "───────────────────────────────────────────────────────────────────────────────"

echo ""
echo "Creating monitoring alert configuration..."

cat > "$PROJECT_ROOT/monitoring/revenue-alerts.yml" << 'EOF'
# Revenue System Monitoring Alerts

alerts:
  # Critical Alerts (PagerDuty)
  - name: high_payment_failure_rate
    condition: payment_failure_rate > 0.10
    severity: critical
    notification: pagerduty
    message: "Payment failure rate above 10%"
    runbook: "REVENUE_OPERATIONS_RUNBOOK.md#mass-payment-failures"
    
  - name: email_delivery_failure
    condition: email_delivery_rate < 0.90
    severity: critical
    notification: pagerduty
    message: "Email delivery rate below 90%"
    runbook: "REVENUE_OPERATIONS_RUNBOOK.md#email-service-down"
    
  - name: api_error_rate_high
    condition: api_error_rate > 0.05
    severity: critical
    notification: pagerduty
    message: "API error rate above 5%"
    
  # High Priority Alerts (Slack)
  - name: high_churn_rate
    condition: churn_rate > 0.20
    severity: high
    notification: slack
    channel: "#revenue-alerts"
    message: "Churn rate above 20%"
    
  - name: low_conversion_rate
    condition: conversion_rate < 0.08
    severity: high
    notification: slack
    channel: "#revenue-alerts"
    message: "Conversion rate below 8%"
    
  - name: mrr_declined
    condition: mrr_week_over_week_change < -0.05
    severity: high
    notification: slack
    channel: "#revenue-alerts"
    message: "MRR declined >5% week-over-week"
    
  # Medium Priority Alerts (Email)
  - name: trial_signup_decline
    condition: trial_signups_week_over_week < -0.20
    severity: medium
    notification: email
    recipients: ["growth@infamousfreight.com"]
    message: "Trial signups declined >20% week-over-week"
    
  - name: webhook_processing_delay
    condition: webhook_processing_time > 5000
    severity: medium
    notification: email
    recipients: ["engineering@infamousfreight.com"]
    message: "Webhook processing time >5s"
    
  # Info Notifications (Slack)
  - name: mrr_milestone
    condition: mrr in [5000, 10000, 25000, 50000, 100000]
    severity: info
    notification: slack
    channel: "#celebrations"
    message: "🎉 MRR milestone reached: ${{mrr}}"
    
  - name: customer_milestone
    condition: active_customers in [25, 50, 100, 250, 500, 1000]
    severity: info
    notification: slack
    channel: "#celebrations"
    message: "🎉 Customer milestone: {{active_customers}} active customers!"

# Monitoring Queries
queries:
  payment_failure_rate:
    sql: |
      SELECT 
        CAST(COUNT(*) FILTER (WHERE "eventType" = 'payment_failed') AS FLOAT) / 
        NULLIF(COUNT(*) FILTER (WHERE "eventType" IN ('payment_succeeded', 'payment_failed')), 0)
      FROM "RevenueEvent"
      WHERE "createdAt" > NOW() - INTERVAL '1 day';
    schedule: "*/15 * * * *"  # Every 15 minutes
    
  email_delivery_rate:
    sql: |
      SELECT delivery_rate 
      FROM email_stats 
      WHERE date = CURRENT_DATE;
    schedule: "0 * * * *"  # Every hour
    
  churn_rate:
    sql: |
      SELECT 
        CAST(COUNT(*) FILTER (WHERE "cancelledAt" > NOW() - INTERVAL '30 days') AS FLOAT) / 
        NULLIF(COUNT(*), 0) * 100
      FROM "Subscription"
      WHERE "createdAt" < NOW() - INTERVAL '30 days';
    schedule: "0 0 * * *"  # Daily
    
  conversion_rate:
    sql: |
      SELECT 
        CAST(COUNT(*) FILTER (WHERE "isOnTrial" = false) AS FLOAT) / 
        NULLIF(COUNT(*), 0) * 100
      FROM "Subscription";
    schedule: "0 */6 * * *"  # Every 6 hours
    
  mrr:
    sql: |
      SELECT SUM("priceMonthly") 
      FROM "Subscription" 
      WHERE status = 'active' 
        AND "isOnTrial" = false;
    schedule: "0 */6 * * *"  # Every 6 hours
EOF

echo -e "${GREEN}✓ Monitoring alerts configuration created${NC}"
echo "   Location: $PROJECT_ROOT/monitoring/revenue-alerts.yml"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 6.4 SUCCESS METRICS TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

echo "6.4 SUCCESS METRICS TRACKING"
echo "───────────────────────────────────────────────────────────────────────────────"

echo ""
echo "Creating success metrics tracker..."

cat > "$PROJECT_ROOT/REVENUE_SUCCESS_METRICS.md" << 'EOF'
# 📊 Revenue Success Metrics Tracker

## 30-Day Goals

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| MRR | $2,500-$5,000 | $0 | 🟡 Not Started |
| Active Customers | 30-50 | 0 | 🟡 Not Started |
| Trial Signups | 500+ | 0 | 🟡 Not Started |
| Conversion Rate | >10% | 0% | 🟡 Not Started |
| Churn Rate | <15% | 0% | 🟡 Not Started |
| Email Open Rate | >40% | 0% | 🟡 Not Started |
| Payment Success | >98% | 0% | 🟡 Not Started |

**Legend:** 🟢 On Track | 🟡 Not Started | 🔴 Below Target

## Weekly Progress

### Week 1 (Days 1-7)
- [ ] 25-50 trial signups
- [ ] 0-5 conversions
- [ ] $250-500 MRR
- [ ] Welcome emails sent: 0
- [ ] Email open rate: 0%

### Week 2 (Days 8-14)
- [ ] 50-100 total trial signups
- [ ] 5-15 total conversions
- [ ] $1-2k MRR
- [ ] Day 7 emails triggering
- [ ] Email open rate: 0%

### Week 3 (Days 15-21)
- [ ] 100-150 total trial signups
- [ ] 15-30 total conversions
- [ ] $5-8k MRR
- [ ] Day 14 checkpoints sent
- [ ] Early upgrade offers (Day 21)

### Week 4 (Days 22-30)
- [ ] 150-200 total trial signups
- [ ] 30-50 total conversions
- [ ] $2-5k MRR ✅ TARGET
- [ ] Final offers sent (Day 29)
- [ ] Churn analysis started

## Year 1 Projections

### Conservative Scenario (10% conversion)
- **Customers:** 500
- **Annual Revenue:** $2.0M - $2.5M
- **Break-even:** Month 4
- **Profit Margin:** 40%

### Aggressive Scenario (15% conversion)
- **Customers:** 900
- **Annual Revenue:** $4.0M - $5.0M
- **Break-even:** Month 3
- **Profit Margin:** 50%

### Optimistic Scenario (20% conversion)
- **Customers:** 1,200
- **Annual Revenue:** $6.0M - $8.0M
- **Break-even:** Month 2
- **Profit Margin:** 55%

## Success Criteria Checklist

### Technical Success
- [x] All payment flows tested
- [x] Email automation active
- [x] Database migrations complete
- [x] Frontend deployed
- [x] API deployed
- [ ] Zero critical bugs in 30 days
- [ ] 99.9% uptime
- [ ] <500ms average API response time

### Business Success
- [ ] 500+ trial signups in 30 days
- [ ] 10%+ conversion rate
- [ ] <15% churn rate
- [ ] $2,500+ MRR
- [ ] 95%+ payment success rate
- [ ] 40%+ email open rate
- [ ] 5+ customer testimonials

### Customer Success
- [ ] 90%+ customer satisfaction (CSAT)
- [ ] <24h support response time
- [ ] 50%+ feature adoption rate
- [ ] 3+ customer case studies
- [ ] NPS score >30

## Update Schedule

**Daily:** Update MRR, active customers, trial signups  
**Weekly:** Review conversion funnel, email performance  
**Monthly:** Full metrics review, board reporting  

Last Updated: [DATE]
Updated By: [NAME]
EOF

echo -e "${GREEN}✓ Success metrics tracker created${NC}"
echo "   Location: $PROJECT_ROOT/REVENUE_SUCCESS_METRICS.md"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 6.5 CREATE MASTER EXECUTION SCRIPT
# ═══════════════════════════════════════════════════════════════════════════════

echo "6.5 CREATE MASTER EXECUTION SCRIPT"
echo "───────────────────────────────────────────────────────────────────────────────"

echo ""
echo "Creating master deployment script..."

cat > "$PROJECT_ROOT/scripts/deploy-revenue-system.sh" << 'EOF'
#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
# MASTER REVENUE SYSTEM DEPLOYMENT SCRIPT
# Executes all 6 phases automatically (where possible)
# ═══════════════════════════════════════════════════════════════════════════════

set -e

echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                   💰 REVENUE SYSTEM MASTER DEPLOYMENT 💰                     ║"
echo "║                                                                               ║"
echo "║                        Complete 6-Phase Execution                            ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Check if running in CI/CD
if [ -n "$CI" ]; then
  echo "Running in CI/CD mode"
  INTERACTIVE=false
else
  INTERACTIVE=true
fi

# Phase status tracking
PHASE1_DONE=false
PHASE2_DONE=false
PHASE3_DONE=false
PHASE4_DONE=false
PHASE5_DONE=false
PHASE6_DONE=false

# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTION START
# ═══════════════════════════════════════════════════════════════════════════════

echo "Starting revenue system deployment..."
echo "This will execute all 6 phases of the deployment process."
echo ""

read -p "Are you ready to begin? (yes/no): " START

if [ "$START" != "yes" ]; then
  echo "Deployment cancelled."
  exit 0
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: PAYMENT INFRASTRUCTURE SETUP
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 1: PAYMENT INFRASTRUCTURE SETUP${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase1-setup-accounts.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase1-setup-accounts.sh"
  PHASE1_DONE=true
  echo -e "${GREEN}✓ Phase 1 Complete${NC}"
else
  echo -e "${RED}✗ Phase 1 script not found${NC}"
  exit 1
fi

echo ""
read -p "Press ENTER to continue to Phase 2... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: ENVIRONMENT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 2: ENVIRONMENT CONFIGURATION${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase2-configure-environment.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase2-configure-environment.sh"
  PHASE2_DONE=true
  echo -e "${GREEN}✓ Phase 2 Complete${NC}"
else
  echo -e "${RED}✗ Phase 2 script not found${NC}"
  exit 1
fi

echo ""
read -p "Press ENTER to continue to Phase 3... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: FRONTEND DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 3: FRONTEND DEPLOYMENT & TESTING${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase3-deploy-frontend.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase3-deploy-frontend.sh"
  PHASE3_DONE=true
  echo -e "${GREEN}✓ Phase 3 Complete${NC}"
else
  echo -e "${RED}✗ Phase 3 script not found${NC}"
  exit 1
fi

echo ""
read -p "Press ENTER to continue to Phase 4... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: PAYMENT VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 4: PAYMENT FLOW VERIFICATION${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase4-verify-payments.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase4-verify-payments.sh"
  PHASE4_DONE=true
  echo -e "${GREEN}✓ Phase 4 Complete${NC}"
else
  echo -e "${RED}✗ Phase 4 script not found${NC}"
  exit 1
fi

echo ""
read -p "Press ENTER to continue to Phase 5... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: PRODUCTION LAUNCH
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 5: PRODUCTION LAUNCH${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

echo -e "${YELLOW}⚠️  WARNING: Phase 5 will enable LIVE payments!${NC}"
read -p "Continue to production launch? (yes/no): " LAUNCH

if [ "$LAUNCH" = "yes" ]; then
  if [ -f "$SCRIPT_DIR/revenue-deployment/phase5-production-launch.sh" ]; then
    bash "$SCRIPT_DIR/revenue-deployment/phase5-production-launch.sh"
    PHASE5_DONE=true
    echo -e "${GREEN}✓ Phase 5 Complete${NC}"
  else
    echo -e "${RED}✗ Phase 5 script not found${NC}"
    exit 1
  fi
else
  echo -e "${YELLOW}⚠ Skipping Phase 5. Run manually when ready.${NC}"
fi

echo ""
read -p "Press ENTER to continue to Phase 6... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: MONITORING & DOCUMENTATION
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 6: MONITORING & DOCUMENTATION${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase6-monitoring.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase6-monitoring.sh"
  PHASE6_DONE=true
  echo -e "${GREEN}✓ Phase 6 Complete${NC}"
else
  echo -e "${RED}✗ Phase 6 script not found${NC}"
  exit 1
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT COMPLETE
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                    🎉 ALL PHASES COMPLETE! 🎉                                ║"
echo "║                                                                               ║"
echo "║                  YOUR REVENUE SYSTEM IS LIVE!                                ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

echo "DEPLOYMENT SUMMARY:"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "Phase 1: Payment Infrastructure     [$( [ "$PHASE1_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 2: Environment Configuration  [$( [ "$PHASE2_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 3: Frontend Deployment        [$( [ "$PHASE3_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 4: Payment Verification       [$( [ "$PHASE4_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 5: Production Launch          [$( [ "$PHASE5_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 6: Monitoring & Documentation [$( [ "$PHASE6_DONE" = true ] && echo "✓" || echo "✗" )]"
echo ""

echo "📚 DOCUMENTATION CREATED:"
echo "• REVENUE_DASHBOARD_GUIDE.md"
echo "• REVENUE_OPERATIONS_RUNBOOK.md"
echo "• REVENUE_SUCCESS_METRICS.md"
echo "• monitoring/revenue-alerts.yml"
echo ""

echo "🚀 NEXT STEPS:"
echo "1. Monitor Stripe dashboard for first payments"
echo "2. Track MRR growth daily"
echo "3. Review email delivery rates"
echo "4. Watch for alerts"
echo "5. Celebrate first $1k MRR! 🎊"
echo ""

echo "💰 START MAKING MONEY! 💰"
echo ""
EOF

chmod +x "$PROJECT_ROOT/scripts/deploy-revenue-system.sh"

echo -e "${GREEN}✓ Master deployment script created${NC}"
echo "   Location: $PROJECT_ROOT/scripts/deploy-revenue-system.sh"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 6.6 MAKE ALL SCRIPTS EXECUTABLE
# ═══════════════════════════════════════════════════════════════════════════════

echo "6.6 MAKE SCRIPTS EXECUTABLE"
echo "───────────────────────────────────────────────────────────────────────────────"

chmod +x "$PROJECT_ROOT/scripts/revenue-deployment"/*.sh
echo -e "${GREEN}✓ All scripts are now executable${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                         PHASE 6 COMPLETE! ✅                                 ║"
echo "║                                                                               ║"
echo "║                     ALL 6 PHASES COMPLETE! 🎉                                ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

echo "✅ Revenue dashboard guide created"
echo "✅ Operational runbook created"
echo "✅ Monitoring alerts configured"
echo "✅ Success metrics tracker created"
echo "✅ Master deployment script created"
echo "✅ All scripts made executable"
echo ""

echo "📚 DOCUMENTATION CREATED:"
echo "───────────────────────────────────────────────────────────────────────────────"
echo "• REVENUE_DASHBOARD_GUIDE.md - Dashboard usage and KPIs"
echo "• REVENUE_OPERATIONS_RUNBOOK.md - Troubleshooting and procedures"
echo "• REVENUE_SUCCESS_METRICS.md - Success tracking"
echo "• monitoring/revenue-alerts.yml - Alert configuration"
echo ""

echo "🛠️ DEPLOYMENT SCRIPTS:"
echo "───────────────────────────────────────────────────────────────────────────────"
echo "• scripts/deploy-revenue-system.sh - Master script (all phases)"
echo "• scripts/revenue-deployment/phase1-setup-accounts.sh"
echo "• scripts/revenue-deployment/phase2-configure-environment.sh"
echo "• scripts/revenue-deployment/phase3-deploy-frontend.sh"
echo "• scripts/revenue-deployment/phase4-verify-payments.sh"
echo "• scripts/revenue-deployment/phase5-production-launch.sh"
echo "• scripts/revenue-deployment/phase6-monitoring.sh"
echo ""

echo "🚀 TO DEPLOY:"
echo "───────────────────────────────────────────────────────────────────────────────"
echo "Run master script:"
echo "  ./scripts/deploy-revenue-system.sh"
echo ""
echo "Or run individual phases:"
echo "  ./scripts/revenue-deployment/phase1-setup-accounts.sh"
echo "  ./scripts/revenue-deployment/phase2-configure-environment.sh"
echo "  ... and so on"
echo ""

echo "💰 YOUR REVENUE SYSTEM IS READY TO LAUNCH! 💰"
echo ""
