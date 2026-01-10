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
