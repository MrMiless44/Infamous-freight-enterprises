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
