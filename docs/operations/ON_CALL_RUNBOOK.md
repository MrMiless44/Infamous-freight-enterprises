# On-Call Engineering Runbook

## 📞 Emergency Contacts

### Primary On-Call Engineers

| Name               | Role          | Phone           | Email                         | Backup    |
| ------------------ | ------------- | --------------- | ----------------------------- | --------- |
| Primary Engineer   | Lead Backend  | +1-XXX-XXX-XXXX | engineer@infamous-freight.com | Secondary |
| Secondary Engineer | Senior DevOps | +1-XXX-XXX-XXXX | devops@infamous-freight.com   | Tertiary  |
| Tertiary Engineer  | Platform Lead | +1-XXX-XXX-XXXX | platform@infamous-freight.com | Primary   |

### Escalation Path

1. **L1 (0-15 min):** On-call engineer responds
2. **L2 (15-30 min):** Escalate to backup engineer
3. **L3 (30-60 min):** Escalate to engineering manager
4. **L4 (60+ min):** Escalate to CTO

### External Contacts

| Service           | Contact              | Purpose               |
| ----------------- | -------------------- | --------------------- |
| AWS Support       | +1-XXX-XXX-XXXX      | Infrastructure issues |
| Vercel Support    | support@vercel.com   | Deployment issues     |
| Stripe Support    | +1-XXX-XXX-XXXX      | Payment issues        |
| Database Provider | support@provider.com | Database emergencies  |

## 🚨 Incident Response Procedures

### Severity Levels

**SEV-1: Critical (Production Down)**

- Response Time: 5 minutes
- Symptoms: API 5xx errors >50%, users cannot access system
- Actions:
  1. Acknowledge incident in PagerDuty
  2. Start war room (Slack #incidents)
  3. Check health endpoint: `GET /api/health`
  4. Review recent deployments
  5. Rollback if necessary: `fly deploy --image <previous-version>`

**SEV-2: Major (Degraded Performance)**

- Response Time: 15 minutes
- Symptoms: API latency >2s, cache hit rate <40%
- Actions:
  1. Check Grafana dashboards
  2. Review database slow queries
  3. Restart Redis if cache miss rate high
  4. Scale up API instances if needed

**SEV-3: Minor (Isolated Issues)**

- Response Time: 1 hour
- Symptoms: Single feature broken, <5% users affected
- Actions:
  1. Create incident ticket
  2. Investigate logs
  3. Fix during business hours

### Incident Checklist

```markdown
## Incident Response Checklist

- [ ] Incident acknowledged (< 5 min)
- [ ] Severity assigned (SEV-1/2/3)
- [ ] War room started (#incidents Slack channel)
- [ ] Status page updated (status.infamous-freight.com)
- [ ] Customer support notified
- [ ] Root cause identified
- [ ] Fix applied or rollback completed
- [ ] Monitoring confirms resolution
- [ ] Postmortem scheduled (within 48h)
- [ ] Incident closed
```

## 🔍 Common Issues & Solutions

### Issue 1: API 500 Errors Spike

**Symptoms:**

- Error rate >5%
- Logs show `ECONNREFUSED` to database
- Health check failing

**Diagnosis:**

```bash
# Check database connection
docker exec -it api-container pnpm prisma db pull

# Check Redis connection
redis-cli ping

# Review logs
docker logs api-container --tail 100
```

**Resolution:**

```bash
# Restart database connection pool
docker-compose restart api

# If persistent, check database health
psql $DATABASE_URL -c "SELECT 1"
```

**Prevention:**

- Enable connection pooling (already configured)
- Set up database replica for failover

---

### Issue 2: High API Latency (>2s P95)

**Symptoms:**

- Grafana shows P95 latency >2000ms
- Cache hit rate <40%
- Database queries slow

**Diagnosis:**

```bash
# Check slow queries
psql $DATABASE_URL -c "SELECT pid, now() - query_start AS duration, query
FROM pg_stat_activity WHERE state = 'active' ORDER BY duration DESC LIMIT 10;"

# Check Redis performance
redis-cli INFO stats
```

**Resolution:**

```bash
# Restart Redis cache
docker-compose restart redis

# Add missing indexes (if identified)
psql $DATABASE_URL -f prisma/migrations/add_indexes.sql

# Scale API horizontally
fly scale count 4 --app infamous-freight-api
```

**Prevention:**

- Database indexes (✅ already added)
- Query optimization
- Cache warming on deploy

---

### Issue 3: Payment Processing Failures

**Symptoms:**

- Stripe/PayPal webhooks failing
- Logs show `401 Unauthorized` from payment provider
- Users report failed charges

**Diagnosis:**

```bash
# Check payment provider credentials
echo $STRIPE_SECRET_KEY | cut -c1-10  # Should start with sk_live_

# Review webhook logs
curl -X GET https://api.stripe.com/v1/webhook_endpoints \
  -u $STRIPE_SECRET_KEY
```

**Resolution:**

```bash
# Verify webhook signature validation
# Check: src/apps/api/src/routes/billing.ts

# Re-register webhook if needed
stripe listen --forward-to localhost:3001/api/billing/stripe-webhook
```

**Prevention:**

- Monitor webhook delivery success rate
- Set up retry logic (already implemented)
- Test webhooks in staging before production

---

### Issue 4: Authentication Token Errors

**Symptoms:**

- Users logged out unexpectedly
- 401 errors on authenticated endpoints
- JWT verification failures

**Diagnosis:**

```bash
# Check JWT secret is set
echo $JWT_SECRET | wc -c  # Should be >32 characters

# Verify token format
node -e "console.log(require('jsonwebtoken').decode('$TOKEN'))"
```

**Resolution:**

```bash
# If JWT_SECRET changed, users must re-login (expected)
# Check token blacklist in Redis
redis-cli KEYS "blacklist:*" | head -10

# Clear blacklist if needed (caution!)
redis-cli FLUSHDB
```

**Prevention:**

- JWT secret rotation with grace period
- Refresh token implementation (✅ added today)
- Monitor token expiration rates

---

### Issue 5: Database Connection Pool Exhausted

**Symptoms:**

- Logs show `P1001: Can't reach database server`
- Connection timeout errors
- API freezes on database queries

**Diagnosis:**

```bash
# Check active connections
psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity;"

# Check Prisma pool config
grep -A5 "connection_limit" prisma/schema.prisma
```

**Resolution:**

```bash
# Increase connection pool size
# Edit: prisma/schema.prisma
# datasource db { url = env("DATABASE_URL"); connection_limit = 20 }

# Restart API
docker-compose restart api

# If urgent, kill idle connections
psql $DATABASE_URL -c "SELECT pg_terminate_backend(pid)
FROM pg_stat_activity WHERE state = 'idle' AND state_change < now() - interval '5 minutes';"
```

**Prevention:**

- Connection pooling (already configured)
- Query timeout limits
- Horizontal API scaling

## 📊 Monitoring & Alerts

### Key Metrics to Watch

**API Health:**

- P95 Latency: Target <300ms (Alert >800ms)
- Error Rate: Target <1% (Alert >5%)
- Throughput: Baseline 100 req/s (Alert on 50% drop)

**Database:**

- Connection Pool Usage: Target <70% (Alert >90%)
- Slow Queries: Target 0 (Alert >5 queries >1s)
- Replica Lag: Target <100ms (Alert >1s)

**Cache:**

- Hit Rate: Target >70% (Alert <40%)
- Eviction Rate: Target <10/min (Alert >50/min)
- Memory Usage: Target <80% (Alert >95%)

**Business Metrics:**

- Active Shipments: Baseline 1,000 (Alert on 50% drop)
- Payment Success Rate: Target >98% (Alert <95%)
- User Signups: Baseline 50/day (Alert on 80% drop)

### Grafana Dashboards

1. **API Overview:** http://grafana.infamous-freight.com/d/api-overview
2. **Database Performance:** http://grafana.infamous-freight.com/d/database
3. **Cache Metrics:** http://grafana.infamous-freight.com/d/cache
4. **Business KPIs:** http://grafana.infamous-freight.com/d/business

### Prometheus Alerts

Alert configurations in `monitoring/prometheus/alerts.yml`:

- `HighErrorRate`: 5xx errors >5% for 5 minutes
- `HighLatency`: P95 >800ms for 5 minutes
- `DatabaseDown`: Health check fails 3 consecutive times
- `CacheMissHigh`: Hit rate <40% for 10 minutes

## 🛠️ Useful Commands

### Check System Health

```bash
# API health
curl https://api.infamous-freight.com/api/health

# Database connection
psql $DATABASE_URL -c "SELECT 1"

# Redis connection
redis-cli -u $REDIS_URL ping

# Check all Docker services
docker-compose ps
```

### Restart Services

```bash
# Restart API only
docker-compose restart api

# Restart all services
docker-compose restart

# Restart with rebuild
docker-compose up -d --build api
```

### View Logs

```bash
# API logs (last 100 lines)
docker logs api-container --tail 100 -f

# Database logs
docker logs postgres-container --tail 100 -f

# All services
docker-compose logs -f --tail 100
```

### Rollback Deployment

```bash
# Fly.io rollback (last working version)
fly releases --app infamous-freight-api
fly deploy --image registry.fly.io/infamous-freight-api:v123

# Docker rollback
docker-compose down
git checkout <previous-commit>
docker-compose up -d --build
```

### Database Operations

```bash
# Run migration
cd src/apps/api && pnpm prisma migrate deploy

# Rollback migration
pnpm prisma migrate resolve --rolled-back <migration-name>

# Database backup
pg_dump $DATABASE_URL > backup-$(date +%Y%m%d-%H%M%S).sql

# Restore backup
psql $DATABASE_URL < backup-20260110-120000.sql
```

## 📝 Postmortem Template

After resolving a SEV-1 or SEV-2 incident, create a postmortem:

```markdown
# Incident Postmortem: [Title]

**Date:** YYYY-MM-DD  
**Severity:** SEV-X  
**Duration:** X hours  
**Impact:** X users affected, $Y revenue lost

## Timeline

- **HH:MM** - Incident detected (alert fired)
- **HH:MM** - On-call engineer acknowledged
- **HH:MM** - Root cause identified
- **HH:MM** - Fix deployed
- **HH:MM** - Incident resolved

## Root Cause

[Detailed explanation of what caused the incident]

## Impact

- X users unable to access system
- Y API requests failed (Z% error rate)
- $W estimated revenue loss

## Resolution

[What was done to fix the issue]

## Action Items

- [ ] [Action 1] - Owner: [Name] - Due: [Date]
- [ ] [Action 2] - Owner: [Name] - Due: [Date]
- [ ] [Action 3] - Owner: [Name] - Due: [Date]

## Lessons Learned

[What we learned and how to prevent this in the future]
```

Save to: `docs/postmortems/YYYY-MM-DD-incident-title.md`

## 📚 Additional Resources

- [Architecture Documentation](../ARCHITECTURE.md)
- [Deployment Guide](../DEPLOYMENT_GUIDE.md)
- [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md)
- [API Documentation](https://api-docs.infamous-freight.com)
- [Status Page](https://status.infamous-freight.com)

---

**Last Updated:** 2026-01-10  
**Owner:** Engineering Team  
**Review Frequency:** Quarterly
