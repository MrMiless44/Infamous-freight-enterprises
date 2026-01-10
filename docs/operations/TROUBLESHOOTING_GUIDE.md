# Troubleshooting Guide

## 🔍 Quick Diagnostic Steps

Before diving into specific issues, run these diagnostic commands:

```bash
# Check all services status
docker-compose ps

# Check API health
curl http://localhost:3001/api/health

# Check database connectivity
psql $DATABASE_URL -c "SELECT 1"

# Check Redis connectivity
redis-cli -u $REDIS_URL ping

# View recent logs
docker-compose logs --tail=50 -f
```

---

## 🚨 Common Issues

### Issue 1: "Cannot connect to database" Error

**Symptoms:**

```
Error: P1001: Can't reach database server at `localhost:5432`
```

**Possible Causes:**

1. PostgreSQL not running
2. Wrong `DATABASE_URL` in `.env`
3. Database not accepting connections
4. Connection pool exhausted

**Solutions:**

**Check 1: Is PostgreSQL running?**

```bash
# Check Docker container
docker ps | grep postgres

# If not running, start it
docker-compose up -d postgres
```

**Check 2: Verify DATABASE_URL**

```bash
# Print (masked) connection string
echo $DATABASE_URL | sed 's/:.*@/:****@/'

# Should look like: postgresql://user:****@localhost:5432/dbname
```

**Check 3: Test direct connection**

```bash
psql $DATABASE_URL -c "SELECT version()"
```

**Check 4: Connection pool**

```bash
# Check active connections
psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity;"

# If high (>18), kill idle connections
psql $DATABASE_URL -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle'
AND state_change < now() - interval '5 minutes';"
```

**Prevention:**

- Set connection limit in `prisma/schema.prisma`:
  ```prisma
  datasource db {
    url             = env("DATABASE_URL")
    connection_limit = 20
  }
  ```
- Enable connection pooling (already configured)

---

### Issue 2: "Prisma Client not generated" Error

**Symptoms:**

```typescript
Error: Cannot find module '@prisma/client'
```

**Solution:**

```bash
cd src/apps/api
pnpm prisma generate
pnpm build
```

**Prevention:**
Add to `postinstall` script in `package.json`:

```json
{
  "scripts": {
    "postinstall": "prisma generate"
  }
}
```

---

### Issue 3: TypeScript Compilation Errors

**Symptoms:**

```
error TS2307: Cannot find module 'next-auth'
error TS2688: Cannot find type definition file for 'jest'
```

**Solution:**

```bash
# Install missing dependencies
cd src/apps/web && pnpm add next-auth
cd src/apps/api && pnpm add -D @types/jest

# Rebuild
pnpm build
```

**Prevention:**

- Always run `pnpm install` after pulling new code
- Check `package.json` for required dependencies

---

### Issue 4: Redis Connection Failures

**Symptoms:**

```
Error: Redis connection refused
Cache hit rate: 0%
```

**Solution:**

```bash
# Check Redis status
docker ps | grep redis

# If not running
docker-compose up -d redis

# Test connection
redis-cli -u $REDIS_URL ping
# Should return: PONG

# Check Redis memory
redis-cli INFO memory
```

**Clear Cache (if corrupted):**

```bash
redis-cli FLUSHDB
# Restart API to rebuild cache
docker-compose restart api
```

**Prevention:**

- Monitor Redis memory usage (<80%)
- Set up Redis persistence (already configured in docker-compose.yml)

---

### Issue 5: JWT Token Verification Failures

**Symptoms:**

```
Error: jwt malformed
Error: jwt expired
Error: invalid signature
```

**Causes & Solutions:**

**Cause 1: Token expired (normal)**

```bash
# User needs to re-login
# Access tokens expire after 15 minutes
# Refresh tokens expire after 7 days
```

**Cause 2: JWT_SECRET changed**

```bash
# Check if JWT_SECRET is set
echo ${JWT_SECRET:0:10}...  # Should not be empty

# If changed, all users must re-login (expected behavior)
```

**Cause 3: Token blacklisted (after logout)**

```bash
# Check Redis blacklist
redis-cli KEYS "blacklist:*" | head -5

# If needed, clear blacklist (caution!)
redis-cli DEL "blacklist:<token>"
```

**Prevention:**

- Implement token rotation (✅ already added today)
- Monitor token expiration rates in Grafana

---

### Issue 6: High API Latency (>2s)

**Symptoms:**

- Grafana shows P95 latency >2000ms
- Slow page loads
- Timeouts

**Diagnostic Steps:**

**Step 1: Identify slow endpoints**

```bash
# Check Grafana: http://grafana.infamous-freight.com/d/api-overview
# Look for high-latency endpoints
```

**Step 2: Check database slow queries**

```bash
psql $DATABASE_URL -c "
SELECT pid, now() - query_start AS duration, query
FROM pg_stat_activity
WHERE state = 'active'
ORDER BY duration DESC
LIMIT 10;"
```

**Step 3: Check cache hit rate**

```bash
redis-cli INFO stats | grep hit_rate
# Should be >70%
```

**Solutions:**

**Solution 1: Add missing indexes**

```bash
cd src/apps/api
psql $DATABASE_URL -f prisma/migrations/20260110_add_performance_indexes.sql
```

**Solution 2: Restart Redis**

```bash
docker-compose restart redis
```

**Solution 3: Scale API horizontally**

```bash
# Fly.io
fly scale count 4 --app infamous-freight-api

# Docker Compose
docker-compose up -d --scale api=3
```

**Prevention:**

- Database indexes (✅ already added)
- Query optimization
- Cache warming on deploy

---

### Issue 7: Payment Processing Failures

**Symptoms:**

```
Stripe webhook error: 401 Unauthorized
PayPal IPN verification failed
```

**Diagnostic Steps:**

**Step 1: Check credentials**

```bash
# Stripe
echo $STRIPE_SECRET_KEY | cut -c1-10
# Should start with: sk_live_ (production) or sk_test_ (development)

# PayPal
echo $PAYPAL_CLIENT_ID | cut -c1-10
# Should be a long string
```

**Step 2: Verify webhook signature**

```bash
# Check logs for signature errors
docker logs api-container | grep -i "stripe\|paypal" | tail -20
```

**Step 3: Test webhook manually**

```bash
stripe listen --forward-to localhost:3001/api/billing/stripe-webhook
```

**Solutions:**

**Solution 1: Update webhook endpoint URL**

```bash
# Stripe Dashboard → Developers → Webhooks
# Update URL to: https://api.infamous-freight.com/api/billing/stripe-webhook
```

**Solution 2: Rotate API keys (if compromised)**

```bash
# Stripe Dashboard → Developers → API Keys → Roll key
# Update .env with new key
# Restart API
docker-compose restart api
```

**Prevention:**

- Monitor webhook delivery success rate
- Set up retry logic (✅ already implemented)
- Test webhooks in staging before production

---

### Issue 8: Docker Build Failures

**Symptoms:**

```
ERROR [build 5/7] RUN pnpm install --frozen-lockfile
ERROR: failed to solve: process "/bin/sh -c pnpm install" did not complete successfully
```

**Solutions:**

**Solution 1: Clear Docker cache**

```bash
docker-compose down
docker system prune -a
docker-compose up -d --build
```

**Solution 2: Update dependencies**

```bash
# Delete lock file and node_modules
rm pnpm-lock.yaml
rm -rf node_modules
pnpm install
```

**Solution 3: Fix dependency conflicts**

```bash
# Check for peer dependency issues
pnpm install --legacy-peer-deps
```

---

### Issue 9: Migration Failures

**Symptoms:**

```
Error: Migration failed
Schema drift detected
```

**Solutions:**

**Solution 1: Reset database (development only)**

```bash
cd src/apps/api
pnpm prisma migrate reset
pnpm prisma migrate deploy
```

**Solution 2: Resolve migration conflict**

```bash
# Mark migration as rolled back
pnpm prisma migrate resolve --rolled-back <migration-name>

# Apply pending migrations
pnpm prisma migrate deploy
```

**Solution 3: Schema drift**

```bash
# Generate new migration from schema changes
pnpm prisma migrate dev --name fix_schema_drift
```

---

### Issue 10: Rate Limiting Issues

**Symptoms:**

```
Error: Too many requests
429 Too Many Requests
```

**Diagnostic Steps:**

**Step 1: Check rate limit config**

```typescript
// src/apps/api/src/middleware/security.js
const limiters = {
  general: 100 requests / 15 minutes,
  auth: 5 requests / 15 minutes,
  billing: 30 requests / 15 minutes,
  ai: 20 requests / 1 minute,
};
```

**Step 2: Identify source of requests**

```bash
# Check access logs
docker logs api-container | grep "429" | tail -20
```

**Solutions:**

**Solution 1: Whitelist trusted IPs**

```typescript
// Add to security.js
const whitelist = ["10.0.0.0/8", "172.16.0.0/12"];
if (whitelist.includes(req.ip)) {
  return next();
}
```

**Solution 2: Increase limits (if legitimate)**

```typescript
// Temporarily increase limit
const limiters = {
  general: rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }),
};
```

**Solution 3: Clear Redis (reset all rate limits)**

```bash
redis-cli FLUSHDB
```

---

## 📊 Performance Issues

### Slow Database Queries

**Diagnostic:**

```bash
# Enable slow query log
psql $DATABASE_URL -c "ALTER SYSTEM SET log_min_duration_statement = 1000;"
psql $DATABASE_URL -c "SELECT pg_reload_conf();"

# View slow queries
psql $DATABASE_URL -c "
SELECT query, calls, mean_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;"
```

**Solution:**

```bash
# Add indexes (already created)
psql $DATABASE_URL -f prisma/migrations/20260110_add_performance_indexes.sql

# Analyze tables
psql $DATABASE_URL -c "ANALYZE;"
```

---

### Low Cache Hit Rate (<40%)

**Diagnostic:**

```bash
redis-cli INFO stats | grep keyspace_hits
redis-cli INFO stats | grep keyspace_misses
```

**Solution:**

```bash
# Warm up cache
curl http://localhost:3001/api/shipments?preload=true

# Increase cache TTL (in cache.ts)
const TTL = 3600; // 1 hour instead of 15 minutes
```

---

### High Memory Usage

**Diagnostic:**

```bash
# Node.js memory
docker stats api-container

# If high, restart
docker-compose restart api
```

**Solution:**

```bash
# Increase Node.js memory limit
NODE_OPTIONS="--max-old-space-size=4096" pnpm start
```

---

## 🔐 Security Issues

### Brute Force Attack Detected

**Symptoms:**

```
Alert: Repeated authentication failures
100+ failed login attempts from IP: X.X.X.X
```

**Solution:**

```bash
# Block IP at firewall level (immediate)
iptables -A INPUT -s X.X.X.X -j DROP

# Or use fail2ban (permanent)
fail2ban-client set sshd banip X.X.X.X
```

---

### Suspicious SQL Injection Attempt

**Symptoms:**

```
Log: Attempted SQL injection: ' OR 1=1--
```

**Solution:**

```bash
# Run SQL injection test suite
cd src/apps/api
pnpm test src/__tests__/security/sql-injection.test.ts

# All tests should pass
# If any fail, review endpoint code immediately
```

---

## 🧰 Useful Debugging Commands

### View Real-Time Logs

```bash
# All services
docker-compose logs -f --tail=100

# API only
docker logs -f api-container

# Database errors only
docker logs postgres-container 2>&1 | grep ERROR
```

### Check Service Health

```bash
# API
curl http://localhost:3001/api/health | jq

# Database
psql $DATABASE_URL -c "SELECT 1"

# Redis
redis-cli PING
```

### Performance Profiling

```bash
# API endpoint response time
time curl http://localhost:3001/api/shipments

# Database query execution plan
psql $DATABASE_URL -c "EXPLAIN ANALYZE SELECT * FROM \"Shipment\" WHERE status = 'in_transit';"
```

### Memory Analysis

```bash
# Node.js heap snapshot
node --expose-gc --inspect server.js

# Connect Chrome DevTools to localhost:9229
# Take heap snapshot and analyze
```

---

## 📞 Getting Help

If you're still stuck after trying these solutions:

1. **Check Documentation:**
   - [Architecture Guide](../ARCHITECTURE.md)
   - [API Documentation](https://api-docs.infamous-freight.com)
   - [Deployment Guide](../DEPLOYMENT_GUIDE.md)

2. **Review Recent Changes:**

   ```bash
   git log --oneline -20
   git show HEAD
   ```

3. **Contact On-Call Engineer:**
   - See [On-Call Runbook](./ON_CALL_RUNBOOK.md) for contact info
   - Slack: #incidents or #engineering

4. **Create Incident:**
   - Severity 1 (Production down): Page immediately
   - Severity 2 (Degraded): Post in #incidents
   - Severity 3 (Minor): Create Jira ticket

---

**Last Updated:** 2026-01-10  
**Owner:** Platform Engineering  
**Review Frequency:** Monthly
