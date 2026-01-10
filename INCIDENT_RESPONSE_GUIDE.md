# 🚨 INCIDENT RESPONSE & TROUBLESHOOTING GUIDE

**Version:** 2.0.0  
**Status:** ✅ PRODUCTION  
**Last Updated:** January 10, 2026

---

## 📋 INCIDENT SEVERITY MATRIX

| Severity | Impact | Response Time | Examples |
|----------|--------|----------------|----------|
| **Critical** | Total outage, no users can access | 5 min | API down, Database down, All errors |
| **High** | Partial outage, some users affected | 15 min | 50%+ error rate, Login broken |
| **Medium** | Degraded performance, workaround exists | 1 hour | Slow API responses, Cache issues |
| **Low** | Minor issue, no user impact | 4 hours | Log errors, Unused code warnings |

---

## 🚨 CRITICAL INCIDENTS

### API Service Completely Down

**Detection:** No response from http://localhost:3001/api/health

**Immediate Action (First 2 minutes):**
```bash
# 1. Verify service status
docker-compose -f docker-compose.production.yml ps api

# 2. Check if container exists
docker ps | grep api

# 3. View error logs
docker-compose -f docker-compose.production.yml logs api --tail=100

# 4. Check recent code changes
git log --oneline -5
```

**Root Cause Analysis:**
```bash
# Memory leak?
docker stats api --no-stream

# CPU maxed?
docker stats api --no-stream | grep CPU

# Port conflict?
lsof -i :3001

# Database connection?
docker-compose exec api npm run test:db

# Environment variables?
docker-compose exec api env | grep DATABASE_URL
```

**Recovery Steps:**
```bash
# Option 1: Restart service
docker-compose -f docker-compose.production.yml restart api

# Option 2: Rebuild if code changed
docker-compose -f docker-compose.production.yml down api
docker-compose -f docker-compose.production.yml up -d --build api

# Option 3: Rollback if recent deployment
git revert HEAD
docker-compose -f docker-compose.production.yml down
docker-compose -f docker-compose.production.yml up -d --build

# Verify recovery
curl http://localhost:3001/api/health
```

**Post-Recovery:**
```bash
# Monitor for 10 minutes
watch -n 5 'docker-compose -f docker-compose.production.yml ps api && curl http://localhost:3001/api/health'

# Check error rates
docker-compose -f docker-compose.production.yml logs api | grep ERROR | wc -l
```

---

### Database Connection Failure

**Detection:** Database connection timeout, pool exhausted

**Immediate Action:**
```bash
# 1. Check if database is running
docker-compose -f docker-compose.production.yml ps postgres

# 2. Test connection
docker-compose exec postgres psql -U postgres -c "SELECT 1;"

# 3. Check active connections
docker-compose exec postgres psql -U postgres -c "
SELECT datname, count(*) as conn_count
FROM pg_stat_activity
GROUP BY datname;
"

# 4. Check database size
docker-compose exec postgres psql -U postgres -c "
SELECT pg_size_pretty(pg_database_size('infamous_freight'));
"
```

**Root Cause Analysis:**
```bash
# Connection pool exhausted?
docker-compose exec postgres psql -U postgres -c "
SELECT count(*) as total_connections FROM pg_stat_activity;
"

# Idle connections hanging?
docker-compose exec postgres psql -U postgres -c "
SELECT pid, state, state_change FROM pg_stat_activity WHERE state = 'idle';
"

# Slow query blocking connections?
docker-compose exec postgres psql -U postgres -c "
SELECT query, calls, mean_time FROM pg_stat_statements
ORDER BY mean_time DESC LIMIT 5;
"

# Disk space?
docker-compose exec postgres psql -U postgres -c "
SELECT pg_database_size('infamous_freight') as size;
"
```

**Recovery Steps:**
```bash
# Option 1: Kill idle connections
docker-compose exec postgres psql -U postgres -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle' AND state_change < NOW() - INTERVAL '10 minutes';
"

# Option 2: Restart database
docker-compose -f docker-compose.production.yml restart postgres
sleep 10

# Option 3: Full recovery
docker-compose -f docker-compose.production.yml down postgres
docker-compose -f docker-compose.production.yml up -d postgres
sleep 15
docker-compose -f docker-compose.production.yml up -d

# Verify recovery
docker-compose exec postgres psql -U postgres -c "SELECT COUNT(*) FROM shipments;"
```

---

### High Error Rate (>5%)

**Detection:** Error rate spike in Grafana or Sentry

**Immediate Action:**
```bash
# 1. Identify error pattern
docker-compose -f docker-compose.production.yml logs api | grep ERROR | head -20

# 2. Check which endpoint is failing
docker-compose -f docker-compose.production.yml logs api | grep "POST\|GET\|PUT\|DELETE" | grep "500\|5.."

# 3. Check error count
docker-compose -f docker-compose.production.yml logs api | grep ERROR | wc -l

# 4. Check Sentry dashboard
# Visit: https://sentry.io/organizations/infamous-freight/
```

**Root Cause Analysis:**
```bash
# Database issues?
curl -s http://localhost:3001/api/health | jq '.database'

# Memory issue?
docker stats api --no-stream | awk '{print $3}'

# Cache issue?
docker-compose exec redis redis-cli INFO stats

# External service down (Stripe, AI)?
grep "external\|stripe\|openai" /var/log/docker-compose/*.log

# Code bug?
git log --oneline -5
git diff HEAD~1 HEAD -- src/routes
```

**Recovery Steps:**
```bash
# Option 1: Clear cache if it's cache-related
docker-compose exec redis redis-cli FLUSHALL

# Option 2: Rollback if recent deployment
git revert HEAD
docker-compose -f docker-compose.production.yml down
docker-compose -f docker-compose.production.yml up -d --build

# Option 3: Scale up if overloaded
docker-compose -f docker-compose.production.yml up -d --scale api=3

# Option 4: Restart services
docker-compose -f docker-compose.production.yml restart api web

# Monitor error rate
watch -n 5 'docker-compose -f docker-compose.production.yml logs api --since 1m | grep ERROR | wc -l'
```

---

## 🟠 HIGH SEVERITY INCIDENTS

### API Response Time > 2 seconds (p95)

**Detection:** Grafana alert or slow user reports

**Investigation:**
```bash
# 1. Check database slow queries
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT query, calls, mean_time FROM pg_stat_statements
WHERE mean_time > 1000 ORDER BY mean_time DESC LIMIT 10;
"

# 2. Check cache hit rate
docker-compose exec redis redis-cli INFO stats | grep hits

# 3. Check API logs
docker-compose -f docker-compose.production.yml logs api | grep "slow\|duration" | tail -20

# 4. Check system resources
docker stats api postgres redis --no-stream
```

**Solutions:**
```bash
# Option 1: Add database indexes
docker-compose exec postgres psql -U postgres infamous_freight -c "
CREATE INDEX CONCURRENTLY idx_shipments_status_created 
ON shipments(status, created_at);
"

# Option 2: Optimize cache
docker-compose exec redis redis-cli CONFIG SET maxmemory 2gb

# Option 3: Scale API
docker-compose -f docker-compose.production.yml up -d --scale api=3

# Option 4: Increase DB connections
# Edit .env.production:
# DATABASE_POOL_MIN=10
# DATABASE_POOL_MAX=30
docker-compose -f docker-compose.production.yml restart api
```

---

### Login/Authentication Failures

**Detection:** Multiple 401/403 errors, users can't log in

**Investigation:**
```bash
# 1. Check JWT secret is loaded
docker-compose exec api env | grep JWT_SECRET

# 2. Check token validation logs
docker-compose -f docker-compose.production.yml logs api | grep "jwt\|unauthorized"

# 3. Check database for user data
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT COUNT(*) FROM users;
"

# 4. Check Stripe webhook for payment issues
curl http://localhost:3001/api/health | jq '.stripe'
```

**Recovery:**
```bash
# Option 1: Verify JWT secret
echo $JWT_SECRET
# If empty, reload .env.production
source .env.production

# Option 2: Restart auth service
docker-compose -f docker-compose.production.yml restart api

# Option 3: Check user permissions
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT user_id, role, created_at FROM users LIMIT 10;
"

# Option 4: Reset test user
docker-compose exec postgres psql -U postgres infamous_freight -c "
UPDATE users SET verified = true WHERE email = 'test@example.com';
"
```

---

## 🟡 MEDIUM SEVERITY INCIDENTS

### Database Disk Space Low

**Detection:** Grafana alert or manual check shows <20% free space

**Investigation:**
```bash
# Check disk usage
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
FROM pg_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 10;
"

# Check for bloated tables
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT relname, round(100.0 * (otta - live_tuples) / otta) as waste_pct
FROM pg_class WHERE otta > 0
ORDER BY waste_pct DESC LIMIT 10;
"
```

**Solutions:**
```bash
# Option 1: Vacuum and analyze
docker-compose exec postgres psql -U postgres infamous_freight -c "
VACUUM ANALYZE;
"

# Option 2: Clean up old data
docker-compose exec postgres psql -U postgres infamous_freight -c "
DELETE FROM shipment_history WHERE created_at < NOW() - INTERVAL '2 years';
"

# Option 3: Increase volume size
# Edit docker-compose.production.yml:
# volumes:
#   postgres_data:
#     driver: local
#     driver_opts:
#       type: tmpfs
#       device: tmpfs
#       size: 50gb  # Increase from current size

# Restart with new size
docker-compose -f docker-compose.production.yml down
docker-compose -f docker-compose.production.yml up -d postgres
```

---

### Memory Usage High (>85%)

**Detection:** Docker stats show high memory, Grafana alert

**Investigation:**
```bash
# Check which service using most memory
docker stats --no-stream | sort -k4 -hr

# Check if memory leak
docker stats api --no-stream
# Record every minute, look for consistent growth

# Check Node.js heap
docker-compose exec api npm run analyze:heap
```

**Solutions:**
```bash
# Option 1: Restart service
docker-compose -f docker-compose.production.yml restart api

# Option 2: Clear cache
docker-compose exec redis redis-cli FLUSHALL

# Option 3: Scale horizontally
docker-compose -f docker-compose.production.yml up -d --scale api=3

# Option 4: Increase memory limit
# Edit docker-compose.production.yml:
# services:
#   api:
#     deploy:
#       resources:
#         limits:
#           memory: 2G  # Increase from 1G

docker-compose -f docker-compose.production.yml up -d
```

---

## 🔍 DIAGNOSTIC TOOLS

### Health Check Script

```bash
#!/bin/bash
echo "📊 Production Health Check"
echo "========================="

# Services running?
echo "🔹 Services Status:"
docker-compose -f docker-compose.production.yml ps

# API responding?
echo ""
echo "🔹 API Health:"
curl -s http://localhost:3001/api/health | jq '.'

# Database connected?
echo ""
echo "🔹 Database Status:"
docker-compose exec postgres psql -U postgres -c "SELECT version();" 2>/dev/null || echo "❌ Database connection failed"

# Cache available?
echo ""
echo "🔹 Redis Status:"
docker-compose exec redis redis-cli ping 2>/dev/null || echo "❌ Redis connection failed"

# Disk space?
echo ""
echo "🔹 Disk Usage:"
docker exec postgres df -h | grep "/var/lib/postgresql"

# Memory usage?
echo ""
echo "🔹 Memory Usage:"
docker stats --no-stream | tail -n +2

# Error rate?
echo ""
echo "🔹 Recent Errors:"
docker-compose -f docker-compose.production.yml logs api --since 5m | grep ERROR | wc -l

echo ""
echo "✅ Health check complete"
```

### Performance Analysis

```bash
# API endpoint performance
echo "Analyzing API endpoint performance..."
for i in {1..10}; do
  curl -w "Request $i: %{time_total}s\n" http://localhost:3001/api/shipments -s -o /dev/null
done

# Database query performance
echo "Top 10 slowest queries:"
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT query, calls, mean_time 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;
" | column -t

# Cache hit ratio
echo "Cache performance:"
docker-compose exec redis redis-cli INFO stats | grep -E "hits|misses"
```

---

## 📞 ESCALATION CONTACTS

| Issue | Primary | Secondary | Notes |
|-------|---------|-----------|-------|
| **API Down** | Backend Lead | DevOps | Page immediately |
| **Database Down** | Database Admin | Backend Lead | Critical priority |
| **High Error Rate** | On-Call Engineer | Backend Lead | Check Sentry first |
| **Performance** | Performance Engineer | DevOps | Check metrics first |
| **Security** | Security Lead | DevOps | Verify and isolate |

---

**Last Updated:** January 10, 2026  
**Review Schedule:** Monthly  
**Next Update:** February 10, 2026
