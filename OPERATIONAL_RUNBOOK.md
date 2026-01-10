# 📘 OPERATIONAL RUNBOOK - Infamous Freight Enterprises v2.0.0

**Version:** 2.0.0  
**Build ID:** 64d01c6  
**Last Updated:** January 10, 2026  
**Status:** ✅ PRODUCTION OPERATIONAL

---

## 📋 TABLE OF CONTENTS

1. [Daily Operations](#daily-operations)
2. [Monitoring & Alerting](#monitoring--alerting)
3. [Scaling & Performance](#scaling--performance)
4. [Backup & Recovery](#backup--recovery)
5. [Troubleshooting](#troubleshooting)
6. [Incident Response](#incident-response)
7. [Security Operations](#security-operations)
8. [Maintenance Windows](#maintenance-windows)

---

## 🔄 DAILY OPERATIONS

### Morning Checklist (Start of Day)

```bash
# 1. Verify all services are running
docker-compose -f docker-compose.production.yml ps

# Expected output:
# NAME                 STATUS
# api                  Up (healthy)
# web                  Up (healthy)
# postgres             Up (healthy)
# redis                Up (healthy)
# prometheus           Up
# grafana              Up
# jaeger               Up

# 2. Check API health
curl -s http://localhost:3001/api/health | jq '.'

# Expected: 200 OK with status object

# 3. Check error tracking
# Visit Sentry dashboard: https://sentry.io/organizations/infamous-freight/

# 4. Review overnight alerts
# Check Datadog dashboard for alerts and anomalies

# 5. Database integrity check
docker-compose exec postgres psql -U postgres -d infamous_freight -c "SELECT COUNT(*) FROM shipments;"

# 6. Verify backups completed
docker-compose exec postgres pg_dump -U postgres infamous_freight | gzip > /backups/backup-$(date +%Y%m%d).sql.gz && echo "✅ Backup successful"
```

### Throughout Day Monitoring

```bash
# Monitor API response times
curl -i -w "\nResponse Time: %{time_total}s\n" http://localhost:3001/api/shipments

# Monitor error rates in Sentry
# Visit: https://sentry.io/organizations/infamous-freight/issues/

# Check Grafana dashboards
# http://localhost:3002 (view system metrics, API performance)

# Monitor real-user metrics (Datadog RUM)
# View user interactions, page load times, errors
```

### End of Day Checklist

```bash
# 1. Review logs for errors
docker-compose -f docker-compose.production.yml logs --tail=100 api | grep "ERROR"

# 2. Verify all services still healthy
docker-compose -f docker-compose.production.yml ps

# 3. Database backup confirmation
ls -lh /backups/ | tail -1

# 4. Check alert queue
# Verify no critical alerts remain unresolved

# 5. Document any issues
# Log in incident tracking system
```

---

## 📊 MONITORING & ALERTING

### Prometheus Metrics

**Access:** http://localhost:9090

**Key Metrics to Monitor:**

```promql
# API Response Time (p95)
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Request Rate
rate(http_requests_total[5m])

# Error Rate
rate(http_requests_total{status=~"5.."}[5m])

# Database Connection Pool
pg_stat_activity_count

# Redis Memory Usage
redis_memory_used_bytes

# Disk Usage
node_filesystem_avail_bytes
```

### Grafana Dashboards

**Access:** http://localhost:3002 (admin credentials in .env.production)

**Available Dashboards:**

1. **System Overview**
   - CPU usage
   - Memory usage
   - Disk I/O
   - Network traffic

2. **API Performance**
   - Request rate
   - Response time (p50, p95, p99)
   - Error rate
   - Endpoint latency

3. **Database Metrics**
   - Query performance
   - Connection pool status
   - Cache hit rate
   - Transaction metrics

4. **Error Tracking**
   - Error rate timeline
   - Top errors
   - Error distribution
   - Stack traces

### Alert Rules

**Critical Alerts (Page immediately):**
- API down (no responses for 5 minutes)
- Database down
- Error rate > 5%
- Disk space < 10%
- Memory usage > 90%

**Warning Alerts (Notify channel):**
- API response time p95 > 2 seconds
- Cache hit rate < 80%
- Database slow queries > 10
- Error rate > 1%
- CPU usage > 80%

**Configure in Grafana:**

```
1. Visit http://localhost:3002
2. Click "Alerting" → "Notification Channels"
3. Add your notification channel (Slack, PagerDuty, Email)
4. Click "Alert Rules" → "New Alert"
5. Set metric and threshold
6. Configure notification channel
```

### Sentry Error Tracking

**Access:** https://sentry.io/organizations/infamous-freight/

**Setup:**
- Errors are automatically sent from API and Web app
- Group similar errors together
- Set release version: 2.0.0
- Create alerts for high-error-rate releases

**Daily Review:**
```bash
# Check for new error patterns
# Review stack traces for common issues
# Update error handling if needed
# Mark resolved issues as fixed
```

---

## 📈 SCALING & PERFORMANCE

### Horizontal Scaling

**Scale API instances:**
```bash
# Scale to 3 API instances
docker-compose -f docker-compose.production.yml up -d --scale api=3

# Verify scaling
docker-compose -f docker-compose.production.yml ps | grep api

# Monitor load distribution
curl http://localhost:3001/api/metrics | grep request_count
```

**Load Balancing:**
- Docker Compose automatically load-balances across instances
- Requests distributed via round-robin
- Configure sticky sessions for stateful operations

### Performance Tuning

**Database Query Optimization:**
```bash
# Identify slow queries
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT query, calls, mean_time, max_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;
"

# Add indexes if needed
docker-compose exec postgres psql -U postgres infamous_freight -c "
CREATE INDEX idx_shipments_status ON shipments(status);
CREATE INDEX idx_shipments_user_id ON shipments(user_id);
"
```

**Cache Optimization:**
```bash
# Monitor cache hit rate
docker-compose exec redis redis-cli INFO stats | grep hits

# Increase cache size if needed
docker-compose exec redis redis-cli CONFIG SET maxmemory 2gb

# Clear cache if needed
docker-compose exec redis redis-cli FLUSHALL
```

**Database Connection Pooling:**
```bash
# Check active connections
docker-compose exec postgres psql -U postgres -c "
SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;
"

# Adjust pool size in .env.production
# DATABASE_POOL_MIN=5
# DATABASE_POOL_MAX=20
```

---

## 💾 BACKUP & RECOVERY

### Automated Backups

**Daily Backup Schedule:**
```bash
# Add to crontab (runs daily at 2 AM)
0 2 * * * docker-compose -f /workspaces/Infamous-freight-enterprises/docker-compose.production.yml exec -T postgres pg_dump -U postgres infamous_freight | gzip > /backups/backup-$(date +\%Y\%m\%d).sql.gz

# Or manually run:
docker-compose exec postgres pg_dump -U postgres infamous_freight | gzip > /backups/backup-$(date +%Y%m%d).sql.gz
```

**Backup Verification:**
```bash
# Check backup size
ls -lh /backups/

# Test restore (on staging)
gunzip -c /backups/backup-20260110.sql.gz | docker-compose exec -T postgres psql -U postgres infamous_freight
```

### Point-in-Time Recovery

**If database is corrupted:**

```bash
# 1. Stop services
docker-compose -f docker-compose.production.yml down

# 2. Restore from backup
docker-compose -f docker-compose.production.yml up -d postgres
sleep 10

# 3. Restore database
gunzip -c /backups/backup-20260110.sql.gz | docker-compose exec -T postgres psql -U postgres infamous_freight

# 4. Verify restore
docker-compose exec postgres psql -U postgres infamous_freight -c "SELECT COUNT(*) FROM shipments;"

# 5. Restart all services
docker-compose -f docker-compose.production.yml up -d
```

### Redis Persistence

**Redis snapshots:**
```bash
# Manual snapshot
docker-compose exec redis redis-cli BGSAVE

# List snapshots
docker-compose exec redis redis-cli LASTSAVE

# Restore from snapshot (happens automatically on startup)
```

---

## 🔧 TROUBLESHOOTING

### API Service Issues

**API not responding:**
```bash
# 1. Check if running
docker-compose -f docker-compose.production.yml ps api

# 2. Check logs
docker-compose -f docker-compose.production.yml logs api --tail=50

# 3. Check database connection
docker-compose exec api npm run test:db

# 4. Restart service
docker-compose -f docker-compose.production.yml restart api

# 5. Check health endpoint
curl http://localhost:3001/api/health
```

**High response time:**
```bash
# 1. Check database performance
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT query, calls, mean_time FROM pg_stat_statements
ORDER BY mean_time DESC LIMIT 5;
"

# 2. Check cache hit rate
docker-compose exec redis redis-cli INFO stats

# 3. Check API logs for errors
docker-compose -f docker-compose.production.yml logs api --tail=100 | grep "slow"

# 4. Scale if needed
docker-compose -f docker-compose.production.yml up -d --scale api=3
```

### Database Issues

**Connection pool exhausted:**
```bash
# Check active connections
docker-compose exec postgres psql -U postgres -c "
SELECT datname, usename, state, count(*)
FROM pg_stat_activity
GROUP BY datname, usename, state;
"

# Kill idle connections
docker-compose exec postgres psql -U postgres -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle' AND state_change < NOW() - INTERVAL '30 minutes';
"

# Increase pool size in .env.production
```

**High disk usage:**
```bash
# Check table sizes
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) 
FROM pg_tables 
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 10;
"

# Vacuum tables to free space
docker-compose exec postgres psql -U postgres infamous_freight -c "
VACUUM ANALYZE;
"

# Archive old data if needed
docker-compose exec postgres psql -U postgres infamous_freight -c "
DELETE FROM shipment_history WHERE created_at < NOW() - INTERVAL '1 year';
"
```

### Cache Issues

**Redis memory high:**
```bash
# Check memory usage
docker-compose exec redis redis-cli INFO memory

# Clear expired keys
docker-compose exec redis redis-cli EVICT

# Reduce TTL for cache entries
# Update in API code: cache.set(key, value, 300) // 5 minutes
```

**Cache hit rate low:**
```bash
# Monitor cache usage
docker-compose exec redis redis-cli --stat

# Identify frequently accessed keys
docker-compose exec redis redis-cli KEYS '*' | wc -l

# Increase cache size
# In docker-compose.production.yml: 
# redis:
#   command: redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
```

---

## 🚨 INCIDENT RESPONSE

### Major Incident Procedure

**When Something Goes Wrong:**

```
Step 1: ALERT (Immediate)
├─ Acknowledge alert in monitoring system
├─ Check Sentry for error patterns
├─ Review logs for root cause
└─ Notify team in Slack/PagerDuty

Step 2: ASSESS (First 5 minutes)
├─ Check which services are affected
├─ Verify database is accessible
├─ Check external dependencies (Stripe, AI services)
└─ Estimate impact (users affected, revenue)

Step 3: TRIAGE (Next 5 minutes)
├─ Decide: Hotfix or Rollback?
├─ If fixable quickly: hotfix
├─ If not: rollback to previous version
└─ Communicate status to users

Step 4: FIX (5-30 minutes)
├─ Apply fix to code
├─ Test in staging first
├─ Deploy hotfix to production
└─ Verify service recovery

Step 5: MONITOR (30 minutes - 1 hour)
├─ Watch error rate return to normal
├─ Monitor user traffic recovery
├─ Check performance metrics
└─ Verify no cascading failures

Step 6: DOCUMENT (After recovery)
├─ Write incident postmortem
├─ Identify root cause
├─ Plan preventive measures
└─ Update runbooks
```

### Rollback Procedure

```bash
# 1. Identify last working version
git log --oneline | head -5

# 2. Rollback to previous build
git checkout <previous_commit_hash>

# 3. Rebuild and deploy
docker-compose -f docker-compose.production.yml down
docker-compose -f docker-compose.production.yml up -d --build

# 4. Verify rollback
curl http://localhost:3001/api/health

# 5. Communicate to team
# Notify team that rollback completed
# Schedule post-incident review
```

---

## 🔐 SECURITY OPERATIONS

### Daily Security Checks

```bash
# 1. Check for unauthorized access
docker-compose -f docker-compose.production.yml logs api | grep "401\|403" | wc -l

# 2. Monitor JWT token usage
curl -H "Authorization: Bearer $JWT_TOKEN" http://localhost:3001/api/shipments

# 3. Verify HTTPS/TLS (if deployed with reverse proxy)
openssl s_client -connect infamous-freight.com:443

# 4. Check rate limiting is active
# Make 100+ requests and verify 429 response
for i in {1..150}; do curl http://localhost:3001/api/shipments; done

# 5. Verify Stripe webhook signature
# Check logs for "webhook verified" messages
docker-compose -f docker-compose.production.yml logs api | grep "webhook"
```

### Secret Rotation

```bash
# Monthly JWT secret rotation (if implemented)
# 1. Generate new secret
openssl rand -base64 32

# 2. Update .env.production
# JWT_SECRET=<new_secret>

# 3. Restart services
docker-compose -f docker-compose.production.yml restart

# 4. Update documentation
# Note rotation date and time
```

### Access Control

```bash
# Review user permissions
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT user_id, role, created_at FROM users ORDER BY created_at DESC LIMIT 20;
"

# Remove inactive users (optional)
docker-compose exec postgres psql -U postgres infamous_freight -c "
DELETE FROM users WHERE last_login < NOW() - INTERVAL '90 days' AND role != 'admin';
"
```

---

## 🔧 MAINTENANCE WINDOWS

### Database Maintenance (Weekly)

```bash
# Vacuum to reclaim space
docker-compose exec postgres psql -U postgres infamous_freight -c "VACUUM ANALYZE;"

# Reindex tables
docker-compose exec postgres psql -U postgres infamous_freight -c "REINDEX DATABASE infamous_freight;"

# Update statistics
docker-compose exec postgres psql -U postgres infamous_freight -c "ANALYZE;"

# Check for table bloat
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) 
FROM pg_tables 
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"
```

### Dependency Updates (Monthly)

```bash
# Check for outdated packages
cd api && pnpm audit
cd ../web && pnpm audit

# Update security patches only
pnpm update --save --depth 0

# Test thoroughly
pnpm test

# Deploy only after testing
```

### Log Rotation (Automated)

```bash
# Ensure log rotation is configured
cat /etc/logrotate.d/docker-compose-logs

# Example configuration:
# /var/log/docker-compose/*.log {
#   daily
#   rotate 30
#   compress
#   delaycompress
#   notifempty
#   create 0640 root root
#   sharedscripts
# }
```

---

## 📞 SUPPORT ESCALATION

### Level 1: Monitoring & Alerts
- Check Grafana dashboards
- Review Sentry error tracking
- Check Datadog RUM
- Run health check script

### Level 2: Operational Support
- Reference DEPLOYMENT_COMMANDS.md
- Review MONITORING_PRODUCTION.md
- Check database performance
- Verify API responses

### Level 3: Emergency Engineering
- Execute rollback procedures
- Contact on-call engineer
- Initiate incident response
- Escalate to infrastructure team

---

**Last Updated:** January 10, 2026  
**Next Review:** January 17, 2026  
**Maintained By:** Operations Team
