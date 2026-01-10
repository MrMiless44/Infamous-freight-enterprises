# Disaster Recovery Plan

## Overview

Comprehensive disaster recovery procedures for Infamous Freight Enterprises infrastructure and data.

**Last Updated**: January 2, 2026  
**Review Cycle**: Quarterly (April 2, July 2, October 2)  
**RTO Target**: 4 hours  
**RPO Target**: 1 hour

---

## 1. Database Recovery

### 1.1 Backup Strategy

**Automated Backups**:

- Frequency: Every 6 hours
- Retention: 30 days
- Location: AWS S3 (3 regions: us-east-1, eu-west-1, ap-southeast-1)
- Type: Full backup + continuous transaction logs

**Manual Backup**:

```bash
# Full backup before major migrations
pg_dump -U $POSTGRES_USER -h $DB_HOST -F custom -b $DB_NAME > backup_$(date +%Y%m%d_%H%M%S).dump

# Upload to S3
aws s3 cp backup_*.dump s3://infamous-freight-backups/postgres/manual/ --sse AES256
```

**Backup Verification**:

```bash
# Weekly restore test on staging database
pg_restore -U $POSTGRES_USER -h $STAGING_HOST -d infamous_freight_test < backup_latest.dump

# Verify data integrity
psql -c "SELECT COUNT(*) FROM shipments; SELECT COUNT(*) FROM drivers;"
```

### 1.2 Point-in-Time Recovery (PITR)

If database is corrupted/hacked, restore to known-good point:

```bash
# 1. Identify corruption time from logs
# 2. Create new RDS instance with point-in-time restore
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier infamous-freight-prod \
  --db-instance-identifier infamous-freight-restored \
  --restore-time 2026-01-02T14:30:00Z

# 3. Run integrity checks
pnpm prisma:validate

# 4. Promote restored instance (after verification)
aws rds promote-read-replica --db-instance-identifier infamous-freight-restored

# 5. Update application endpoint
# 6. Monitor for errors (30 min)
# 7. Archive corrupted database
```

**Estimated Time**: 30-60 minutes

### 1.3 Database Failover

If primary database becomes unavailable:

```bash
# 1. Check RDS status
aws rds describe-db-instances --db-instance-identifier infamous-freight-prod

# 2. Promote read replica (must be pre-created)
aws rds promote-read-replica \
  --db-instance-identifier infamous-freight-read-replica \
  --backup-retention-period 30

# 3. Update application connection string
fly secrets set DATABASE_URL="postgresql://new-host:5432/infamous_freight"

# 4. Restart API pods
fly scale count 1 && fly scale count 3

# 5. Verify connectivity
pnpm check:db

# 6. Replication setup (optional)
# Create new read replica on restored primary
aws rds create-db-instance-read-replica \
  --db-instance-identifier infamous-freight-read-replica-2 \
  --source-db-instance-identifier infamous-freight-prod
```

**Estimated Time**: 15-30 minutes

### 1.4 Data Restoration from Backup

For specific data loss (e.g., accidental deletion):

```bash
# 1. Restore full backup to temporary database
pg_restore -U $USER -h $TEMP_HOST -d infamous_freight_temp < backup_$(date +%Y%m%d).dump

# 2. Query the temporary database for lost data
SELECT * FROM shipments WHERE id = 'lost-shipment-id';

# 3. Script to restore specific records
psql -c "
  INSERT INTO shipments (id, origin, destination, ...)
  SELECT id, origin, destination, ... FROM infamous_freight_temp.shipments
  WHERE id = 'lost-shipment-id'
  ON CONFLICT DO NOTHING;
"

# 4. Verify restored data
pnpm test:data-integrity

# 5. Drop temporary database
dropdb -U $USER -h $TEMP_HOST infamous_freight_temp
```

---

## 2. Application Recovery

### 2.1 API Server Recovery

If API is down or corrupted:

```bash
# 1. Check pod status
fly status --app infamous-freight-api

# 2. Check logs for error
fly logs --app infamous-freight-api --lines 100

# 3. Restart API (rolling restart, no downtime)
fly scale count 0 && sleep 10 && fly scale count 3

# 4. Verify health check passes
curl https://api.infamous-freight.com/api/health

# 5. Monitor error rate
fly logs --app infamous-freight-api
```

**Estimated Time**: 5-10 minutes

### 2.2 Web Application Recovery

If web application is down:

```bash
# 1. Check Vercel deployment status
vercel status

# 2. Rollback to previous version (if needed)
vercel rollback --prod

# 3. Trigger manual redeploy
vercel deploy --prod

# 4. Verify SSL certificate (check web console)
# 5. Clear CDN cache
vercel caches purge --scope=production
```

**Estimated Time**: 5-15 minutes

### 2.3 Container Registry Corruption

If Docker images are corrupted:

```bash
# 1. Identify last known-good version
docker inspect infamous-freight-api:v2.0.0

# 2. Pull from backup registry
docker pull backup-registry.aws.com/infamous-freight-api:v2.0.0

# 3. Tag and push to primary registry
docker tag backup-registry.aws.com/infamous-freight-api:v2.0.0 \
  docker.io/infamousfreight/api:v2.0.0

docker push docker.io/infamousfreight/api:v2.0.0

# 4. Rebuild and test
docker build -t infamousfreight/api:v2.0.0 .
pnpm test:docker

# 5. Redeploy
fly deploy --image infamousfreight/api:v2.0.0
```

---

## 3. Data Loss Prevention

### 3.1 Transaction Log Archival

Maintain continuous WAL (Write-Ahead Logs) for point-in-time recovery:

```bash
# In RDS, enable automated backups
aws rds modify-db-instance \
  --db-instance-identifier infamous-freight-prod \
  --backup-retention-period 30 \
  --preferred-backup-window "02:00-03:00" \
  --enable-cloudwatch-logs-exports '["postgresql"]'
```

### 3.2 Cross-Region Replication

Replicate database to another AWS region:

```bash
# Create cross-region read replica
aws rds create-db-instance-read-replica \
  --db-instance-identifier infamous-freight-dr \
  --source-db-instance-identifier infamous-freight-prod \
  --source-region us-east-1 \
  --region eu-west-1

# Verify replication lag
aws cloudwatch get-metric-statistics \
  --namespace AWS/RDS \
  --metric-name AuroraBinlogReplicaLag \
  --dimensions Name=DBInstanceIdentifier,Value=infamous-freight-dr \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average
```

---

## 4. Networking & Infrastructure

### 4.1 DNS Failover

If primary domain/CDN is unreachable:

```bash
# 1. Check DNS propagation
dig @8.8.8.8 api.infamous-freight.com

# 2. Check Cloudflare DNS (if using)
curl -X GET "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN"

# 3. Failover to backup domain (if configured)
# Update: api.backup.infamous-freight.com → Fly.io load balancer

# 4. TTL check (may need to wait for cache invalidation)
# Most clients should see new IP within 5-15 minutes
```

### 4.2 Certificate Renewal

If SSL certificate expires:

```bash
# 1. Automatic renewal (Let's Encrypt via Vercel/Fly)
# Usually automatic; check Vercel console

# 2. Manual renewal if automatic fails
certbot renew --force-renewal

# 3. Update certificate in Fly.io
fly certs add api.infamous-freight.com

# 4. Verify certificate
openssl s_client -connect api.infamous-freight.com:443 -showcerts
```

---

## 5. Incident Response

### 5.1 Detection & Assessment

**Monitoring Alerts**:

- API health check fails → PagerDuty alert
- Database connection pool exhausted → Slack #alerts
- Error rate >5% → Page on-call engineer
- Disk usage >80% → Slack warning

**Assessment Checklist**:

- [ ] Severity level (Critical/High/Medium/Low)
- [ ] Affected systems (API/Web/Mobile/DB)
- [ ] Number of affected users
- [ ] Est. time to resolution
- [ ] Notify stakeholders (exec, support)

### 5.2 Communication

**Internal**:

1. Post in #incidents Slack channel with timestamp, severity
2. Page on-call engineer (PagerDuty)
3. Update status page every 15 min

**External**:

1. Post on status page: `infamous-freight.statuspage.io`
2. Tweet from @InfamousFreight if major
3. Email customers if data affected

**Template**:

```
🚨 [INCIDENT] Database Connection Timeout
- Status: Investigating
- Affected: API/Shipment Tracking
- Impact: Some users unable to view shipments
- ETA: Resolving by 15:30 UTC
- Updates every 15 minutes

Last Update: 15:10 UTC
```

### 5.3 Escalation

| Level     | Time     | Action                        |
| --------- | -------- | ----------------------------- |
| 0-15 min  | Alert    | On-call engineer investigates |
| 15-30 min | Alert    | Escalate to DevOps lead       |
| 30-60 min | Page     | CTO & CEO notified            |
| 60+ min   | Critical | All hands response            |

---

## 6. Recovery Verification

After restoring from disaster:

### 6.1 Data Integrity Checks

```bash
# Run comprehensive tests
pnpm test:data-integrity

# Verify row counts match backup
SELECT COUNT(*) as shipments FROM shipments;
SELECT COUNT(*) as drivers FROM drivers;

# Check for orphaned records
SELECT d.id FROM drivers d
LEFT JOIN shipments s ON s.driver_id = d.id
WHERE d.deleted_at IS NULL AND s.id IS NULL;
```

### 6.2 Application Tests

```bash
# Smoke tests
pnpm test:smoke

# E2E tests
pnpm test:e2e

# Performance test (ensure recovery didn't degrade)
pnpm test:performance
```

### 6.3 User Communication

- Post incident report in #general Slack
- Update status page: "All systems operational"
- Send email to affected users with apology & impact summary
- Schedule post-mortem meeting (24-48 hours)

---

## 7. Maintenance & Testing

### 7.1 Backup Testing Schedule

| Item                              | Frequency     | Owner                |
| --------------------------------- | ------------- | -------------------- |
| Backup verification               | Weekly        | DevOps               |
| PITR test                         | Monthly       | DevOps               |
| Failover drill                    | Quarterly     | DevOps + Engineering |
| Full disaster recovery simulation | Semi-annually | DevOps + Product     |

### 7.2 Documentation

- [ ] Keep runbooks updated after each incident
- [ ] Update contact list (on-call rotation)
- [ ] Test communication chains
- [ ] Review and update RTO/RPO targets

---

## 8. Emergency Contacts

| Role              | Name       | Phone                              | Email                            |
| ----------------- | ---------- | ---------------------------------- | -------------------------------- |
| DevOps Lead       | [Name]     | +1-XXX-XXX-XXXX                    | devops-lead@infamous-freight.com |
| CTO               | [Name]     | +1-XXX-XXX-XXXX                    | cto@infamous-freight.com         |
| CEO               | [Name]     | +1-XXX-XXX-XXXX                    | ceo@infamous-freight.com         |
| On-Call (weekday) | [Rotation] | [PagerDuty](https://pagerduty.com) | -                                |
| On-Call (weekend) | [Rotation] | [PagerDuty](https://pagerduty.com) | -                                |

---

## 9. Post-Incident Review

Within 48 hours of incident, conduct meeting with:

- Engineer who responded
- DevOps team
- Product manager
- Customer support

**Review Items**:

- Root cause analysis
- Why wasn't this caught earlier?
- Preventative measures
- Monitoring/alerting improvements
- Documentation updates

**Output**: Post-incident report posted in #engineering

---

## Appendix: Quick Recovery Commands

```bash
# Database
pg_dump -U user -h host -F custom db_name > backup.dump
pg_restore -U user -h host -d db_name < backup.dump

# API
fly logs --app infamous-freight-api
fly scale count 0 && sleep 10 && fly scale count 3

# Web
vercel rollback --prod
vercel deploy --prod

# Health Check
curl https://api.infamous-freight.com/api/health
curl https://infamous-freight.com/api/health

# Database Check
psql -c "SELECT 1;" # Quick connectivity test

# Notifications
# Slack: @here 🚨 Database down, investigating...
# StatusPage: Post incident update
# PagerDuty: Acknowledge alert
```

---

**Created**: January 2, 2026  
**Next Review**: April 2, 2026  
**Last Test**: [Date of last recovery drill]
