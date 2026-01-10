# Production Deployment Commands

## Quick Deployment (Docker Compose - Recommended)

### Start Production Stack

```bash
docker-compose -f docker-compose.production.yml up -d
```

### Check Service Status

```bash
docker-compose -f docker-compose.production.yml ps
```

### View Logs

```bash
# All services
docker-compose -f docker-compose.production.yml logs -f

# Specific service
docker-compose -f docker-compose.production.yml logs -f api
docker-compose -f docker-compose.production.yml logs -f web
```

### Stop Services

```bash
docker-compose -f docker-compose.production.yml down
```

## Health Checks

### API Health

```bash
curl -s http://localhost:3001/api/health | jq .
```

### Web Health

```bash
curl -s http://localhost:3000/ | head -20
```

### Database Connection

```bash
docker-compose -f docker-compose.production.yml exec postgres \
  psql -U infamous -d infamous_freight -c "SELECT 1"
```

### Redis Connection

```bash
docker-compose -f docker-compose.production.yml exec redis \
  redis-cli ping
```

## Monitoring Access

### Prometheus Metrics

- URL: http://localhost:9090
- Default user: admin
- Default password: admin

### Grafana Dashboards

- URL: http://localhost:3002
- Default user: admin
- Default password: (from .env.production GRAFANA_ADMIN_PASSWORD)

### API Metrics

```bash
curl -s http://localhost:3001/metrics | head -50
```

## Troubleshooting

### View Service Logs

```bash
docker-compose -f docker-compose.production.yml logs [service-name]
```

### Restart Service

```bash
docker-compose -f docker-compose.production.yml restart [service-name]
```

### Check Resource Usage

```bash
docker stats
```

### Environment Variables Verification

```bash
docker-compose -f docker-compose.production.yml config | grep -A 50 "environment:"
```

## Post-Deployment Verification

### 1. API Availability

```bash
curl -s http://localhost:3001/api/health | jq .
# Expected: {"status": "ok", "uptime": "..."}
```

### 2. Web Application

```bash
curl -s http://localhost:3000/ | grep -o "<title>.*</title>"
```

### 3. Database Connectivity

```bash
docker-compose -f docker-compose.production.yml exec api \
  npx prisma db execute --stdin < /dev/null
```

### 4. Redis Cache

```bash
docker-compose -f docker-compose.production.yml exec api \
  npx redis-cli ping
```

### 5. Monitoring Stack

```bash
# Prometheus
curl -s http://localhost:9090/api/v1/targets | jq .

# Grafana
curl -s http://localhost:3002/api/health | jq .
```

## Scaling Commands

### Scale API Instances

```bash
docker-compose -f docker-compose.production.yml up -d --scale api=3
```

### Scale Web Instances

```bash
docker-compose -f docker-compose.production.yml up -d --scale web=2
```

## Backup & Recovery

### Database Backup

```bash
docker-compose -f docker-compose.production.yml exec postgres \
  pg_dump -U infamous infamous_freight > backup_$(date +%s).sql
```

### Database Restore

```bash
docker-compose -f docker-compose.production.yml exec postgres \
  psql -U infamous infamous_freight < backup_timestamp.sql
```

## Monitoring & Alerts

### Enable Prometheus Metrics Scraping

```bash
curl -X POST http://localhost:9090/api/v1/admin/tsdb/clean_tombstones
```

### Setup Grafana Alerts

1. Visit http://localhost:3002
2. Login with admin credentials
3. Navigate to: Alerting > Notification channels
4. Configure email/webhook endpoints

## Deployment Status

After deployment, verify:

- [ ] API responding at http://localhost:3001/api/health
- [ ] Web available at http://localhost:3000
- [ ] Database connected
- [ ] Redis cache running
- [ ] Prometheus scraping metrics
- [ ] Grafana dashboards loaded
- [ ] All containers running (docker ps)
