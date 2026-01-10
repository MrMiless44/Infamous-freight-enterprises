# Production Monitoring & Observability

## Monitoring Stack Components

### 1. Prometheus (Metrics Collection)

- **Port:** 9090
- **URL:** http://localhost:9090
- **Purpose:** Collects metrics from all services
- **Scrape Interval:** 15 seconds
- **Retention:** 15 days

#### Prometheus Dashboard Usage

1. Visit http://localhost:9090
2. Click "Graph" tab
3. Enter metric name (e.g., `http_requests_total`)
4. Execute to see time-series data
5. Create custom graphs as needed

### 2. Grafana (Visualization & Alerts)

- **Port:** 3002
- **URL:** http://localhost:3002
- **Default User:** admin
- **Default Password:** (see .env.production)

#### Pre-configured Dashboards

- Application Performance
- Database Metrics
- Redis Cache Stats
- API Response Times
- Error Rates

#### Creating Custom Dashboards

1. Login to Grafana
2. Click "+" > "Dashboard"
3. Add panels with Prometheus data source
4. Save dashboard

### 3. Application Logs (Winston)

**Location:** `/var/log/infamous-freight/`

**Log Files:**

- `api.log` - API server logs
- `web.log` - Web server logs
- `error.log` - Error logs only
- `combined.log` - All logs

**Log Levels:**

- `error` - Critical issues
- `warn` - Warnings
- `info` - Business events
- `debug` - Diagnostic info

### 4. Error Tracking (Sentry)

**DSN:** (configured in .env.production)

**Features:**

- Error aggregation
- User session tracking
- Performance monitoring
- Release tracking

#### Accessing Sentry Dashboard

1. Visit configured Sentry organization
2. Project: Infamous Freight Enterprises
3. View errors, releases, performance data

## Monitoring Queries

### API Performance Metrics

```promql
# Request rate (requests/sec)
rate(http_requests_total[1m])

# Request latency (p95)
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Error rate
rate(http_requests_total{status=~"5.."}[1m])
```

### Database Metrics

```promql
# Connection count
pg_stat_activity_count

# Query duration (p99)
histogram_quantile(0.99, rate(pg_slow_queries_seconds_bucket[5m]))

# Active transactions
pg_stat_activity_count{state="active"}
```

### Redis Metrics

```promql
# Connected clients
redis_connected_clients

# Memory usage
redis_memory_used_bytes

# Commands per second
rate(redis_commands_processed_total[1m])
```

## Alert Rules

### Critical Alerts

- API response time > 2s
- Error rate > 5%
- Database connection failures
- Redis connection failures
- Disk space < 10%
- Memory usage > 90%

### Warning Alerts

- API response time > 1s
- Error rate > 1%
- High CPU usage (> 75%)
- Memory usage > 80%

## Dashboards

### Application Dashboard

Displays:

- Request rate and latency
- Error rate
- Active users
- Top endpoints

### Infrastructure Dashboard

Displays:

- CPU usage
- Memory usage
- Disk space
- Network I/O

### Database Dashboard

Displays:

- Connection count
- Query performance
- Slow queries
- Replication lag

## Alerts Configuration

### Grafana Alerts

1. Login to Grafana (http://localhost:3002)
2. Navigate to Alerting > Notification channels
3. Configure channels (email, webhook, Slack)
4. Create alert rules for dashboards

### Prometheus Alerts

1. Edit prometheus.yml
2. Define alert rules (yaml)
3. Configure alert manager
4. Set notification routes

## Log Analysis

### View Recent Errors

```bash
docker-compose logs --tail=100 api | grep ERROR
```

### Search Logs

```bash
docker-compose logs api | grep "specific-text"
```

### Logs with Timestamps

```bash
docker-compose logs -t api
```

## Performance Optimization

### Identify Bottlenecks

1. Check Prometheus metrics
2. Look at slow query logs
3. Analyze CPU/memory usage
4. Review error rates

### Common Issues

- **High latency:** Check database queries
- **High error rate:** Check error logs in Sentry
- **Memory leak:** Monitor memory_used over time
- **Slow queries:** Check PostgreSQL slow query log

## Health Check Commands

```bash
# Overall health
curl http://localhost:3001/api/health

# Detailed metrics
curl http://localhost:3001/metrics | head -50

# Database health
docker exec infamous-db psql -U infamous -c "SELECT 1"

# Redis health
docker exec infamous-redis redis-cli ping

# Prometheus targets
curl http://localhost:9090/api/v1/targets
```

## Backup & Disaster Recovery

### Prometheus Data Backup

```bash
docker run --rm -v prometheus_data:/data \
  -v $(pwd):/backup \
  ubuntu tar czf /backup/prometheus_backup.tar.gz -C /data .
```

### Grafana Dashboards Backup

```bash
docker exec grafana grafana-cli admin export-dashboard \
  > dashboard_backup.json
```

### Restore Process

1. Stop services: `docker-compose down`
2. Restore data volumes
3. Start services: `docker-compose up -d`
4. Verify data is accessible
