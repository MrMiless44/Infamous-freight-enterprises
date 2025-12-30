# Monitoring Setup & Operations Guide

**Project**: Infamous Freight Enterprises  
**Date**: December 30, 2025  
**Status**: Ready for Implementation

---

## Quick Start: Monitoring Stack

### Components to Deploy

1. **Prometheus** - Metrics collection (port 9090)
2. **Grafana** - Visualization & dashboards (port 3000)
3. **Redis** - Cache & adapter (port 6379)
4. **Winston** - Application logging (files + console)

### Docker Compose Setup

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD:-admin}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  prometheus_data:
  grafana_data:
  redis_data:
```

### Start Monitoring Stack

```bash
# 1. Copy monitoring config
cp docker-compose.monitoring.yml docker-compose.yml

# 2. Start services
docker-compose up -d

# 3. Verify services
curl http://localhost:9090/-/healthy    # Prometheus
curl http://localhost:3000              # Grafana (login: admin/admin)
redis-cli PING                          # Redis

# 4. Configure Grafana data source
# Visit http://localhost:3000
# Configuration → Data Sources → Add Prometheus
# URL: http://prometheus:9090
```

---

## Prometheus Configuration

### prometheus.yml

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'freight-api'

alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - localhost:9093

rule_files:
  - "alert_rules.yml"

scrape_configs:
  # API metrics
  - job_name: 'freight-api'
    static_configs:
      - targets: ['localhost:4000']
    metrics_path: '/api/metrics'

  # Node exporter (system metrics)
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']

  # Redis exporter
  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:6379']
```

### alert_rules.yml

```yaml
groups:
  - name: freight_alerts
    interval: 15s
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate > 5% for 5 minutes"

      # High latency
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "API latency high"
          description: "P95 latency > 1 second"

      # Memory warning
      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes / 1024 / 1024 > 1024
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory > 1GB"

      # WebSocket connection drop
      - alert: WebSocketDropping
        expr: rate(websocket_disconnections_total[1m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "WebSocket disconnections"
          description: "> 10 disconnections per minute"
```

---

## Grafana Dashboard Setup

### Import Grafana Config

```bash
# 1. Login to Grafana
# http://localhost:3000 (admin/admin)

# 2. Import from JSON
# Settings → Dashboards → Import
# Paste the configuration from src/apps/api/src/config/grafana.ts

# 3. Or create manually from queries below
```

### Dashboard: System Health

```
Panel 1: CPU Usage (%)
Query: rate(process_cpu_seconds_total[1m]) * 100
Thresholds: Warning 70%, Critical 85%

Panel 2: Memory Usage (MB)
Query: process_resident_memory_bytes / 1024 / 1024
Thresholds: Warning 800MB, Critical 1024MB

Panel 3: Uptime (hours)
Query: process_uptime_seconds / 3600

Panel 4: Disk Free (GB)
Query: node_filesystem_avail_bytes / 1024 / 1024 / 1024
```

### Dashboard: API Performance

```
Panel 1: Request Rate (req/s)
Query: rate(http_requests_total[1m])
Legend: {{ method }} {{ path }} {{ status }}

Panel 2: Response Time (ms)
Query: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) * 1000
Legend: P95 Latency

Panel 3: Error Rate (%)
Query: rate(http_requests_total{status=~"5.."}[1m]) / rate(http_requests_total[1m]) * 100
Legend: Error Rate

Panel 4: Active Connections
Query: http_requests_in_flight
Legend: In-Flight Requests
```

### Dashboard: WebSocket Real-time

```
Panel 1: Connected Clients
Query: websocket_connections_active
Legend: Active Connections

Panel 2: Messages/sec
Query: rate(websocket_messages_total[1m])
Legend: Messages/sec

Panel 3: Connection Latency (ms)
Query: websocket_connection_latency_ms
Legend: Latency

Panel 4: Reconnections
Query: rate(websocket_reconnections_total[1m])
Legend: Reconnections/sec
```

### Dashboard: Cache Performance

```
Panel 1: Hit Rate (%)
Query: cache_hit_ratio * 100
Thresholds: Warning 50%, Target 70%

Panel 2: Cache Size (MB)
Query: cache_size_bytes / 1024 / 1024

Panel 3: Redis Commands/sec
Query: rate(redis_commands_total[1m])
Legend: {{ command }}

Panel 4: Cache Evictions
Query: rate(cache_evictions_total[1m])
```

---

## Logging Configuration

### Winston Logger Setup

```typescript
// Already configured in src/apps/api/src/middleware/logger.ts

import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
  ),
  transports: [
    // Console
    new winston.transports.Console({
      format: winston.format.simple(),
    }),
    // Error log
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
    }),
    // Combined log
    new winston.transports.File({
      filename: 'logs/combined.log',
    }),
  ],
});
```

### Log Levels to Monitor

```
ERROR:   Application errors, exceptions
WARN:    Degraded functionality, rate limits, slow queries
INFO:    Business events (shipments, payments, users)
DEBUG:   Diagnostic info (only development)
```

### Log Aggregation (Optional)

```bash
# Install ELK Stack for log aggregation
docker run -d --name elasticsearch docker.elastic.co/elasticsearch/elasticsearch:7.17.0

# Install Logstash
# Configure to forward logs from:
# - API logs (/var/log/freight-api/*.log)
# - System logs (/var/log/syslog)

# Query logs in Kibana
# http://localhost:5601
```

---

## Alert Routing & Notifications

### Slack Integration

```typescript
// In your alert handler
import axios from 'axios';

async function notifySlack(alert: {
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
}) {
  const color = {
    critical: '#ff0000',
    warning: '#ffaa00',
    info: '#0099ff',
  }[alert.severity];

  await axios.post(process.env.SLACK_WEBHOOK_URL, {
    attachments: [{
      color,
      title: alert.title,
      text: alert.description,
      ts: Math.floor(Date.now() / 1000),
    }],
  });
}
```

### Email Alerts (Optional)

```bash
# Configure Prometheus AlertManager
# Install: https://prometheus.io/download/#alertmanager

# alertmanager.yml
global:
  resolve_timeout: 5m

route:
  receiver: 'email-critical'
  group_by: ['alertname']
  routes:
    - match:
        severity: critical
      receiver: 'email-critical'
      group_wait: 0s
      group_interval: 1m

receivers:
  - name: 'email-critical'
    email_configs:
      - to: 'oncall@yourdomain.com'
        from: 'alerts@yourdomain.com'
        smarthost: 'smtp.gmail.com:587'
        auth_username: 'alerts@yourdomain.com'
        auth_password: '${GMAIL_PASSWORD}'
```

---

## Daily Monitoring Tasks

### Morning Check (8 AM)

```bash
# 1. View overnight summary
# Grafana → Dashboard → System Health
# Check: Error rate, latency, memory usage

# 2. Review error logs
tail -100 logs/error.log

# 3. Check alert status
curl http://localhost:9090/api/v1/alerts

# 4. Team notification
# Post summary to #status channel if anything abnormal
```

### Hourly Check (During business hours)

```bash
# 1. Monitor key metrics
watch -n 10 'curl -s http://localhost:4000/api/metrics/performance | jq'

# 2. Watch for alerts
# Refresh http://localhost:9090 alert page

# 3. Monitor error rate
# If > 1%: Investigate logs immediately
```

### Weekly Review (Friday)

```bash
# 1. Export metrics for analysis
# Grafana → Dashboard → Export CSV

# 2. Generate performance report
# Prometheus: rate(http_requests_total[1w])

# 3. Identify optimization opportunities
# Review slow queries
# Review high-latency endpoints

# 4. Team retrospective
# What went well?
# What could improve?
# Action items for next week
```

---

## Performance Baselines

### Target Metrics

```
Metric                  | Target      | Warning     | Critical
─────────────────────────────────────────────────────────────
API P50 Latency         | < 100ms     | > 200ms     | > 500ms
API P95 Latency         | < 500ms     | > 800ms     | > 1000ms
API P99 Latency         | < 1000ms    | > 1500ms    | > 2000ms
Error Rate              | < 0.5%      | > 1%        | > 2%
Cache Hit Rate          | > 70%       | < 60%       | < 40%
WebSocket Connections   | Variable    | ↓ 20% drop  | ↓ 50% drop
Memory Usage            | < 50%       | > 75%       | > 85%
CPU Usage               | < 60%       | > 75%       | > 85%
Database Connections    | < 50%       | > 75%       | > 90%
Disk Usage              | < 70%       | > 85%       | > 95%
```

### Establish Baselines

```bash
# Run for 1 hour under normal traffic
# Record metrics

# Week 1:
# - Min, Max, Mean, P95, P99 for each metric
# - Use as baseline for future comparison

# Ongoing:
# - Weekly comparison to baseline
# - Alert if deviation > 20%
```

---

## Troubleshooting Common Issues

### High API Latency

1. **Check database**
   ```bash
   # Slow queries
   psql -c "SELECT query, mean_exec_time FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"
   ```

2. **Check cache**
   ```bash
   redis-cli info stats
   # Look for: hit_ratio (should be > 0.7)
   ```

3. **Check system resources**
   ```bash
   # CPU
   top -bn1 | grep "Cpu(s)" | awk '{print $2}'
   
   # Memory
   free -m | grep Mem | awk '{print "Used:", $3, "MB, Free:", $4, "MB"}'
   ```

4. **Check active connections**
   ```bash
   # API
   curl http://localhost:4000/api/metrics/performance | jq .in_flight_requests
   ```

### High Error Rate

1. **View error logs**
   ```bash
   tail -f logs/error.log | grep "ERROR"
   ```

2. **Check Sentry**
   ```
   Visit: https://sentry.yourdomain.com
   Filter: Last 1 hour
   Group by: Error type
   ```

3. **Check specific endpoint**
   ```bash
   curl -X GET https://api.yourdomain.com/api/shipments \
        -H "Authorization: Bearer $TOKEN" \
        -v
   ```

### WebSocket Disconnections

1. **Check Redis connection**
   ```bash
   redis-cli PING  # Should return PONG
   redis-cli INFO
   ```

2. **Check Socket.IO metrics**
   ```bash
   curl http://localhost:4000/api/metrics/websocket
   ```

3. **Check network**
   ```bash
   # From client
   # Open DevTools → Network → WS
   # Look for successful connection
   ```

---

## Backup & Disaster Recovery

### Backup Metrics (Prometheus)

```bash
# Prometheus stores metrics in /prometheus/
# Backup daily
tar -czf prometheus-backup-$(date +%Y%m%d).tar.gz /prometheus/

# Upload to S3
aws s3 cp prometheus-backup-*.tar.gz s3://backups/prometheus/
```

### Restore Metrics

```bash
# 1. Stop Prometheus
docker-compose stop prometheus

# 2. Restore data
tar -xzf prometheus-backup-YYYYMMDD.tar.gz

# 3. Start Prometheus
docker-compose start prometheus
```

---

## Success Indicators

✅ **Monitoring is working if**:
- Grafana dashboards display real-time data
- Metrics update every 15 seconds
- Alerts trigger on thresholds
- Logs are collected and searchable
- No gaps in data collection

---

**Next**: Deploy monitoring stack and configure dashboards
