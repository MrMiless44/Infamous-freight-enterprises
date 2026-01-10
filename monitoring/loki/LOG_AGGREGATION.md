# Log Aggregation Configuration

# Loki + Promtail for centralized logging

## Docker Compose Configuration

```yaml
# Add to docker-compose.yml

services:
  loki:
    image: grafana/loki:2.8.0
    container_name: loki
    ports:
      - "3100:3100"
    volumes:
      - ./monitoring/loki/loki-config.yml:/etc/loki/local-config.yml
      - loki-data:/loki
    command: -config.file=/etc/loki/local-config.yml
    networks:
      - monitoring
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3100/ready"]
      interval: 10s
      timeout: 5s
      retries: 5

  promtail:
    image: grafana/promtail:2.8.0
    container_name: promtail
    volumes:
      - ./monitoring/promtail/promtail-config.yml:/etc/promtail/config.yml
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock
      - /var/log:/var/log:ro
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
    command: -config.file=/etc/promtail/config.yml
    networks:
      - monitoring
    depends_on:
      - loki

networks:
  monitoring:
    driver: bridge

volumes:
  loki-data:
```

## Loki Configuration

```yaml
# monitoring/loki/loki-config.yml

auth_enabled: false

ingester:
  chunk_idle_period: 3m
  chunk_retain_period: 1m
  max_chunk_age: 1h
  max_streams_matchers_cache_size: 10
  chunk_encoding: snappy

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h
  ingestion_rate_mb: 50
  ingestion_burst_size_mb: 100
  per_stream_rate_limit: 50MB
  per_stream_rate_limit_burst: 100MB

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

server:
  http_listen_port: 3100
  log_level: info

storage_config:
  boltdb_shipper:
    active_index_directory: /loki/boltdb-shipper-active
    cache_location: /loki/boltdb-shipper-cache
    shared_store: filesystem
  filesystem:
    directory: /loki/chunks

retention_config:
  enabled: true
  default_retention: 7d
  retention_deletes_enabled: true
  retention_schedule_enabled: true
```

## Promtail Configuration

```yaml
# monitoring/promtail/promtail-config.yml

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  # API logs
  - job_name: api
    static_configs:
      - targets:
          - localhost
        labels:
          job: api
          service: infamous-freight-api
          __path__: /var/log/api/*.log

    # Parse JSON logs
    pipeline_stages:
      - json:
          expressions:
            level: level
            msg: message
            timestamp: timestamp
            service: service
      - labels:
          level:
          service:

  # Web server logs
  - job_name: web
    static_configs:
      - targets:
          - localhost
        labels:
          job: web
          service: infamous-freight-web
          __path__: /var/log/web/*.log

    pipeline_stages:
      - json:
          expressions:
            level: level
            msg: message
            timestamp: timestamp
      - labels:
          level:

  # Docker logs
  - job_name: docker
    docker: {}
    relabel_configs:
      - source_labels: ["__meta_docker_container_name"]
        regex: '(.*)\..*'
        target_label: "container_name"
      - source_labels: ["__meta_docker_container_log_stream"]
        target_label: "stream"

  # System logs
  - job_name: syslog
    static_configs:
      - targets:
          - localhost
        labels:
          job: syslog
          __path__: /var/log/syslog

  # PostgreSQL logs
  - job_name: postgres
    static_configs:
      - targets:
          - localhost
        labels:
          job: postgres
          __path__: /var/log/postgresql/*.log

  # Redis logs
  - job_name: redis
    static_configs:
      - targets:
          - localhost
        labels:
          job: redis
          __path__: /var/log/redis/*.log
```

## Querying Logs

### Loki Query Language (LogQL)

```logql
# All logs from API service
{job="api"}

# Error logs only
{job="api"} |= "ERROR"

# Filter by level and service
{level="error", service="api"}

# JSON field matching
{job="api"} | json | status >= 500

# Regex pattern matching
{job="api"} |~ "auth.*failed"

# Count errors in last hour
count_over_time({job="api"} | json | status >= 500 [1h])

# Search shipment-related logs
{service="api"} |~ "shipment|driver" | json | timestamp > "2026-01-10"
```

## Integration with Grafana

### Add Loki as Data Source

1. Navigate to Grafana: http://localhost:3000
2. Settings → Data Sources → Add Data Source
3. Select Loki
4. URL: http://loki:3100
5. Click Save & Test

### Create Log Dashboard

Create a new dashboard and add Loki panels:

```json
{
  "targets": [
    {
      "refId": "A",
      "expr": "{job=\"api\", level=\"error\"}"
    }
  ]
}
```

## Log Retention & Cleanup

### Automatic Cleanup (Docker)

```bash
# Remove logs older than 7 days
docker exec loki /loki-delete-http \
  -loki.url=http://localhost:3100 \
  -older-than=168h
```

### Manual Cleanup

```bash
# Remove specific job logs
curl -X DELETE http://localhost:3100/loki/api/v1/delete \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'query={job="old-service"}'
```

## Monitoring Loki Health

### Loki Metrics

```promql
# Loki API request rate
rate(loki_request_duration_seconds_bucket[5m])

# Loki distributor ingestion rate
rate(loki_distributor_lines_received_total[5m])

# Loki ingester disk usage
disk_used_bytes{service="loki"}
```

### Add to Prometheus

```yaml
# monitoring/prometheus/prometheus.yml
scrape_configs:
  - job_name: "loki"
    static_configs:
      - targets: ["loki:3100"]
```

## Performance Optimization

### Tune Loki for High Volume

```yaml
# monitoring/loki/loki-config.yml
ingester:
  # Increase chunk size for higher throughput
  chunk_idle_period: 5m
  max_chunk_age: 2h
  chunk_target_size: 1572864 # 1.5MB

limits_config:
  # Increase ingestion rates
  ingestion_rate_mb: 100
  ingestion_burst_size_mb: 200
  per_stream_rate_limit: 100MB
```

### Index optimization

```yaml
schema_config:
  configs:
    - from: 2020-10-24
      index:
        # Smaller period = faster queries, more storage
        period: 12h
```

## Troubleshooting

### Loki won't start

```bash
# Check logs
docker logs loki

# Verify permissions
ls -la /loki /loki/chunks

# Check disk space
df -h /loki
```

### High query latency

```bash
# Check query metrics in Prometheus
rate(loki_request_duration_seconds_bucket[5m])

# Increase cache
ingester:
  max_cache_period_items: 5000
```

### Log ingestion errors

```bash
# Check Promtail logs
docker logs promtail

# Verify Loki connectivity
curl http://loki:3100/ready
```

---

**Last Updated:** 2026-01-10  
**Documentation:** [Loki Docs](https://grafana.com/docs/loki/)
