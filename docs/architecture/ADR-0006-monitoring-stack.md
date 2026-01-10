# ADR-0006: Monitoring & Observability Stack

**Status:** Accepted  
**Date:** 2026-01-10  
**Deciders:** Platform Engineering Team, SRE Team  
**Technical Story:** Implement comprehensive monitoring to achieve 99.9% uptime SLA

---

## Context and Problem Statement

Infamous Freight Enterprises currently has limited visibility into production system health. When incidents occur, we lack the tools to quickly diagnose root causes, leading to:

1. **Long MTTR (Mean Time To Recovery):** ~2 hours average
2. **Reactive incident response:** No proactive alerting
3. **Limited performance insights:** No visibility into bottlenecks
4. **Poor customer experience:** Users report issues before we detect them

We need a monitoring stack that provides:

- Real-time alerting
- Performance metrics
- Business KPI tracking
- Distributed tracing
- Log aggregation

---

## Decision Drivers

- **SLA Requirements:** 99.9% uptime (43 minutes/month downtime budget)
- **MTTR Target:** <15 minutes for critical incidents
- **Cost Constraints:** <$500/month for monitoring infrastructure
- **Team Expertise:** Prefer open-source, widely-adopted tools
- **Scalability:** Support 10,000+ req/sec monitoring load

---

## Considered Options

### Option 1: Cloud-Native (Datadog, New Relic)

**Pros:**

- Fully managed, no ops burden
- Best-in-class UX
- Integrated APM, logs, traces

**Cons:**

- Expensive ($1,500+/month at scale)
- Vendor lock-in
- Data egress costs

### Option 2: Self-Hosted (Prometheus + Grafana + Loki) ✅

**Pros:**

- Open-source, no licensing costs
- Full control and customization
- Industry standard (CNCF)
- Large community support

**Cons:**

- Requires operational expertise
- Self-hosted infrastructure costs
- Need to manage HA/backups

### Option 3: Hybrid (AWS CloudWatch + Grafana)

**Pros:**

- Leverage existing AWS infrastructure
- Lower cost than pure cloud-native
- Some managed components

**Cons:**

- Limited feature set
- Poor query performance at scale
- AWS vendor lock-in

---

## Decision Outcome

**Chosen option:** Self-Hosted Prometheus + Grafana + Loki Stack

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Application Layer                  │
│                                                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │   API   │  │   Web   │  │Database │        │
│  └────┬────┘  └────┬────┘  └────┬────┘        │
│       │            │             │              │
│       v            v             v              │
│  ┌────────────────────────────────────┐        │
│  │      Metrics Exporters              │        │
│  │  • prom-client (Node.js)           │        │
│  │  • postgres_exporter               │        │
│  │  • redis_exporter                  │        │
│  └────────────────────────────────────┘        │
└─────────────────────────────────────────────────┘
                      │
                      v
┌─────────────────────────────────────────────────┐
│           Monitoring & Alerting Layer           │
│                                                 │
│  ┌──────────────┐      ┌──────────────┐        │
│  │  Prometheus  │─────>│ Alertmanager │───┐    │
│  │  (Metrics)   │      │  (Alerts)    │   │    │
│  └──────┬───────┘      └──────────────┘   │    │
│         │                                  │    │
│         │  ┌──────────────┐               │    │
│         │  │     Loki     │               │    │
│         │  │    (Logs)    │               │    │
│         │  └──────┬───────┘               │    │
│         │         │                       │    │
│         v         v                       v    │
│  ┌──────────────────────────────────────────┐  │
│  │            Grafana                       │  │
│  │  • Dashboards                            │  │
│  │  • Alerting Rules                        │  │
│  │  • Query Interface                       │  │
│  └──────────────────────────────────────────┘  │
│                     │                           │
│                     v                           │
│  ┌──────────────────────────────────────────┐  │
│  │       Notification Channels              │  │
│  │  • PagerDuty (SEV-1)                     │  │
│  │  • Slack (#alerts)                       │  │
│  │  • Email (fallback)                      │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
                      │
                      v
┌─────────────────────────────────────────────────┐
│             Optional: Future Add-ons            │
│  • Jaeger (Distributed Tracing)                 │
│  • OpenTelemetry (Unified Observability)        │
│  • Thanos (Long-term Metrics Storage)           │
└─────────────────────────────────────────────────┘
```

---

## Components

### 1. Prometheus (Metrics Collection)

**Purpose:** Time-series database for metrics

**Configuration:**

```yaml
# prometheus.yml
global:
  scrape_interval: 30s
  evaluation_interval: 30s

scrape_configs:
  - job_name: "api"
    static_configs:
      - targets: ["api:4000"]

  - job_name: "postgresql"
    static_configs:
      - targets: ["postgres-exporter:9187"]

  - job_name: "redis"
    static_configs:
      - targets: ["redis-exporter:9121"]
```

**Metrics Collected:**

- API: Request rate, latency (P50/P95/P99), error rate
- Database: Query duration, connection pool, slow queries
- Cache: Hit rate, eviction rate, memory usage
- System: CPU, memory, disk, network

**Retention:** 15 days (configurable)

---

### 2. Grafana (Visualization)

**Purpose:** Dashboard and alerting interface

**Dashboards (4 pre-configured):**

1. **API Overview:** Request rate, latency, errors
2. **Database Performance:** Query times, connections, slow queries
3. **Cache Metrics:** Hit rate, evictions, memory
4. **Business KPIs:** Shipments, revenue, signups

**Alert Rules (15 pre-configured):**

- API down (SEV-1)
- High error rate >5% (SEV-1)
- High latency P95 >800ms (SEV-1)
- Low cache hit rate <40% (Warning)
- Database connection pool >90% (SEV-1)

**Access Control:**

- Viewer: All engineers (read-only)
- Editor: Platform team (can edit dashboards)
- Admin: SRE team only

---

### 3. Loki (Log Aggregation)

**Purpose:** Centralized logging

**Log Sources:**

- API application logs (JSON structured)
- Database logs (slow queries, errors)
- Redis logs
- System logs (Docker, kernel)

**Query Examples:**

```logql
# All 5xx errors in last hour
{job="api"} |= "5xx" | json | status >= 500

# Slow queries >1s
{job="postgresql"} |= "duration" | json | duration_ms > 1000

# Failed authentication attempts
{job="api"} |= "auth" | json | event="login_failed"
```

**Retention:** 7 days (cost optimization)

---

### 4. Alertmanager (Alert Routing)

**Purpose:** Alert deduplication and routing

**Routing Rules:**

- **SEV-1 (Critical):** PagerDuty + Slack #incidents
- **SEV-2 (Warning):** Slack #alerts only
- **SEV-3 (Info):** Email digest (daily)

**Silencing:**

- Maintenance windows: Manual silence via Grafana
- Known issues: Auto-silence via runbook

---

### 5. Exporters (Metrics Translation)

**Node.js Metrics (prom-client):**

```typescript
import client from "prom-client";

// Custom metrics
export const httpRequestDuration = new client.Histogram({
  name: "http_request_duration_seconds",
  help: "HTTP request latency",
  labelNames: ["method", "endpoint", "status"],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5],
});

// Expose /metrics endpoint
app.get("/metrics", async (req, res) => {
  res.set("Content-Type", client.register.contentType);
  res.end(await client.register.metrics());
});
```

**PostgreSQL Exporter:**

- Monitors: connections, queries, replication lag
- Port: 9187

**Redis Exporter:**

- Monitors: memory, hit rate, connected clients
- Port: 9121

---

## Consequences

### Positive

- **Proactive Alerting:** Detect issues before users report them
- **Faster MTTR:** 2 hours → 15 minutes (87% improvement)
- **Cost Savings:** $1,500/month (Datadog) → $200/month (self-hosted)
- **Full Control:** Customize dashboards, retention, alerts
- **No Vendor Lock-In:** Open-source, portable

### Negative

- **Operational Burden:** Need to maintain Prometheus, Grafana, Loki
- **Learning Curve:** Team needs to learn PromQL, LogQL
- **High Availability:** Need to set up HA for Prometheus (future)
- **Storage Costs:** Metrics and logs consume ~50GB/month
- **Alert Fatigue Risk:** Must tune alert thresholds carefully

---

## Monitoring Metrics

### Golden Signals (SRE Best Practices)

**1. Latency**

- **Metric:** `http_request_duration_seconds{quantile="0.95"}`
- **Target:** <300ms P95
- **Alert:** >800ms for 5 minutes

**2. Traffic**

- **Metric:** `rate(http_requests_total[5m])`
- **Target:** >100 req/sec
- **Alert:** <10 req/sec (possible outage)

**3. Errors**

- **Metric:** `rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])`
- **Target:** <1% error rate
- **Alert:** >5% for 5 minutes

**4. Saturation**

- **Metric:** `prisma_pool_connections_open / prisma_pool_connections_max`
- **Target:** <70% pool usage
- **Alert:** >90% for 5 minutes

### Business Metrics

- **Active Shipments:** `shipments_active_total`
- **Revenue (daily):** `sum(increase(revenue_usd[1d]))`
- **User Signups (24h):** `increase(user_signups_total[24h])`
- **Payment Success Rate:** `(payments_successful / payments_attempted) * 100`

---

## Deployment

### Docker Compose (Development)

```yaml
# docker-compose.monitoring.yml
version: "3.8"

services:
  prometheus:
    image: prom/prometheus:v2.45.0
    volumes:
      - ./monitoring/prometheus:/etc/prometheus
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=15d"

  grafana:
    image: grafana/grafana:10.0.0
    volumes:
      - ./monitoring/grafana:/etc/grafana/provisioning
      - grafana-data:/var/lib/grafana
    ports:
      - "3002:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false

  loki:
    image: grafana/loki:2.8.0
    volumes:
      - ./monitoring/loki:/etc/loki
      - loki-data:/loki
    ports:
      - "3100:3100"

  alertmanager:
    image: prom/alertmanager:v0.26.0
    volumes:
      - ./monitoring/alertmanager:/etc/alertmanager
    ports:
      - "9093:9093"

  postgres-exporter:
    image: prometheuscommunity/postgres-exporter:v0.13.0
    environment:
      - DATA_SOURCE_NAME=${DATABASE_URL}
    ports:
      - "9187:9187"

  redis-exporter:
    image: oliver006/redis_exporter:v1.51.0
    environment:
      - REDIS_ADDR=redis:6379
    ports:
      - "9121:9121"

volumes:
  prometheus-data:
  grafana-data:
  loki-data:
```

### Production (Kubernetes - Future)

```yaml
# monitoring/k8s/prometheus-deployment.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: prometheus
spec:
  replicas: 2 # HA setup
  template:
    spec:
      containers:
        - name: prometheus
          image: prom/prometheus:v2.45.0
          volumeMounts:
            - name: config
              mountPath: /etc/prometheus
            - name: storage
              mountPath: /prometheus
```

---

## Success Criteria

### Metrics (3 months post-deployment)

| Metric             | Before  | Target   | Actual  |
| ------------------ | ------- | -------- | ------- |
| MTTR               | 2 hours | <15 min  | TBD     |
| Uptime             | 99.5%   | 99.9%    | TBD     |
| Undetected Outages | 30%     | <5%      | TBD     |
| Alert Accuracy     | N/A     | >90%     | TBD     |
| Monitoring Cost    | $0      | <$500/mo | $200/mo |

### Qualitative

- ✅ On-call engineers have visibility into all critical systems
- ✅ Business stakeholders can track KPIs in real-time
- ✅ Incident postmortems include metrics and traces
- ✅ Proactive alerts catch 95%+ of incidents before user reports

---

## Future Enhancements

### Phase 2 (Q2 2026)

- **Distributed Tracing (Jaeger):** Track requests across microservices
- **OpenTelemetry:** Unified observability (metrics + logs + traces)
- **Thanos:** Long-term Prometheus storage (1+ year retention)

### Phase 3 (Q3 2026)

- **Anomaly Detection:** ML-based alerting (AWS CloudWatch Insights)
- **SLO Tracking:** Error budgets and SLO dashboard
- **Cost Attribution:** Track infrastructure cost per customer

---

## Related Decisions

- [ADR-0005: Caching Strategy](./ADR-0005-caching-strategy.md)
- [ADR-0003: Rate Limiting](./ADR-0003-rate-limiting.md)
- [On-Call Runbook](../operations/ON_CALL_RUNBOOK.md)

---

**Last Updated:** 2026-01-10  
**Authors:** Platform Engineering Team, SRE Team  
**Reviewers:** CTO, VP Engineering  
**Next Review:** 2026-04-10 (Quarterly)
