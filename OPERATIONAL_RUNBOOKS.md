# Operational Runbooks

## 1. Scaling WebSocket Connections

### When to Scale

- Concurrent connections exceed 5,000
- WebSocket latency exceeds 200ms
- CPU usage on API server exceeds 80%

### How to Scale

#### Option A: Vertical Scaling (Single Server)

```bash
# Increase Node.js file descriptor limits
ulimit -n 100000

# Increase system socket limits
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Restart API service
docker restart infamous-freight-api
```

#### Option B: Horizontal Scaling (Multiple Servers)

1. Add Redis for pub/sub:

```typescript
// In server.ts
const io = require("socket.io")(httpServer, {
  adapter: require("socket.io-redis")({
    host: "redis-server",
    port: 6379,
  }),
});
```

2. Deploy API instances behind load balancer (Nginx)
3. Configure sticky sessions for WebSocket connections
4. Monitor connection distribution with `/api/metrics/websocket`

### Monitoring

```bash
# Check WebSocket connections
curl http://api-server:4000/api/metrics/websocket

# Check metrics
curl http://api-server:4000/api/metrics | grep websocket
```

---

## 2. Cache Invalidation Strategies

### Manual Cache Invalidation

```typescript
// Clear specific key
await CacheService.del("shipment:SHIP-001");

// Clear entire cache
await CacheService.clear();
```

### Automatic Cache Invalidation (On Data Change)

```typescript
// In route handler after update
const shipment = await updateShipment(id, data);
await CacheService.del(`shipment:${id}`);
WebSocketService.emitShipmentUpdate(shipment);
```

### Cache Warm-up on Startup

```typescript
// In server initialization
async function warmupCache() {
  const shipments = await prisma.shipment.findMany({
    where: { status: "in_transit" },
  });

  for (const shipment of shipments) {
    await CacheService.set(
      `shipment:${shipment.id}`,
      shipment,
      3600, // 1 hour TTL
    );
  }
}
```

### Monitoring Cache Performance

```bash
# View cache hit rate
curl http://api-server:4000/api/metrics/cache

# Expected: Hit rate > 70% for healthy cache
```

---

## 3. Rate Limit Adjustment

### Current Limits

```bash
RATE_LIMIT_GENERAL_MAX=100      # 100 per 15 minutes
RATE_LIMIT_AI_MAX=20             # 20 per 1 minute
RATE_LIMIT_BILLING_MAX=30        # 30 per 15 minutes
```

### Adjusting Limits

1. **Identify problematic endpoints:**

```bash
curl http://api-server:4000/api/metrics/ratelimit | jq '.limiters'
```

2. **Update environment variables:**

```bash
# .env or docker-compose override
RATE_LIMIT_GENERAL_MAX=150
RATE_LIMIT_AI_MAX=30
```

3. **Apply without downtime:**

```bash
docker-compose up -d  # Restarts only API service
```

### Whitelisting High-Volume Services

```typescript
// In userRateLimit.ts
const WHITELIST = ["internal-analytics-service", "batch-processor"];

if (WHITELIST.includes(req.user.sub)) {
  return next(); // Skip rate limiting
}
```

---

## 4. Debugging Slow Queries

### Enable Query Logging

```typescript
// In prisma client setup
const prisma = new PrismaClient({
  log: [
    { level: "query", emit: "event" },
    { level: "warn", emit: "stdout" },
  ],
});

prisma.$on("query", (e) => {
  console.log("Query:", e.query);
  console.log("Duration:", e.duration + "ms");
});
```

### Find Slow Queries

```bash
# View slow queries (>1s)
curl http://api-server:4000/api/metrics/performance | jq '.slowQueries'
```

### Optimize Query

```typescript
// Before: N+1 query problem
const shipments = await prisma.shipment.findMany();
for (const s of shipments) {
  s.driver = await prisma.driver.findUnique({ where: { id: s.driverId } });
}

// After: Use include
const shipments = await prisma.shipment.findMany({
  include: { driver: true },
});

// Cache the result
await CacheService.set("shipments-with-drivers", shipments, 3600);
```

### Add Database Indexes

```sql
-- Connect to PostgreSQL
psql -U postgres -d infamous_freight

-- Create indexes for common queries
CREATE INDEX idx_shipment_status ON shipment(status);
CREATE INDEX idx_shipment_driver_id ON shipment(driver_id);
CREATE INDEX idx_shipment_created_at ON shipment(created_at DESC);
```

---

## 5. Troubleshooting WebSocket Issues

### Check Connection

```bash
# View active connections
curl http://api-server:4000/api/metrics/websocket

# View connection logs
docker logs infamous-freight-api | grep WebSocket
```

### Common Issues

#### Issue: Connections drop frequently

**Solution: Check token expiry**

```typescript
// Ensure tokens are refreshed before expiry
const tokenExpiry = jwt.decode(token).exp * 1000;
if (Date.now() > tokenExpiry - 60000) {
  // Refresh token if within 1 minute of expiry
  const newToken = await refreshToken(token);
}
```

#### Issue: Clients can't connect

**Solution: Check CORS and auth**

```bash
# Verify CORS settings
echo $WS_CORS_ORIGINS

# Check auth token in request
curl -H "Authorization: Bearer $TOKEN" http://api-server:4000/api/health
```

#### Issue: Messages not being received

**Solution: Verify room subscription**

```typescript
// Ensure client is subscribed to correct room
socket.emit("join:room", { shipmentId: "SHIP-001" });
socket.on("shipment:update", (data) => console.log(data));
```

---

## 6. Export Service Troubleshooting

### Issue: Export fails with large datasets

**Solution: Implement streaming**

```typescript
// Use streaming for large exports
const stream = fs.createWriteStream("export.csv");
const csvStream = json2csv.transform();

csvStream.pipe(stream);
shipments.forEach((s) => csvStream.write(s));
csvStream.end();
```

### Issue: PDF generation too slow

**Solution: Cache generated PDFs**

```typescript
// Cache PDF for repeated requests
const cacheKey = `export-pdf:${filters.hash()}`;
const cached = await CacheService.get(cacheKey);
if (cached) return cached;

const pdf = await generatePDF(shipments);
await CacheService.set(cacheKey, pdf, 3600);
```

### Monitoring Exports

```bash
# View export statistics
curl http://api-server:4000/api/metrics/exports

# Check export audit log
curl http://api-server:4000/api/audit-log?action=export
```

---

## 7. Health Check Monitoring

### Setup Prometheus Scraping

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "infamous-freight-api"
    static_configs:
      - targets: ["localhost:4000"]
    metrics_path: "/api/metrics"
```

### Setup Alerting Rules

```yaml
# alerting.yml
groups:
  - name: freight_api
    rules:
      - alert: HighMemoryUsage
        expr: process_heap_used_bytes / process_heap_total_bytes > 0.9
        for: 5m
        annotations:
          summary: "API memory usage critical"

      - alert: DatabaseDown
        expr: database_connected == 0
        for: 1m
        annotations:
          summary: "Database connection failed"

      - alert: HighLatency
        expr: request_duration_ms > 500
        for: 5m
        annotations:
          summary: "API latency exceeds 500ms"
```

### Manual Health Checks

```bash
# Basic health
curl http://api-server:4000/api/health

# Detailed health
curl http://api-server:4000/api/health/detailed | jq

# Readiness (Kubernetes)
curl http://api-server:4000/api/health/ready

# Liveness (Kubernetes)
curl http://api-server:4000/api/health/live

# Metrics health
curl http://api-server:4000/api/metrics/health | jq
```

---

## 8. Incident Response

### Service Down Checklist

1. [ ] Check server status: `docker ps`
2. [ ] Check logs: `docker logs infamous-freight-api`
3. [ ] Check health: `curl http://api-server:4000/api/health`
4. [ ] Check database: `psql -c "SELECT 1"`
5. [ ] Restart if needed: `docker restart infamous-freight-api`
6. [ ] Verify recovery: Wait 30s, check health again

### Memory Leak Investigation

1. [ ] Monitor memory over time: `docker stats`
2. [ ] Check for stuck connections: `/api/metrics/websocket`
3. [ ] Review logs for errors
4. [ ] Restart service if memory >90%
5. [ ] Update logging to identify source

### High Latency Investigation

1. [ ] Check database performance: `EXPLAIN ANALYZE [query]`
2. [ ] Check cache hit rate: `/api/metrics/cache`
3. [ ] Check WebSocket metrics: `/api/metrics/websocket`
4. [ ] Check rate limiting: `/api/metrics/ratelimit`
5. [ ] Optimize slow queries

---

## 9. Deployment Checklist

Before deploying:

- [ ] All tests passing: `pnpm test`
- [ ] No security vulnerabilities: `pnpm audit`
- [ ] Staging deployment successful
- [ ] Health checks passing: `/api/health/detailed`
- [ ] Load tested: `locust -f locustfile.py`

After deploying:

- [ ] Monitor metrics: `/api/metrics`
- [ ] Check error rate: < 1%
- [ ] Check latency: < 200ms p95
- [ ] Monitor WebSocket connections
- [ ] Monitor cache hit rate: > 70%

---

## 10. Performance Baselines

### Expected Metrics

```
API Response Time:        < 200ms (p95)
WebSocket Latency:        < 100ms
Cache Hit Rate:           > 70%
Database Query Time:      < 100ms
Memory Usage:             < 512MB
CPU Usage:                < 70%
WebSocket Connections:    < 5000
```

### SLO Targets

```
Availability:             99.5%
Error Rate:               < 1%
Latency (p95):            < 200ms
Cache Hit Rate:           > 70%
```

---

## Quick Command Reference

```bash
# Health Checks
curl http://api-server:4000/api/health/detailed

# Metrics
curl http://api-server:4000/api/metrics

# Performance
curl http://api-server:4000/api/metrics/performance | jq

# WebSocket Stats
curl http://api-server:4000/api/metrics/websocket | jq

# Cache Stats
curl http://api-server:4000/api/metrics/cache | jq

# Rate Limits
curl http://api-server:4000/api/metrics/ratelimit | jq

# Service Status
docker ps | grep infamous-freight-api
docker logs -f infamous-freight-api

# Database
docker exec infamous-freight-db psql -U postgres -c "SELECT 1"
```

---

**Last Updated**: December 30, 2024
**Version**: 1.0
