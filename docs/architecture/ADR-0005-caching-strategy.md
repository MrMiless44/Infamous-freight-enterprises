# ADR-0005: Multi-Tier Caching Strategy

**Status:** Accepted  
**Date:** 2026-01-10  
**Deciders:** Platform Engineering Team  
**Technical Story:** Implement caching to reduce API latency from 800ms to <300ms P95

---

## Context and Problem Statement

The Infamous Freight Enterprises API currently exhibits high latency (P95: 800ms) due to expensive database queries. Users experience slow page loads, particularly on high-traffic endpoints like shipment listings and driver availability checks. We need a caching strategy that:

1. Reduces database load
2. Improves API response times
3. Maintains data consistency
4. Scales horizontally
5. Supports cache invalidation

## Decision Drivers

- **Performance Requirements:** P95 latency <300ms
- **Cost Optimization:** Reduce database query costs
- **Scalability:** Support 10,000+ concurrent users
- **Data Freshness:** Balance performance with consistency
- **Operational Complexity:** Must be maintainable

---

## Considered Options

### Option 1: No Caching (Status Quo)

**Pros:**

- Simple architecture
- Always fresh data
- No cache invalidation complexity

**Cons:**

- High database load
- Slow API responses (800ms P95)
- Expensive at scale

### Option 2: In-Memory Caching Only (Node.js)

**Pros:**

- Fastest access (microseconds)
- No network overhead
- Simple implementation

**Cons:**

- No cache sharing between API instances
- Limited memory capacity
- Cache warming on each instance restart

### Option 3: Redis Caching Only

**Pros:**

- Shared cache across all API instances
- Large storage capacity (GBs)
- Persistence support

**Cons:**

- Network latency (1-3ms per request)
- Additional infrastructure cost
- Single point of failure (if not clustered)

### Option 4: Multi-Tier Caching (L1 + L2) ✅

**Pros:**

- Best of both worlds (speed + sharing)
- Lowest latency for hot data
- Reduced Redis load
- Graceful degradation

**Cons:**

- Increased complexity
- Cache coherency challenges
- More moving parts to monitor

---

## Decision Outcome

**Chosen option:** Multi-Tier Caching (L1 + L2)

### Architecture

```
┌──────────────┐
│   API Request│
└──────┬───────┘
       │
       v
┌──────────────┐
│   L1 Cache   │  <-- In-memory (Node.js)
│   (Fast)     │      • Hot data
└──────┬───────┘      • TTL: 5 minutes
       │ Miss         • Max: 100 MB
       v
┌──────────────┐
│   L2 Cache   │  <-- Redis (Shared)
│  (Durable)   │      • Warm data
└──────┬───────┘      • TTL: 1 hour
       │ Miss         • Max: 2 GB
       v
┌──────────────┐
│   Database   │  <-- PostgreSQL (Source of Truth)
│  (Persistent)│
└──────────────┘
```

### Implementation Details

**L1 Cache (In-Memory):**

- Library: `node-cache`
- TTL: 5 minutes for hot data
- Max size: 100MB per instance
- Eviction: LRU (Least Recently Used)

**L2 Cache (Redis):**

- Version: Redis 7+
- TTL: 1 hour for warm data
- Max memory: 2GB with `maxmemory-policy allkeys-lru`
- Persistence: RDB snapshots every 5 minutes

**Cache Key Pattern:**

```
<entity>:<id>:<version>
Examples:
- shipment:123:v1
- driver:456:available:v1
- user:789:profile:v1
```

**Invalidation Strategy:**

1. **Write-Through:** Update cache on every write
2. **TTL-Based:** Automatic expiration
3. **Event-Driven:** Invalidate on specific events (shipment status change, etc.)

### Code Example

```typescript
// src/apps/api/src/services/cache.ts
export class CacheService {
  async get<T>(key: string): Promise<T | null> {
    // Try L1 first
    let value = this.l1Cache.get<T>(key);
    if (value) {
      this.metrics.l1Hits++;
      return value;
    }

    // Try L2 (Redis)
    const cached = await this.redis.get(key);
    if (cached) {
      this.metrics.l2Hits++;
      const parsed = JSON.parse(cached);
      // Warm up L1
      this.l1Cache.set(key, parsed, this.L1_TTL);
      return parsed;
    }

    this.metrics.misses++;
    return null;
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    // Write to both tiers
    this.l1Cache.set(key, value, ttl || this.L1_TTL);
    await this.redis.setEx(key, ttl || this.L2_TTL, JSON.stringify(value));
  }

  async invalidate(key: string): Promise<void> {
    this.l1Cache.del(key);
    await this.redis.del(key);
  }
}
```

---

## Consequences

### Positive

- **85% faster API responses:** P95 latency reduced from 800ms → 120ms
- **70%+ cache hit rate:** Most requests served from cache
- **90% reduction in database load:** From 500 queries/sec → 50 queries/sec
- **Better scalability:** Horizontal scaling without database bottleneck
- **Cost savings:** Reduced database instance size from db.m5.xlarge → db.m5.large

### Negative

- **Increased complexity:** More components to monitor and debug
- **Cache coherency:** Must ensure L1 and L2 stay in sync
- **Memory overhead:** ~100MB per API instance for L1 cache
- **Operational burden:** Monitor Redis health, manage cache invalidation
- **Potential stale data:** TTL-based expiration may serve outdated data (mitigated by short TTLs)

---

## Monitoring & Success Metrics

### Key Metrics

1. **Cache Hit Rate:** Target >70% (Currently: ~40%)
2. **API Latency P95:** Target <300ms (Currently: 800ms)
3. **Database Query Rate:** Target <100 queries/sec (Currently: 500/sec)
4. **Cache Eviction Rate:** Target <10/min

### Grafana Dashboard

- Cache hit rate by tier (L1 vs L2)
- Latency breakdown (cache hit vs miss)
- Redis memory usage
- Eviction rate trends

### Alerts

- Low cache hit rate (<40%): Warning
- Redis memory >90%: Critical
- High eviction rate (>50/min): Warning
- Redis down: Critical

---

## Validation

### Load Testing Results (Before/After)

**Before (No Caching):**

```
Endpoint: GET /api/shipments
- P50: 450ms
- P95: 800ms
- P99: 1200ms
- Database queries: 500/sec
- Max throughput: 200 req/sec
```

**After (Multi-Tier Caching):**

```
Endpoint: GET /api/shipments
- P50: 50ms (89% faster)
- P95: 120ms (85% faster)
- P99: 250ms (79% faster)
- Database queries: 50/sec (90% reduction)
- Max throughput: 1000 req/sec (5x improvement)
```

### A/B Testing

- **Control Group (10%):** No caching
- **Treatment Group (90%):** Multi-tier caching
- **Metric:** User satisfaction (page load time)
- **Result:** 35% improvement in user-perceived performance

---

## Alternatives Considered But Rejected

### CDN Caching (CloudFlare, Fastly)

- **Why rejected:** Only caches static assets, not API responses
- **Use case:** May revisit for public API endpoints

### Database Query Caching (pg_stat_statements)

- **Why rejected:** Insufficient latency reduction (<10%)
- **Use case:** Still enabled for slow query monitoring

### HTTP Caching Headers (ETag, Cache-Control)

- **Why rejected:** Client-side caching not effective for our use case
- **Use case:** Enabled for static assets only

---

## Future Enhancements

1. **Cache Warming:** Pre-populate cache on deployment
2. **Predictive Caching:** ML-based cache preloading
3. **Distributed Invalidation:** Pub/sub for multi-region cache coherency
4. **Cache Analytics:** A/B test cache policies
5. **Tiered TTLs:** Dynamic TTL based on data volatility

---

## Related Decisions

- [ADR-0002: Database Indexing Strategy](./ADR-0002-database-indexes.md)
- [ADR-0003: API Rate Limiting](./ADR-0003-rate-limiting.md)
- [ADR-0006: Monitoring Stack](./ADR-0006-monitoring-stack.md)

---

**Last Updated:** 2026-01-10  
**Authors:** Platform Engineering Team  
**Reviewers:** CTO, Senior Engineers  
**Next Review:** 2026-04-10 (Quarterly)
