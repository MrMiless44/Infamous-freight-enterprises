# Performance Optimization Configuration

## 🚀 Next.js Web App Optimization

### next.config.mjs Enhancements

```javascript
// web/next.config.mjs additions
const config = {
  // ... existing config

  // Image optimization
  images: {
    domains: ["infamous-freight-cdn.com", "res.cloudinary.com"],
    formats: ["image/avif", "image/webp"],
    minimumCacheTTL: 60,
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
  },

  // Compression
  compress: true,

  // Production source maps (disable for faster builds)
  productionBrowserSourceMaps: false,

  // SWC minification (faster than Terser)
  swcMinify: true,

  // Experimental features for performance
  experimental: {
    optimizeCss: true,
    optimizePackageImports: ["@mui/material", "lucide-react"],
    scrollRestoration: true,
  },

  // Webpack optimizations
  webpack: (config, { dev, isServer }) => {
    if (!dev && !isServer) {
      config.optimization = {
        ...config.optimization,
        splitChunks: {
          chunks: "all",
          cacheGroups: {
            default: false,
            vendors: false,
            // Vendor chunk for node_modules
            vendor: {
              name: "vendor",
              chunks: "all",
              test: /node_modules/,
              priority: 20,
            },
            // Common chunk for shared code
            common: {
              name: "common",
              minChunks: 2,
              chunks: "all",
              priority: 10,
              reuseExistingChunk: true,
              enforce: true,
            },
          },
        },
      };
    }
    return config;
  },

  // Headers for caching
  async headers() {
    return [
      {
        source: "/static/:path*",
        headers: [
          {
            key: "Cache-Control",
            value: "public, max-age=31536000, immutable",
          },
        ],
      },
      {
        source: "/api/:path*",
        headers: [
          {
            key: "Cache-Control",
            value: "public, s-maxage=60, stale-while-revalidate=30",
          },
        ],
      },
    ];
  },
};
```

### Performance Budgets

```json
// web/lighthouse-budget.json
{
  "budgets": [
    {
      "resourceSizes": [
        {
          "resourceType": "script",
          "budget": 300
        },
        {
          "resourceType": "total",
          "budget": 500
        },
        {
          "resourceType": "document",
          "budget": 50
        },
        {
          "resourceType": "stylesheet",
          "budget": 50
        },
        {
          "resourceType": "font",
          "budget": 100
        },
        {
          "resourceType": "image",
          "budget": 200
        }
      ],
      "timings": [
        {
          "metric": "first-contentful-paint",
          "budget": 1500
        },
        {
          "metric": "largest-contentful-paint",
          "budget": 2500
        },
        {
          "metric": "cumulative-layout-shift",
          "budget": 0.1
        },
        {
          "metric": "time-to-interactive",
          "budget": 3000
        },
        {
          "metric": "total-blocking-time",
          "budget": 300
        }
      ]
    }
  ]
}
```

## ⚡ API Performance Optimization

### Express.js Middleware Optimizations

```javascript
// api/src/middleware/performance.js
const compression = require("compression");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const RedisStore = require("rate-limit-redis");
const Redis = require("ioredis");

// Redis client for caching
const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379");

// Compression middleware
const compressionMiddleware = compression({
  level: 6, // Balance between speed and compression ratio
  threshold: 1024, // Only compress responses > 1KB
  filter: (req, res) => {
    if (req.headers["x-no-compression"]) {
      return false;
    }
    return compression.filter(req, res);
  },
});

// Response caching middleware
const cacheMiddleware = (duration) => {
  return async (req, res, next) => {
    if (req.method !== "GET") {
      return next();
    }

    const key = `cache:${req.originalUrl}`;

    try {
      const cached = await redis.get(key);
      if (cached) {
        res.set("X-Cache", "HIT");
        return res.json(JSON.parse(cached));
      }

      // Store original json method
      const originalJson = res.json.bind(res);

      // Override json method to cache response
      res.json = (body) => {
        redis.setex(key, duration, JSON.stringify(body));
        res.set("X-Cache", "MISS");
        return originalJson(body);
      };

      next();
    } catch (error) {
      console.error("[Cache Error]", error);
      next();
    }
  };
};

// Database query optimization hints
const dbOptimizationHints = {
  // Use indexes
  useIndexes: true,

  // Limit result sets
  defaultLimit: 100,
  maxLimit: 1000,

  // Use select fields to reduce payload
  selectFields: true,

  // Connection pooling
  pool: {
    min: 2,
    max: 10,
    acquireTimeoutMillis: 30000,
    idleTimeoutMillis: 30000,
  },
};

module.exports = {
  compressionMiddleware,
  cacheMiddleware,
  redis,
  dbOptimizationHints,
};
```

### Database Query Optimization

```javascript
// api/src/services/optimizedQueries.js

// Bad: N+1 query
// const shipments = await prisma.shipment.findMany();
// for (const shipment of shipments) {
//   shipment.driver = await prisma.driver.findUnique({ where: { id: shipment.driverId }});
// }

// Good: Use include/select
const shipments = await prisma.shipment.findMany({
  include: {
    driver: {
      select: {
        id: true,
        name: true,
        phone: true,
        // Exclude sensitive fields
      },
    },
    customer: {
      select: {
        id: true,
        name: true,
        email: true,
      },
    },
  },
  where: {
    status: {
      in: ["pending", "in-transit"],
    },
  },
  orderBy: {
    createdAt: "desc",
  },
  take: 50, // Pagination
  skip: 0,
});

// Use raw queries for complex aggregations
const stats = await prisma.$queryRaw`
  SELECT 
    status,
    COUNT(*) as count,
    AVG(EXTRACT(EPOCH FROM (delivered_at - created_at))) as avg_duration
  FROM "Shipment"
  WHERE created_at > NOW() - INTERVAL '30 days'
  GROUP BY status
`;
```

## 📊 Monitoring & Metrics

### Prometheus Metrics Endpoints

```javascript
// api/src/routes/metrics.js
const express = require("express");
const router = express.Router();
const promClient = require("prom-client");

// Create a Registry
const register = new promClient.Registry();

// Add default metrics
promClient.collectDefaultMetrics({ register });

// Custom metrics
const httpRequestDuration = new promClient.Histogram({
  name: "http_request_duration_seconds",
  help: "Duration of HTTP requests in seconds",
  labelNames: ["method", "route", "status"],
  buckets: [0.1, 0.5, 1, 2, 5],
  registers: [register],
});

const dbQueryDuration = new promClient.Histogram({
  name: "db_query_duration_seconds",
  help: "Duration of database queries in seconds",
  labelNames: ["operation", "table"],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2],
  registers: [register],
});

const aiDecisionConfidence = new promClient.Gauge({
  name: "ai_decision_confidence",
  help: "AI decision confidence score",
  labelNames: ["role", "action"],
  registers: [register],
});

// Metrics endpoint
router.get("/metrics", async (req, res) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

module.exports = {
  router,
  httpRequestDuration,
  dbQueryDuration,
  aiDecisionConfidence,
};
```

## 🔧 Load Testing Configuration

### Artillery Load Test Scenarios

```yaml
# load-tests/api-load-test.yml
config:
  target: "https://api.infamous-freight.com"
  phases:
    # Warm-up phase
    - duration: 60
      arrivalRate: 5
      name: "Warm up"
    # Ramp up
    - duration: 120
      arrivalRate: 5
      rampTo: 50
      name: "Ramp up load"
    # Sustained load
    - duration: 300
      arrivalRate: 50
      name: "Sustained load"
    # Spike test
    - duration: 60
      arrivalRate: 100
      name: "Spike"
  processor: "./load-test-processor.js"

scenarios:
  - name: "Health check"
    weight: 10
    flow:
      - get:
          url: "/api/health"
          expect:
            - statusCode: 200

  - name: "List shipments"
    weight: 30
    flow:
      - get:
          url: "/api/shipments"
          headers:
            Authorization: "Bearer {{ $processEnvironment.TEST_TOKEN }}"
          expect:
            - statusCode: 200
            - contentType: json

  - name: "Create shipment"
    weight: 20
    flow:
      - post:
          url: "/api/shipments"
          headers:
            Authorization: "Bearer {{ $processEnvironment.TEST_TOKEN }}"
          json:
            origin: "New York, NY"
            destination: "Los Angeles, CA"
            weight: 15000
          capture:
            - json: "$.data.id"
              as: "shipmentId"
          expect:
            - statusCode: 201

  - name: "AI route optimization"
    weight: 15
    flow:
      - post:
          url: "/api/ai/optimize-route"
          headers:
            Authorization: "Bearer {{ $processEnvironment.TEST_TOKEN }}"
          json:
            origin: { lat: 40.7128, lng: -74.006 }
            destination: { lat: 34.0522, lng: -118.2437 }
          expect:
            - statusCode: 200
            - hasProperty: "data.optimizedRoute"
```

### Performance Targets

```javascript
// Target SLOs (Service Level Objectives)
const performanceTargets = {
  // API Response Times
  api: {
    p50: 100, // 50th percentile < 100ms
    p95: 250, // 95th percentile < 250ms
    p99: 500, // 99th percentile < 500ms
  },

  // Database Query Times
  database: {
    p50: 10, // < 10ms
    p95: 50, // < 50ms
    p99: 100, // < 100ms
  },

  // Web Vitals
  web: {
    FCP: 1.5, // First Contentful Paint < 1.5s
    LCP: 2.5, // Largest Contentful Paint < 2.5s
    FID: 100, // First Input Delay < 100ms
    CLS: 0.1, // Cumulative Layout Shift < 0.1
    TTI: 3.0, // Time to Interactive < 3s
    TBT: 200, // Total Blocking Time < 200ms
  },

  // Uptime
  uptime: 99.9, // 99.9% uptime (< 43 min downtime/month)

  // Error Rate
  errorRate: 0.1, // < 0.1% error rate
};

module.exports = performanceTargets;
```

## 🎯 Performance Checklist

### Before Each Release

- [ ] Run Lighthouse CI (all scores > 90)
- [ ] Run load tests (meets SLO targets)
- [ ] Check bundle sizes (< budgets)
- [ ] Verify database query performance (< 50ms p95)
- [ ] Test WebSocket scalability (1000+ concurrent connections)
- [ ] Review error rates (< 0.1%)
- [ ] Check memory leaks (load test for 1+ hour)
- [ ] Verify CDN cache hit rates (> 80%)
- [ ] Test auto-scaling triggers
- [ ] Review APM dashboards (Datadog/New Relic)

### Continuous Monitoring

- Prometheus alerts for SLO violations
- Sentry for error tracking
- Datadog RUM for real user monitoring
- Grafana dashboards for system metrics
- PagerDuty for critical alerts

---

**Performance is a feature. These configs ensure Infæmous Freight stays fast at scale.**
