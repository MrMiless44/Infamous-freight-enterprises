/**
 * Monitoring Dashboards Configuration
 * Prometheus and Grafana setup for infrastructure monitoring
 */

import { Router, Request, Response } from "express";
import client from "prom-client";

const router = Router();

// Create metrics registry
const register = new client.Registry();

// Default metrics (CPU, memory, etc.)
client.collectDefaultMetrics({ register });

// Custom metrics
const httpRequestDuration = new client.Histogram({
  name: "http_request_duration_ms",
  help: "Duration of HTTP requests in ms",
  labelNames: ["method", "route", "status_code"],
  buckets: [0.1, 5, 15, 50, 100, 500, 1000, 2000, 5000],
  registers: [register],
});

const httpRequestsTotal = new client.Counter({
  name: "http_requests_total",
  help: "Total number of HTTP requests",
  labelNames: ["method", "route", "status_code"],
  registers: [register],
});

const databaseQueryDuration = new client.Histogram({
  name: "db_query_duration_ms",
  help: "Duration of database queries in ms",
  labelNames: ["query_type", "table"],
  buckets: [0.1, 5, 15, 50, 100, 500, 1000],
  registers: [register],
});

const cacheHits = new client.Counter({
  name: "cache_hits_total",
  help: "Total number of cache hits",
  labelNames: ["cache_key"],
  registers: [register],
});

const cacheMisses = new client.Counter({
  name: "cache_misses_total",
  help: "Total number of cache misses",
  labelNames: ["cache_key"],
  registers: [register],
});

const activeConnections = new client.Gauge({
  name: "active_connections",
  help: "Number of active connections",
  labelNames: ["type"],
  registers: [register],
});

const errorCount = new client.Counter({
  name: "errors_total",
  help: "Total number of errors",
  labelNames: ["error_type", "route"],
  registers: [register],
});

const rateLimitExceeded = new client.Counter({
  name: "rate_limit_exceeded_total",
  help: "Total number of rate limit exceeded events",
  labelNames: ["endpoint"],
  registers: [register],
});

const shipmentProcessingTime = new client.Histogram({
  name: "shipment_processing_time_ms",
  help: "Time to process shipment updates in ms",
  labelNames: ["status"],
  buckets: [10, 50, 100, 500, 1000, 5000],
  registers: [register],
});

const activeShipments = new client.Gauge({
  name: "active_shipments",
  help: "Number of active shipments by status",
  labelNames: ["status"],
  registers: [register],
});

const driverOnline = new client.Gauge({
  name: "drivers_online",
  help: "Number of online drivers",
  registers: [register],
});

// Middleware to track metrics
export function metricsMiddleware(req: Request, res: Response, next: Function) {
  const start = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - start;
    const route = req.route?.path || req.path;
    const method = req.method;
    const statusCode = res.statusCode;

    httpRequestDuration.observe(
      { method, route, status_code: statusCode },
      duration,
    );
    httpRequestsTotal.inc({ method, route, status_code: statusCode });
  });

  next();
}

// Metrics endpoints
router.get("/metrics", async (req: Request, res: Response) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

// Health metrics endpoint
router.get("/health/metrics", (req: Request, res: Response) => {
  res.json({
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cpu: process.cpuUsage(),
    timestamp: new Date().toISOString(),
  });
});

// Dashboard metrics summary
router.get("/dashboard/metrics", async (req: Request, res: Response) => {
  const metrics = {
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    metrics: {
      httpRequests: "See /metrics for details",
      databaseQueries: "See /metrics for details",
      cachePerformance: "See /metrics for details",
      errorRate: "See /metrics for details",
    },
  };

  res.json(metrics);
});

// Export metrics for use in application
export const metrics = {
  httpRequestDuration,
  httpRequestsTotal,
  databaseQueryDuration,
  cacheHits,
  cacheMisses,
  activeConnections,
  errorCount,
  rateLimitExceeded,
  shipmentProcessingTime,
  activeShipments,
  driverOnline,
  register,
};

// Prometheus scrape configuration (as guide)
export const prometheusConfig = `
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'infamous-freight-monitor'

scrape_configs:
  - job_name: 'api-server'
    static_configs:
      - targets: ['localhost:4000']
    metrics_path: '/api/metrics'
    scrape_interval: 10s
    scrape_timeout: 5s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['localhost:9187']
`;

// Grafana dashboard configuration (as JSON)
export const grafanaDashboardConfig = {
  dashboard: {
    title: "Infamous Freight Enterprises",
    panels: [
      {
        title: "HTTP Request Rate",
        targets: [
          {
            expr: "rate(http_requests_total[5m])",
          },
        ],
      },
      {
        title: "HTTP Request Duration (p95)",
        targets: [
          {
            expr: "histogram_quantile(0.95, rate(http_request_duration_ms_bucket[5m]))",
          },
        ],
      },
      {
        title: "Error Rate",
        targets: [
          {
            expr: "rate(errors_total[5m])",
          },
        ],
      },
      {
        title: "Database Query Duration (p95)",
        targets: [
          {
            expr: "histogram_quantile(0.95, rate(db_query_duration_ms_bucket[5m]))",
          },
        ],
      },
      {
        title: "Cache Hit Rate",
        targets: [
          {
            expr: "rate(cache_hits_total[5m]) / (rate(cache_hits_total[5m]) + rate(cache_misses_total[5m]))",
          },
        ],
      },
      {
        title: "Active Connections",
        targets: [
          {
            expr: "active_connections",
          },
        ],
      },
      {
        title: "Rate Limit Exceeded Events",
        targets: [
          {
            expr: "rate(rate_limit_exceeded_total[5m])",
          },
        ],
      },
      {
        title: "Active Shipments by Status",
        targets: [
          {
            expr: "active_shipments",
          },
        ],
      },
      {
        title: "Online Drivers",
        targets: [
          {
            expr: "drivers_online",
          },
        ],
      },
      {
        title: "Memory Usage",
        targets: [
          {
            expr: "process_resident_memory_bytes",
          },
        ],
      },
    ],
  },
};

// Alert rules configuration
export const alertRulesConfig = `
groups:
  - name: infamous-freight
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: rate(errors_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ \$value | humanizePercentage }} over 5 minutes"

      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_ms_bucket[5m])) > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High response time detected"
          description: "P95 response time is {{ \$value }}ms"

      - alert: HighDatabaseQueryTime
        expr: histogram_quantile(0.95, rate(db_query_duration_ms_bucket[5m])) > 500
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High database query time"
          description: "P95 query time is {{ \$value }}ms"

      - alert: CacheMissRate
        expr: rate(cache_misses_total[5m]) / (rate(cache_hits_total[5m]) + rate(cache_misses_total[5m])) > 0.5
        for: 5m
        labels:
          severity: info
        annotations:
          summary: "High cache miss rate"
          description: "Cache miss rate is {{ \$value | humanizePercentage }}"

      - alert: RateLimitExceeded
        expr: rate(rate_limit_exceeded_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Rate limit frequently exceeded"
          description: "Rate limit exceeded {{ \$value }} times per second"

      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes > 1073741824
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ \$value | humanize }}B"

      - alert: NoOnlineDrivers
        expr: drivers_online == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "No drivers online"
          description: "All drivers are currently offline"
`;

export default router;
