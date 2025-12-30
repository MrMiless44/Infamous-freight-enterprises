import { Router, type Request, type Response } from "express";
import { prisma } from "../lib/prisma";

export const monitoring = Router();

/**
 * Prometheus-compatible metrics endpoint
 * GET /api/metrics
 * Returns metrics in Prometheus text format
 */
monitoring.get("/metrics", async (_: Request, res: Response) => {
  try {
    const startTime = Date.now();

    // Collect metrics
    const metrics = {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString(),
    };

    // Database check
    try {
      await prisma.$queryRaw`SELECT 1`;
      metrics.database_connected = 1;
    } catch {
      metrics.database_connected = 0;
    }

    // Format as Prometheus metrics
    const prometheusMetrics = `
# HELP process_uptime_seconds Process uptime in seconds
# TYPE process_uptime_seconds gauge
process_uptime_seconds ${metrics.uptime}

# HELP process_resident_memory_bytes Resident memory in bytes
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes ${metrics.memory.rss}

# HELP process_heap_used_bytes Heap used in bytes
# TYPE process_heap_used_bytes gauge
process_heap_used_bytes ${metrics.memory.heapUsed}

# HELP process_heap_total_bytes Total heap in bytes
# TYPE process_heap_total_bytes gauge
process_heap_total_bytes ${metrics.memory.heapTotal}

# HELP database_connected Database connection status (1=connected, 0=disconnected)
# TYPE database_connected gauge
database_connected ${metrics.database_connected}

# HELP request_duration_ms Request duration in milliseconds
# TYPE request_duration_ms gauge
request_duration_ms ${Date.now() - startTime}
`.trim();

    res.setHeader("Content-Type", "text/plain; version=0.0.4");
    res.send(prometheusMetrics);
  } catch (error) {
    res.status(500).json({ error: "Failed to generate metrics" });
  }
});

/**
 * Performance metrics endpoint
 * GET /api/metrics/performance
 * Returns detailed performance metrics
 */
monitoring.get("/metrics/performance", async (_: Request, res: Response) => {
  try {
    const uptime = process.uptime();
    const memory = process.memoryUsage();
    const heapUsedPercent = (memory.heapUsed / memory.heapTotal) * 100;

    res.json({
      timestamp: new Date().toISOString(),
      uptime: {
        seconds: uptime,
        formatted: formatUptime(uptime),
      },
      memory: {
        rss_mb: Math.round(memory.rss / 1024 / 1024),
        heap_used_mb: Math.round(memory.heapUsed / 1024 / 1024),
        heap_total_mb: Math.round(memory.heapTotal / 1024 / 1024),
        heap_used_percent: Math.round(heapUsedPercent * 100) / 100,
        external_mb: Math.round(memory.external / 1024 / 1024),
      },
      process: {
        pid: process.pid,
        version: process.version,
        platform: process.platform,
        arch: process.arch,
      },
      alerts: generateAlerts(memory, heapUsedPercent),
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve performance metrics" });
  }
});

/**
 * Cache metrics endpoint
 * GET /api/metrics/cache
 * Returns cache hit/miss statistics
 */
monitoring.get("/metrics/cache", async (_: Request, res: Response) => {
  try {
    // This would be populated by cache service
    // For now, return empty metrics structure
    res.json({
      timestamp: new Date().toISOString(),
      hits: 0,
      misses: 0,
      hitRate: 0,
      size: 0,
      maxSize: 0,
      ttlAverage: 0,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve cache metrics" });
  }
});

/**
 * WebSocket metrics endpoint
 * GET /api/metrics/websocket
 * Returns WebSocket connection statistics
 */
monitoring.get("/metrics/websocket", async (_: Request, res: Response) => {
  try {
    // This would be populated by WebSocket service
    // For now, return empty metrics structure
    res.json({
      timestamp: new Date().toISOString(),
      activeConnections: 0,
      totalConnections: 0,
      averageLatency: 0,
      messagesPerSecond: 0,
      rooms: {},
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve WebSocket metrics" });
  }
});

/**
 * Rate limiting metrics endpoint
 * GET /api/metrics/ratelimit
 * Returns rate limiting statistics
 */
monitoring.get("/metrics/ratelimit", async (_: Request, res: Response) => {
  try {
    res.json({
      timestamp: new Date().toISOString(),
      limiters: {
        general: {
          name: "General Rate Limit",
          max: parseInt(process.env.RATE_LIMIT_GENERAL_MAX || "100"),
          window: "15 minutes",
          hits: 0,
          rejections: 0,
        },
        ai: {
          name: "AI Rate Limit",
          max: parseInt(process.env.RATE_LIMIT_AI_MAX || "20"),
          window: "1 minute",
          hits: 0,
          rejections: 0,
        },
        billing: {
          name: "Billing Rate Limit",
          max: parseInt(process.env.RATE_LIMIT_BILLING_MAX || "30"),
          window: "15 minutes",
          hits: 0,
          rejections: 0,
        },
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve rate limit metrics" });
  }
});

/**
 * Liveness probe endpoint
 * GET /api/metrics/alive
 * Returns 200 if service is alive
 */
monitoring.get("/metrics/alive", (_: Request, res: Response) => {
  res.json({ alive: true, timestamp: new Date().toISOString() });
});

/**
 * Readiness probe endpoint
 * GET /api/metrics/ready
 * Returns 200 if service is ready to accept traffic
 */
monitoring.get("/metrics/ready", async (_: Request, res: Response) => {
  try {
    // Check database
    await prisma.$queryRaw`SELECT 1`;

    res.json({
      ready: true,
      checks: {
        database: "ok",
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(503).json({
      ready: false,
      error: "Service not ready",
      timestamp: new Date().toISOString(),
    });
  }
});

/**
 * Health summary endpoint
 * GET /api/metrics/health
 * Returns overall health status
 */
monitoring.get("/metrics/health", async (_: Request, res: Response) => {
  try {
    const memory = process.memoryUsage();
    const heapUsedPercent = (memory.heapUsed / memory.heapTotal) * 100;

    let overall = "healthy";
    const issues: string[] = [];

    // Check memory
    if (heapUsedPercent > 90) {
      overall = "degraded";
      issues.push("Memory usage critical (>90%)");
    } else if (heapUsedPercent > 75) {
      overall = "degraded";
      issues.push("Memory usage high (>75%)");
    }

    // Check database
    let databaseOk = true;
    try {
      await prisma.$queryRaw`SELECT 1`;
    } catch (error) {
      databaseOk = false;
      overall = "unhealthy";
      issues.push("Database connection failed");
    }

    res.status(overall === "healthy" ? 200 : 503).json({
      status: overall,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      checks: {
        database: databaseOk ? "ok" : "error",
        memory:
          heapUsedPercent > 90
            ? "critical"
            : heapUsedPercent > 75
              ? "warning"
              : "ok",
      },
      issues,
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      error: "Failed to retrieve health status",
    });
  }
});

/**
 * Helper functions
 */
function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / (24 * 3600));
  const hours = Math.floor((seconds % (24 * 3600)) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  return `${days}d ${hours}h ${minutes}m ${secs}s`;
}

function generateAlerts(
  memory: NodeJS.MemoryUsage,
  heapUsedPercent: number,
): string[] {
  const alerts: string[] = [];

  if (heapUsedPercent > 90) {
    alerts.push("CRITICAL: Memory usage exceeds 90%");
  } else if (heapUsedPercent > 75) {
    alerts.push("WARNING: Memory usage exceeds 75%");
  }

  if (memory.rss > 1024 * 1024 * 1024) {
    alerts.push("WARNING: RSS memory exceeds 1GB");
  }

  return alerts;
}

export default monitoring;
