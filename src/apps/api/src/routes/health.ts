import { Router, type Request, type Response } from "express";
import { prisma } from "../lib/prisma";

export const health = Router();

/**
 * Basic health check
 * GET /api/health
 */
health.get("/", async (_: Request, res: Response) => {
  try {
    // Quick database ping
    await prisma.$queryRaw`SELECT 1`;

    res.json({
      ok: true,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  } catch (error) {
    res.status(503).json({
      ok: false,
      error: "Health check failed",
      timestamp: new Date().toISOString(),
    });
  }
});

/**
 * Detailed health check with all service statuses
 * GET /api/health/detailed
 */
health.get("/detailed", async (_: Request, res: Response) => {
  const startTime = Date.now();

  const health: any = {
    status: "healthy",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    checks: {
      database: { status: "unknown", latency: 0 },
      memory: { status: "ok", usage: 0 },
    },
    latency: 0,
  };

  try {
    // Database check
    const dbStart = Date.now();
    await prisma.$queryRaw`SELECT 1`;
    health.checks.database = {
      status: "ok",
      latency: Date.now() - dbStart,
    };
  } catch (error) {
    health.status = "degraded";
    health.checks.database = {
      status: "error",
      latency: Date.now() - startTime,
    };
  }

  // Memory check
  const memUsage = process.memoryUsage();
  health.checks.memory = {
    status: "ok",
    usage: Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100),
  };

  health.latency = Date.now() - startTime;

  const statusCode = health.status === "healthy" ? 200 : 503;
  res.status(statusCode).json(health);
});

/**
 * Kubernetes readiness probe
 * GET /api/health/ready
 * Returns 200 if ready to accept traffic
 */
health.get("/ready", async (_: Request, res: Response) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.status(200).json({ ready: true });
  } catch (error) {
    res.status(503).json({ ready: false, error: "Not ready" });
  }
});

/**
 * Kubernetes liveness probe
 * GET /api/health/live
 * Returns 200 if service is alive
 */
health.get("/live", (_: Request, res: Response) => {
  res.status(200).json({ alive: true });
});
