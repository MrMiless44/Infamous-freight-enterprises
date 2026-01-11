const express = require("express");
const { version } = require("../../package.json");
const { prisma } = require("../db/prisma");
const { getStats: getCacheStats } = require("../services/cache");
const { getConnectedClientsCount } = require("../services/websocket");
const { auditLog } = require("../middleware/security");

const router = express.Router();

// Basic health check
router.get("/health", auditLog, (_req, res) => {
  res.json({
    status: "ok",
    service: "infamous-freight-api",
    version: version || "2.0.0",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || "development",
  });
});

// Detailed health check with service dependencies
router.get("/health/detailed", auditLog, async (_req, res) => {
  const checks = {
    api: { status: "healthy", message: "API is running" },
    database: { status: "unknown", message: "Not checked" },
    cache: { status: "unknown", message: "Not checked" },
    websocket: { status: "unknown", message: "Not checked" },
  };

  let overallStatus = "healthy";

  // Check database connection
  try {
    await prisma.$queryRaw`SELECT 1`;
    checks.database = {
      status: "healthy",
      message: "Database connection successful",
    };
  } catch (error) {
    checks.database = {
      status: "unhealthy",
      message: `Database error: ${error.message}`,
    };
    overallStatus = "degraded";
  }

  // Check cache
  try {
    const cacheStats = await getCacheStats();
    checks.cache = {
      status: "healthy",
      message: `Cache type: ${cacheStats.type}`,
      stats: cacheStats,
    };
  } catch (error) {
    checks.cache = {
      status: "degraded",
      message: `Cache error: ${error.message}`,
    };
  }

  // Check WebSocket
  try {
    const connectedClients = getConnectedClientsCount();
    checks.websocket = {
      status: "healthy",
      message: `${connectedClients} clients connected`,
      connectedClients,
    };
  } catch (error) {
    checks.websocket = {
      status: "degraded",
      message: `WebSocket error: ${error.message}`,
    };
  }

  // Overall status
  const unhealthyServices = Object.values(checks).filter(
    (check) => check.status === "unhealthy",
  ).length;

  if (unhealthyServices > 0) {
    overallStatus = "unhealthy";
  } else if (
    Object.values(checks).some((check) => check.status === "degraded")
  ) {
    overallStatus = "degraded";
  }

  const statusCode = overallStatus === "unhealthy" ? 503 : 200;

  res.status(statusCode).json({
    status: overallStatus,
    service: "infamous-freight-api",
    version: version || "2.0.0",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || "development",
    checks,
  });
});

// Readiness check (for Kubernetes/orchestration)
router.get("/health/ready", auditLog, async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ready" });
  } catch (error) {
    res.status(503).json({
      status: "not ready",
      error: error.message,
    });
  }
});

// Liveness check (for Kubernetes/orchestration)
router.get("/health/live", auditLog, (_req, res) => {
  res.json({ status: "alive" });
});

module.exports = router;
