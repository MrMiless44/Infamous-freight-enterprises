const express = require("express");
const { version } = require("../../package.json");
const { prisma } = require("../db/prisma");
const { logger } = require("../middleware/logger");

const router = express.Router();

router.get("/health", async (_req, res) => {
  const startedAt = Date.now();
  let databaseStatus = "disconnected";
  let databaseLatencyMs = null;

  try {
    await prisma.$queryRaw`SELECT 1`;
    databaseStatus = "connected";
    databaseLatencyMs = Date.now() - startedAt;
  } catch (error) {
    logger.warn(
      { error: error.message },
      "Database connectivity check failed during health probe",
    );
  }

  const isHealthy = databaseStatus === "connected";
  const statusCode = isHealthy ? 200 : 503;

  res.status(statusCode).json({
    status: isHealthy ? "ok" : "degraded",
    service: "infamous-freight-api",
    version: version || "2.0.0",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || "development",
    database: databaseStatus,
    databaseLatencyMs,
  });
});

module.exports = router;
