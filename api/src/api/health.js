const express = require("express");
const { version } = require("../../package.json");
const { getCircuitBreakerStats } = require("../ai/aiSyntheticClient");

const router = express.Router();

router.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "infamous-freight-api",
    version: version || "2.0.0",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || "development",
  });
});

router.get("/health/circuit-breakers", (_req, res) => {
  try {
    const stats = getCircuitBreakerStats();
    const allClosed = Object.values(stats).every(breaker => breaker.state === 'closed');
    
    res.json({
      status: allClosed ? "healthy" : "degraded",
      circuitBreakers: stats,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      error: "Failed to retrieve circuit breaker stats",
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router;
