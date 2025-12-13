const express = require("express");
const { version } = require("../../package.json");

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

module.exports = router;
