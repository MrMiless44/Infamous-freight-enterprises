const express = require("express");
const { register } = require("@infamous-freight/shared/metrics");

const router = express.Router();

router.get("/metrics", async (req, res) => {
  try {
    res.set("Content-Type", register.contentType);
    const metrics = await register.metrics();
    res.end(metrics);
  } catch (err) {
    res.status(500).json({ error: "Metrics collection failed" });
  }
});

module.exports = router;
