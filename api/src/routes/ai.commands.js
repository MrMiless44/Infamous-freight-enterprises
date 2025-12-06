const express = require("express");
const { sendCommand } = require("../services/aiSyntheticClient");
const {
  rateLimit,
  authenticate,
  requireScope,
  auditLog
} = require("../middleware/security");

const router = express.Router();

router.post(
  "/ai/command",
  rateLimit,
  authenticate,
  requireScope("ai:command"),
  auditLog,
  async (req, res) => {
    const { command, payload = {}, meta = {} } = req.body || {};
    if (!command) return res.status(400).json({ error: "command required" });

    try {
      const response = await sendCommand(command, payload, {
        ...meta,
        user: req.user?.sub
      });
      res.json({ ok: true, response });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  }
);

module.exports = router;
