const express = require("express");
const { body } = require("express-validator");
const { sendCommand } = require("../services/aiSyntheticClient");
const {
  authenticate,
  requireScope,
  auditLog,
  limiters,
} = require("../middleware/security");
const {
  validateString,
  handleValidationErrors,
} = require("../middleware/validation");

const router = express.Router();

router.post(
  "/ai/command",
  limiters.ai, // Apply AI rate limiter
  authenticate,
  requireScope("ai:command"),
  auditLog,
  [
    validateString("command", { min: 1, max: 200 }),
    body("payload")
      .optional()
      .isObject()
      .withMessage("payload must be an object"),
    body("meta").optional().isObject().withMessage("meta must be an object"),
    handleValidationErrors,
  ],
  async (req, res, next) => {
    const { command, payload = {}, meta = {} } = req.body || {};

    try {
      const response = await sendCommand(command, payload, {
        ...meta,
        user: req.user?.sub,
      });
      res.json({ ok: true, response });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
