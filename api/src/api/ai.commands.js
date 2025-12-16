const express = require("express");
const {
  authenticate,
  requireScope,
  auditLog,
  limiters,
} = require("../middleware/security");
const { detectApiVersion } = require("../middleware/versionDetection");
const { validateBody } = require("../middleware/zodValidation");

// Version handlers
const v1 = require("../ai/commands/v1");
const v2 = require("../ai/commands/v2");

const router = express.Router();

// Apply version detection to all routes
router.use(detectApiVersion);

/**
 * POST /api/ai/command
 * Handles both v1 and v2 based on detected version
 */
router.post(
  "/ai/command",
  limiters.ai, // Apply AI rate limiter
  authenticate,
  requireScope("ai:command"),
  auditLog,
  (req, res, next) => {
    // Route to appropriate version handler
    if (req.apiVersion === 'v2') {
      validateBody(v2.schema)(req, res, next);
    } else {
      validateBody(v1.schema)(req, res, next);
    }
  },
  async (req, res, next) => {
    // Execute versioned handler
    if (req.apiVersion === 'v2') {
      return v2.handler(req, res, next);
    } else {
      return v1.handler(req, res, next);
    }
  }
);

/**
 * POST /api/v2/ai/command/stream
 * v2 only - streaming support
 */
router.post(
  "/v2/ai/command/stream",
  limiters.ai,
  authenticate,
  requireScope("ai:command"),
  auditLog,
  validateBody(v2.schema),
  v2.streamHandler
);

/**
 * POST /api/v2/ai/command/batch
 * v2 only - batch processing
 */
router.post(
  "/v2/ai/command/batch",
  limiters.ai,
  authenticate,
  requireScope("ai:command"),
  auditLog,
  validateBody(v2.batchSchema),
  v2.batchHandler
);

module.exports = router;
