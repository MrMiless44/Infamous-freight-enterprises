const express = require("express");
const { prisma } = require("../db/prisma");
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

// Get all AI decisions with optional filtering
router.get(
  "/ai-decisions",
  limiters.general,
  authenticate,
  requireScope("ai:decisions:read"),
  auditLog,
  async (req, res, next) => {
    try {
      const { organizationId, agent, invoiceId } = req.query;
      const where = {};

      if (organizationId) where.organizationId = organizationId;
      if (agent) where.agent = agent;
      if (invoiceId) where.invoiceId = invoiceId;

      const decisions = await prisma.aiDecision.findMany({
        where,
        include: {
          feedback: true,
        },
        orderBy: {
          createdAt: "desc",
        },
      });

      res.json({ ok: true, decisions });
    } catch (err) {
      next(err);
    }
  },
);

// Get AI decision by ID
router.get(
  "/ai-decisions/:id",
  limiters.general,
  authenticate,
  requireScope("ai:decisions:read"),
  auditLog,
  async (req, res, next) => {
    try {
      const decision = await prisma.aiDecision.findUnique({
        where: { id: req.params.id },
        include: {
          feedback: true,
        },
      });

      if (!decision) {
        return res
          .status(404)
          .json({ ok: false, error: "AI decision not found" });
      }

      res.json({ ok: true, decision });
    } catch (err) {
      next(err);
    }
  },
);

// Create new AI decision
router.post(
  "/ai-decisions",
  limiters.ai,
  authenticate,
  requireScope("ai:decisions:write"),
  auditLog,
  [
    validateString("organizationId", { min: 1, max: 100 }),
    validateString("invoiceId", { min: 1, max: 100 }),
    validateString("agent", { min: 1, max: 100 }),
    validateString("decision", { min: 1, max: 50 }),
    handleValidationErrors,
  ],
  async (req, res, next) => {
    try {
      const { organizationId, invoiceId, agent, decision, confidence, rationale } =
        req.body;

      // Validate confidence is a number between 0 and 1
      if (
        typeof confidence !== "number" ||
        confidence < 0 ||
        confidence > 1
      ) {
        return res.status(400).json({
          ok: false,
          error: "Confidence must be a number between 0 and 1",
        });
      }

      // Validate decision value
      if (!["approve", "dispute"].includes(decision)) {
        return res.status(400).json({
          ok: false,
          error: "Decision must be 'approve' or 'dispute'",
        });
      }

      const newDecision = await prisma.aiDecision.create({
        data: {
          organizationId,
          invoiceId,
          agent,
          decision,
          confidence,
          rationale: rationale || {},
        },
        include: {
          feedback: true,
        },
      });

      res.status(201).json({ ok: true, decision: newDecision });
    } catch (err) {
      next(err);
    }
  },
);

// Create feedback for an AI decision
router.post(
  "/ai-decisions/:id/feedback",
  limiters.general,
  authenticate,
  requireScope("ai:decisions:write"),
  auditLog,
  [
    validateString("outcome", { min: 1, max: 50 }),
    handleValidationErrors,
  ],
  async (req, res, next) => {
    try {
      const { id } = req.params;
      const { outcome, notes } = req.body;

      // Validate outcome value
      if (!["correct", "false_positive", "missed"].includes(outcome)) {
        return res.status(400).json({
          ok: false,
          error: "Outcome must be 'correct', 'false_positive', or 'missed'",
        });
      }

      // Check if decision exists
      const decision = await prisma.aiDecision.findUnique({
        where: { id },
        include: { feedback: true },
      });

      if (!decision) {
        return res
          .status(404)
          .json({ ok: false, error: "AI decision not found" });
      }

      // Check if feedback already exists
      if (decision.feedback) {
        return res.status(409).json({
          ok: false,
          error: "Feedback already exists for this decision",
        });
      }

      const feedback = await prisma.aiFeedback.create({
        data: {
          aiDecisionId: id,
          outcome,
          notes: notes || null,
        },
      });

      res.status(201).json({ ok: true, feedback });
    } catch (err) {
      next(err);
    }
  },
);

// Update feedback for an AI decision
router.patch(
  "/ai-feedback/:id",
  limiters.general,
  authenticate,
  requireScope("ai:decisions:write"),
  auditLog,
  async (req, res, next) => {
    try {
      const { id } = req.params;
      const { outcome, notes } = req.body;

      // Validate outcome if provided
      if (
        outcome &&
        !["correct", "false_positive", "missed"].includes(outcome)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Outcome must be 'correct', 'false_positive', or 'missed'",
        });
      }

      const data = {};
      if (outcome) data.outcome = outcome;
      if (notes !== undefined) data.notes = notes;

      const feedback = await prisma.aiFeedback.update({
        where: { id },
        data,
      });

      res.json({ ok: true, feedback });
    } catch (err) {
      if (err.code === "P2025") {
        return res.status(404).json({ ok: false, error: "Feedback not found" });
      }
      next(err);
    }
  },
);

// Get feedback by AI decision ID
router.get(
  "/ai-decisions/:id/feedback",
  limiters.general,
  authenticate,
  requireScope("ai:decisions:read"),
  auditLog,
  async (req, res, next) => {
    try {
      const { id } = req.params;

      const feedback = await prisma.aiFeedback.findUnique({
        where: { aiDecisionId: id },
        include: {
          aiDecision: true,
        },
      });

      if (!feedback) {
        return res.status(404).json({ ok: false, error: "Feedback not found" });
      }

      res.json({ ok: true, feedback });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
