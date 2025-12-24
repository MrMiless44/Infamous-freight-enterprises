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

/**
 * @swagger
 * components:
 *   schemas:
 *     AiDecision:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *           example: "decision-123"
 *         organizationId:
 *           type: string
 *           example: "org-123"
 *         invoiceId:
 *           type: string
 *           example: "invoice-123"
 *         agent:
 *           type: string
 *           example: "billing_audit"
 *         decision:
 *           type: string
 *           enum: [approve, dispute]
 *           example: "approve"
 *         confidence:
 *           type: number
 *           format: float
 *           minimum: 0
 *           maximum: 1
 *           example: 0.95
 *         rationale:
 *           type: object
 *           example: { "reason": "Invoice matches purchase order" }
 *         createdAt:
 *           type: string
 *           format: date-time
 *         feedback:
 *           $ref: '#/components/schemas/AiFeedback'
 *     AiFeedback:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *           example: "feedback-123"
 *         aiDecisionId:
 *           type: string
 *           example: "decision-123"
 *         outcome:
 *           type: string
 *           enum: [correct, false_positive, missed]
 *           example: "correct"
 *         notes:
 *           type: string
 *           example: "Decision was accurate"
 *         createdAt:
 *           type: string
 *           format: date-time
 */

/**
 * @swagger
 * /api/ai-decisions:
 *   get:
 *     summary: Get all AI decisions with optional filtering
 *     tags: [AI Decisions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: organizationId
 *         schema:
 *           type: string
 *         description: Filter by organization ID
 *       - in: query
 *         name: agent
 *         schema:
 *           type: string
 *         description: Filter by agent name
 *       - in: query
 *         name: invoiceId
 *         schema:
 *           type: string
 *         description: Filter by invoice ID
 *     responses:
 *       200:
 *         description: List of AI decisions
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 decisions:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/AiDecision'
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Insufficient permissions
 */
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

/**
 * @swagger
 * /api/ai-decisions/{id}:
 *   get:
 *     summary: Get AI decision by ID
 *     tags: [AI Decisions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: AI decision ID
 *     responses:
 *       200:
 *         description: AI decision details
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 decision:
 *                   $ref: '#/components/schemas/AiDecision'
 *       404:
 *         description: AI decision not found
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Insufficient permissions
 */
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

/**
 * @swagger
 * /api/ai-decisions:
 *   post:
 *     summary: Create new AI decision
 *     tags: [AI Decisions]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [organizationId, invoiceId, agent, decision, confidence]
 *             properties:
 *               organizationId:
 *                 type: string
 *                 example: "org-123"
 *               invoiceId:
 *                 type: string
 *                 example: "invoice-123"
 *               agent:
 *                 type: string
 *                 example: "billing_audit"
 *               decision:
 *                 type: string
 *                 enum: [approve, dispute]
 *                 example: "approve"
 *               confidence:
 *                 type: number
 *                 format: float
 *                 minimum: 0
 *                 maximum: 1
 *                 example: 0.95
 *               rationale:
 *                 type: object
 *                 example: { "reason": "Invoice matches purchase order" }
 *     responses:
 *       201:
 *         description: AI decision created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 decision:
 *                   $ref: '#/components/schemas/AiDecision'
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Insufficient permissions
 */
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

/**
 * @swagger
 * /api/ai-decisions/{id}/feedback:
 *   post:
 *     summary: Create feedback for an AI decision
 *     tags: [AI Decisions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: AI decision ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [outcome]
 *             properties:
 *               outcome:
 *                 type: string
 *                 enum: [correct, false_positive, missed]
 *                 example: "correct"
 *               notes:
 *                 type: string
 *                 example: "Decision was accurate"
 *     responses:
 *       201:
 *         description: Feedback created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 feedback:
 *                   $ref: '#/components/schemas/AiFeedback'
 *       400:
 *         description: Invalid input
 *       404:
 *         description: AI decision not found
 *       409:
 *         description: Feedback already exists
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Insufficient permissions
 *   get:
 *     summary: Get feedback for an AI decision
 *     tags: [AI Decisions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: AI decision ID
 *     responses:
 *       200:
 *         description: Feedback details
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 feedback:
 *                   $ref: '#/components/schemas/AiFeedback'
 *       404:
 *         description: Feedback not found
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Insufficient permissions
 */
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

/**
 * @swagger
 * /api/ai-feedback/{id}:
 *   patch:
 *     summary: Update feedback for an AI decision
 *     tags: [AI Decisions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Feedback ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               outcome:
 *                 type: string
 *                 enum: [correct, false_positive, missed]
 *                 example: "correct"
 *               notes:
 *                 type: string
 *                 example: "Updated feedback notes"
 *     responses:
 *       200:
 *         description: Feedback updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 feedback:
 *                   $ref: '#/components/schemas/AiFeedback'
 *       400:
 *         description: Invalid input
 *       404:
 *         description: Feedback not found
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Insufficient permissions
 */
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
