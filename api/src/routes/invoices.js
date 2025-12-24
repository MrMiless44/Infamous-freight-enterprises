const express = require("express");
const { body, param } = require("express-validator");
const { prisma } = require("../db/prisma");
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

const currencyValidator = body("currency")
  .optional()
  .isString()
  .trim()
  .isLength({ min: 3, max: 3 })
  .withMessage("currency must be a 3-letter code")
  .toUpperCase();

const amountValidator = body("totalAmount")
  .isFloat({ gt: 0 })
  .withMessage("totalAmount must be a positive number")
  .toFloat();

// Create invoice (metadata first)
router.post(
  "/invoices",
  limiters.billing,
  authenticate,
  requireScope("billing:write"),
  auditLog,
  [
    validateString("carrier", { min: 1, max: 200 }),
    validateString("reference", { min: 1, max: 100 }),
    amountValidator,
    currencyValidator,
    handleValidationErrors,
  ],
  async (req, res, next) => {
    try {
      const { carrier, reference, totalAmount, currency } = req.body;
      const invoice = await prisma.invoice.create({
        data: {
          carrier,
          reference,
          totalAmount,
          currency: currency || "USD",
          status: "pending",
        },
      });
      res.status(201).json({ ok: true, invoice });
    } catch (err) {
      if (err.code === "P2002") {
        return res
          .status(409)
          .json({ ok: false, error: "Invoice reference already exists" });
      }
      next(err);
    }
  },
);

// List invoices
router.get(
  "/invoices",
  limiters.billing,
  authenticate,
  requireScope("billing:read"),
  auditLog,
  async (_req, res, next) => {
    try {
      const invoices = await prisma.invoice.findMany({
        orderBy: { createdAt: "desc" },
      });
      res.json({ ok: true, invoices });
    } catch (err) {
      next(err);
    }
  },
);

// Audit invoice (AI)
router.post(
  "/invoices/:id/audit",
  limiters.ai,
  authenticate,
  requireScope("billing:read"),
  requireScope("ai:command"),
  auditLog,
  [param("id").isString().notEmpty(), handleValidationErrors],
  async (req, res, next) => {
    try {
      const { id } = req.params;

      const invoice = await prisma.invoice.findUnique({ where: { id } });
      if (!invoice) {
        return res.status(404).json({ ok: false, error: "Invoice not found" });
      }

      const aiPayload = {
        invoice: {
          carrier: invoice.carrier,
          reference: invoice.reference,
          totalAmount: Number(invoice.totalAmount),
          currency: invoice.currency,
        },
        ruleset: "standard_freight",
      };

      const result = await sendCommand("audit_invoice", aiPayload, {
        user: req.user?.sub,
      });

      const savingsValue = Number(result?.savings ?? 0);
      const decision = typeof result?.decision === "string" ? result.decision : null;
      const status =
        decision === "approve"
          ? "approved"
          : decision === "dispute"
            ? "disputed"
            : "audited";

      const updated = await prisma.invoice.update({
        where: { id },
        data: {
          auditResult: result || {},
          savings: Number.isFinite(savingsValue) ? savingsValue : 0,
          status,
        },
      });

      res.json({ ok: true, invoice: updated });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
