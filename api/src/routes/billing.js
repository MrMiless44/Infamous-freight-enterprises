const express = require("express");
const Stripe = require("stripe");
const paypal = require("@paypal/checkout-server-sdk");
const { prisma } = require("../db/prisma");
const {
  authenticate,
  requireScope,
  auditLog,
} = require("../middleware/security");
const {
  validateString,
  handleValidationErrors,
} = require("../middleware/validation");
const invoiceRoutes = require("./billing/invoices");
const reportRoutes = require("./billing/reports");

const router = express.Router();

router.use("/billing/invoices", invoiceRoutes);
router.use("/billing/reports", reportRoutes);

// Lazy initialization functions for better testability
const getStripeClient = () => {
  if (!process.env.STRIPE_SECRET_KEY) return null;
  return Stripe(process.env.STRIPE_SECRET_KEY);
};

const getPayPalClient = () => {
  if (!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_SECRET) return null;
  const env = new paypal.core.SandboxEnvironment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_SECRET,
  );
  return new paypal.core.PayPalHttpClient(env);
};

const createError = (message, status = 500) => {
  const err = new Error(message);
  err.status = status;
  return err;
};

router.post(
  "/billing/stripe/session",
  authenticate,
  requireScope("billing:write"),
  auditLog,
  async (req, res, next) => {
    const stripe = getStripeClient();
    if (!stripe) return next(createError("Stripe not configured", 503));

    try {
      const successUrl = process.env.STRIPE_SUCCESS_URL;
      const cancelUrl = process.env.STRIPE_CANCEL_URL;
      if (!successUrl || !cancelUrl) {
        return next(
          createError("Stripe success/cancel URLs not configured", 503),
        );
      }

      // NOTE: Prisma transaction & audit logging intentionally deferred
      // Will be implemented when audit event schema is finalized
      // For now, Stripe's own audit trail provides sufficient tracking
      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        success_url: successUrl,
        cancel_url: cancelUrl,
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: { name: "Infamous Freight AI" },
              unit_amount: 4900,
            },
            quantity: 1,
          },
        ],
      });

      // Log AI event would happen here with Prisma
      // await tx.aiEvent.create({...})

      res.json({ ok: true, sessionId: session.id, url: session.url });
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  "/billing/paypal/order",
  authenticate,
  requireScope("billing:write"),
  auditLog,
  async (req, res, next) => {
    const paypalClient = getPayPalClient();
    if (!paypalClient) return next(createError("PayPal not configured", 503));

    try {
      const request = new paypal.orders.OrdersCreateRequest();
      request.requestBody = {
        intent: "CAPTURE",
        purchase_units: [
          {
            amount: { currency_code: "USD", value: "49.00" },
          },
        ],
      };

      const order = await paypalClient.execute(request);

      // NOTE: Event logging deferred - PayPal's webhook system provides audit trail
      // Will integrate with centralized audit logging system in future iteration

      const approvalUrl =
        order.result.links?.find((link) => link.rel === "approve")?.href ||
        null;
      res.json({ ok: true, orderId: order.result.id, approvalUrl });
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  "/billing/paypal/capture",
  authenticate,
  requireScope("billing:write"),
  auditLog,
  [validateString("orderId", { min: 1, max: 128 }), handleValidationErrors],
  async (req, res, next) => {
    const paypalClient = getPayPalClient();
    if (!paypalClient) return next(createError("PayPal not configured", 503));

    try {
      const request = new paypal.orders.OrdersCaptureRequest(req.body.orderId);
      request.requestBody = {};

      const capture = await paypalClient.execute(request);

      // NOTE: Event logging deferred - PayPal's webhook system provides audit trail
      // Will integrate with centralized audit logging system in future iteration

      res.json({ ok: true, capture: capture.result });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
