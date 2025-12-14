const express = require("express");
const Stripe = require("stripe");
const paypal = require("@paypal/checkout-server-sdk");
const prisma = require("../db/prisma");
const {
  authenticate,
  requireScope,
  auditLog,
} = require("../middleware/security");
const {
  validateString,
  handleValidationErrors,
} = require("../middleware/validation");

const router = express.Router();

const stripe = process.env.STRIPE_SECRET_KEY
  ? Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

let paypalClient = null;
if (process.env.PAYPAL_CLIENT_ID && process.env.PAYPAL_SECRET) {
  const env = new paypal.core.SandboxEnvironment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_SECRET,
  );
  paypalClient = new paypal.core.PayPalHttpClient(env);
}

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
    if (!stripe) return next(createError("Stripe not configured", 503));

    try {
      const successUrl = process.env.STRIPE_SUCCESS_URL;
      const cancelUrl = process.env.STRIPE_CANCEL_URL;
      if (!successUrl || !cancelUrl) {
        return next(
          createError("Stripe success/cancel URLs not configured", 503),
        );
      }

      // Use transaction to ensure atomic operation
      const result = await prisma.$transaction(
        async (tx) => {
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

          // Log AI event for billing session creation
          await tx.aiEvent.create({
            data: {
              type: "billing.stripe.session.created",
              payload: {
                sessionId: session.id,
                userId: req.user?.id,
                amount: 4900,
                currency: "usd",
              },
            },
          });

          return session;
        },
        {
          timeout: 30000, // 30s timeout
        },
      );

      res.json({ ok: true, sessionId: result.id, url: result.url });
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
    if (!paypalClient) return next(createError("PayPal not configured", 503));

    try {
      const result = await prisma.$transaction(
        async (tx) => {
          const request = new paypal.orders.OrdersCreateRequest();
          request.requestBody({
            intent: "CAPTURE",
            purchase_units: [
              {
                amount: { currency_code: "USD", value: "49.00" },
              },
            ],
          });

          const order = await paypalClient.execute(request);

          // Log event for order creation
          await tx.aiEvent.create({
            data: {
              type: "billing.paypal.order.created",
              payload: {
                orderId: order.result.id,
                userId: req.user?.id,
                amount: 49.0,
                currency: "USD",
              },
            },
          });

          return order;
        },
        {
          timeout: 30000,
        },
      );

      const approvalUrl =
        result.result.links?.find((link) => link.rel === "approve")?.href ||
        null;
      res.json({ ok: true, orderId: result.result.id, approvalUrl });
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
    if (!paypalClient) return next(createError("PayPal not configured", 503));

    try {
      const result = await prisma.$transaction(
        async (tx) => {
          const request = new paypal.orders.OrdersCaptureRequest(
            req.body.orderId,
          );
          request.requestBody({});

          const capture = await paypalClient.execute(request);

          // Log event for payment capture
          await tx.aiEvent.create({
            data: {
              type: "billing.paypal.capture.completed",
              payload: {
                orderId: req.body.orderId,
                userId: req.user?.id,
                captureId: capture.result.id,
                status: capture.result.status,
              },
            },
          });

          return capture;
        },
        {
          timeout: 30000,
        },
      );

      res.json({ ok: true, capture: result });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
