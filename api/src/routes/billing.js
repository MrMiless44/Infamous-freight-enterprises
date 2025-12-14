const express = require("express");
const Stripe = require("stripe");
const paypal = require("@paypal/checkout-server-sdk");
// TODO: Enable Prisma when OpenSSL issue is resolved
// const prisma = require("../db/prisma");
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

      // TODO: Uncomment transaction when Prisma is available
      // Use transaction to ensure atomic operation
      // const result = await prisma.$transaction(async (tx) => {
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
    if (!paypalClient) return next(createError("PayPal not configured", 503));

    try {
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

      // TODO: Log event with Prisma when available
      // await prisma.aiEvent.create({...})

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
    if (!paypalClient) return next(createError("PayPal not configured", 503));

    try {
      const request = new paypal.orders.OrdersCaptureRequest(req.body.orderId);
      request.requestBody({});

      const capture = await paypalClient.execute(request);

      // TODO: Log event with Prisma when available
      // await prisma.aiEvent.create({...})

      res.json({ ok: true, capture });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
