const express = require("express");
const Stripe = require("stripe");
const paypal = require("@paypal/checkout-server-sdk");
const {
  rateLimit,
  authenticate,
  requireScope,
  auditLog
} = require("../middleware/security");

const router = express.Router();

const stripe = process.env.STRIPE_SECRET_KEY
  ? Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

let paypalClient = null;
if (process.env.PAYPAL_CLIENT_ID && process.env.PAYPAL_SECRET) {
  const env = new paypal.core.SandboxEnvironment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_SECRET
  );
  paypalClient = new paypal.core.PayPalHttpClient(env);
}

router.post(
  "/billing/stripe/session",
  rateLimit,
  authenticate,
  requireScope("billing:write"),
  auditLog,
  async (_req, res) => {
    if (!stripe) return res.status(500).json({ error: "Stripe not configured" });

    try {
      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        success_url: process.env.STRIPE_SUCCESS_URL,
        cancel_url: process.env.STRIPE_CANCEL_URL,
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: { name: "Infamous Freight AI" },
              unit_amount: 4900
            },
            quantity: 1
          }
        ]
      });

      res.json({ ok: true, sessionId: session.id, url: session.url });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  }
);

router.post(
  "/billing/paypal/order",
  rateLimit,
  authenticate,
  requireScope("billing:write"),
  auditLog,
  async (_req, res) => {
    if (!paypalClient) return res.status(500).json({ error: "PayPal not configured" });

    try {
      const request = new paypal.orders.OrdersCreateRequest();
      request.requestBody({
        intent: "CAPTURE",
        purchase_units: [
          {
            amount: { currency_code: "USD", value: "49.00" }
          }
        ]
      });

      const order = await paypalClient.execute(request);
      const approvalUrl =
        order.result.links?.find(link => link.rel === "approve")?.href || null;
      res.json({ ok: true, orderId: order.result.id, approvalUrl });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  }
);

router.post(
  "/billing/paypal/capture",
  rateLimit,
  authenticate,
  requireScope("billing:write"),
  auditLog,
  async (req, res) => {
    if (!paypalClient) return res.status(500).json({ error: "PayPal not configured" });

    const { orderId } = req.body || {};
    if (!orderId) return res.status(400).json({ error: "orderId required" });

    try {
      const request = new paypal.orders.OrdersCaptureRequest(orderId);
      request.requestBody({});

      const capture = await paypalClient.execute(request);
      res.json({ ok: true, capture });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  }
);

module.exports = router;
