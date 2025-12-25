import { Router } from "express";
import Stripe from "stripe";
import paypal from "@paypal/checkout-server-sdk";
import config from "../config";
import { requireAuth, requireScope } from "../middleware/auth";

const stripeApiVersion = "2024-06-20" as Stripe.LatestApiVersion;

function createStripeClient() {
  const stripeConfig = config.getStripeConfig();
  return new Stripe(stripeConfig.secretKey, { apiVersion: stripeApiVersion });
}

function createPayPalClient() {
  const paypalConfig = config.getPayPalConfig();
  const environment = new paypal.core.SandboxEnvironment(
    paypalConfig.clientId,
    paypalConfig.clientSecret,
  );
  return new paypal.core.PayPalHttpClient(environment);
}

const DEFAULT_PLAN = {
  mode: "payment" as const,
  price: 4900,
  name: "Infamous Freight AI",
};

export const billing = Router();

billing.use(requireAuth);
billing.use(requireScope("billing:write"));

billing.post("/stripe/session", async (req, res, next) => {
  const stripeConfig = config.getStripeConfig();

  if (!stripeConfig.enabled) {
    return res.status(503).json({ error: "Stripe not configured" });
  }

  if (!stripeConfig.successUrl || !stripeConfig.cancelUrl) {
    return res
      .status(503)
      .json({ error: "Stripe success/cancel URLs not configured" });
  }

  // This endpoint uses a fixed default plan and does not accept any request body.
  if (req.body && Object.keys(req.body).length > 0) {
    return res.status(400).json({
      error:
        "This endpoint does not accept a request body; the default plan is used.",
    });
  }
  try {
    const stripeClient = createStripeClient();
    const session = await stripeClient.checkout.sessions.create({
      mode: DEFAULT_PLAN.mode,
      success_url: stripeConfig.successUrl,
      cancel_url: stripeConfig.cancelUrl,
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: { name: DEFAULT_PLAN.name },
            unit_amount: DEFAULT_PLAN.price,
          },
          quantity: 1,
        },
      ],
    });

    return res.status(200).json({
      ok: true,
      sessionId: session.id,
      url: session.url,
    });
  } catch (err) {
    return next(err);
  }
});

billing.post("/paypal/order", async (req, res, next) => {
  const paypalConfig = config.getPayPalConfig();
  if (!paypalConfig.enabled) {
    return res.status(503).json({ error: "PayPal not configured" });
  }

  const returnUrl =
    paypalConfig.returnUrl || "https://example.com/paypal/success";
  const cancelUrl =
    paypalConfig.cancelUrl || "https://example.com/paypal/cancel";

  try {
    const client = createPayPalClient();
    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
      intent: "CAPTURE",
      purchase_units: [
        {
          amount: {
            currency_code: "USD",
            value: (DEFAULT_PLAN.price / 100).toFixed(2),
          },
        },
      ],
      application_context: {
        return_url: returnUrl,
        cancel_url: cancelUrl,
      },
    });

    const order = await client.execute(request);
    const approvalUrl =
      order?.result?.links?.find((link: { rel: string }) => link.rel === "approve")
        ?.href ?? null;

    return res.status(200).json({
      ok: true,
      orderId: order?.result?.id,
      approvalUrl,
    });
  } catch (err) {
    return next(err);
  }
});

billing.post("/paypal/capture", async (req, res, next) => {
  const { orderId } = req.body ?? {};
  if (!orderId || typeof orderId !== "string" || orderId.length < 1) {
    return res.status(400).json({ error: "orderId is required" });
  }

  if (orderId.length > 128) {
    return res.status(400).json({ error: "orderId too long" });
  }

  const paypalConfig = config.getPayPalConfig();
  if (!paypalConfig.enabled) {
    return res.status(503).json({ error: "PayPal not configured" });
  }

  try {
    const client = createPayPalClient();
    const captureRequest = new paypal.orders.OrdersCaptureRequest(orderId);
    captureRequest.requestBody({});
    const capture = await client.execute(captureRequest);

    return res.status(200).json({
      ok: true,
      capture: capture.result,
    });
  } catch (err) {
    return next(err);
  }
});

export default billing;

// Support CommonJS require in legacy tests
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const module: any;
if (typeof module !== "undefined" && module?.exports) {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  module.exports = billing;
}
