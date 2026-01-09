import express, { Router } from "express";
import Stripe from "stripe";
import paypal from "@paypal/checkout-server-sdk";
import config from "../config";
import { prisma } from "../db/prisma";
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

const PRICE = {
  DISPATCH_MONTHLY: "price_1Sne9YJBKY4ohJDA62rFeOh7",
  FLEET_MONTHLY: "price_1SneAFJBKY4ohJDATu9s9af6",
  OPS_MONTHLY: "price_1SneAkJBKY4ohJDAkULygwM7",
  ENTERPRISE_MONTHLY: "price_1SneKlJBKY4ohJDAML8txHCO",
  DISPATCH_ANNUAL: "price_1SneHuJBKY4ohJDA97jEMaf4",
  FLEET_ANNUAL: "price_1SneIJJBKY4ohJDAeadaRPi5",
  OPS_ANNUAL: "price_1SneIcJBKY4ohJDAGaw2PUzW",
  ENTERPRISE_ANNUAL: "price_1SneMeJBKY4ohJDAfnjjWJSV",
} as const;

function featuresForPrice(priceId: string) {
  const base = {
    ai_dispatch: true,
    driver_view: true,
    basic_loads: true,
    analytics: false,
    automation: false,
    audit_logs: false,
    api_access: false,
    invoice_audit: false,
  };

  switch (priceId) {
    case PRICE.DISPATCH_MONTHLY:
    case PRICE.DISPATCH_ANNUAL:
      return base;
    case PRICE.FLEET_MONTHLY:
    case PRICE.FLEET_ANNUAL:
      return { ...base, analytics: true };
    case PRICE.OPS_MONTHLY:
    case PRICE.OPS_ANNUAL:
      return { ...base, analytics: true, automation: true };
    case PRICE.ENTERPRISE_MONTHLY:
    case PRICE.ENTERPRISE_ANNUAL:
      return {
        ...base,
        analytics: true,
        automation: true,
        audit_logs: true,
        api_access: true,
        invoice_audit: true,
      };
    default:
      return {
        ai_dispatch: false,
        driver_view: false,
        basic_loads: false,
        analytics: false,
        automation: false,
        audit_logs: false,
        api_access: false,
        invoice_audit: false,
      };
  }
}

function planName(priceId: string) {
  if ([PRICE.DISPATCH_MONTHLY, PRICE.DISPATCH_ANNUAL].includes(priceId as any)) {
    return "AI Dispatch Operator";
  }
  if ([PRICE.FLEET_MONTHLY, PRICE.FLEET_ANNUAL].includes(priceId as any)) {
    return "Fleet Intelligence";
  }
  if ([PRICE.OPS_MONTHLY, PRICE.OPS_ANNUAL].includes(priceId as any)) {
    return "Autonomous Ops Suite";
  }
  if ([PRICE.ENTERPRISE_MONTHLY, PRICE.ENTERPRISE_ANNUAL].includes(priceId as any)) {
    return "Enterprise";
  }
  return "Unknown";
}

function requireUserId(req: express.Request) {
  const userId = req.user?.id;
  if (!userId) {
    throw new Error("User context required for billing checkout.");
  }
  return userId;
}

export const billing = Router();
export const billingWebhook = Router();

billing.use(requireAuth);
billing.use(requireScope("billing:write"));

billing.post("/stripe/checkout", express.json(), async (req, res) => {
  const stripeConfig = config.getStripeConfig();
  if (!stripeConfig.enabled) {
    return res.status(503).json({ error: "Stripe not configured" });
  }

  if (!stripeConfig.successUrl || !stripeConfig.cancelUrl) {
    return res
      .status(503)
      .json({ error: "Stripe success/cancel URLs not configured" });
  }

  const { priceId } = req.body as { priceId?: string };
  if (!priceId) {
    return res.status(400).json({ error: "priceId is required" });
  }

  try {
    const userId = requireUserId(req);
    const stripeClient = createStripeClient();

    let stripeCustomer = await prisma.stripeCustomer.findUnique({
      where: { userId },
    });
    if (!stripeCustomer) {
      const customer = await stripeClient.customers.create({
        metadata: { userId },
      });
      stripeCustomer = await prisma.stripeCustomer.create({
        data: { userId, stripeCustomerId: customer.id },
      });
    }

    const session = await stripeClient.checkout.sessions.create({
      mode: "subscription",
      customer: stripeCustomer.stripeCustomerId,
      line_items: [{ price: priceId, quantity: 1 }],
      allow_promotion_codes: true,
      client_reference_id: userId,
      subscription_data: {
        metadata: { userId, plan: planName(priceId) },
      },
      success_url: stripeConfig.successUrl,
      cancel_url: stripeConfig.cancelUrl,
    });

    return res.status(200).json({ url: session.url, id: session.id });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message ?? "Unknown error" });
  }
});

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

billingWebhook.post(
  "/",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const stripeConfig = config.getStripeConfig();
    if (!stripeConfig.enabled) {
      return res.status(503).json({ error: "Stripe not configured" });
    }

    const { stripeWebhookSecret } = config.getApiKeys();
    const signature = req.headers["stripe-signature"];
    if (!signature || typeof signature !== "string") {
      return res.status(400).send("Missing Stripe-Signature header");
    }

    let event: Stripe.Event;

    try {
      event = createStripeClient().webhooks.constructEvent(
        req.body,
        signature,
        stripeWebhookSecret,
      );
    } catch (err: any) {
      return res
        .status(400)
        .send(
          `Webhook signature verification failed: ${err?.message ?? "Unknown error"}`,
        );
    }

    const existing = await prisma.stripeEvent.findUnique({
      where: { eventId: event.id },
    });
    if (existing) {
      return res.status(200).json({ received: true, duplicate: true });
    }

    await prisma.stripeEvent.create({
      data: { eventId: event.id, type: event.type },
    });

    try {
      switch (event.type) {
        case "invoice.paid": {
          const invoice = event.data.object as Stripe.Invoice;
          const subscriptionId =
            typeof invoice.subscription === "string"
              ? invoice.subscription
              : invoice.subscription?.id;
          if (!subscriptionId) break;

          const stripeClient = createStripeClient();
          const subscription = await stripeClient.subscriptions.retrieve(
            subscriptionId,
            {
              expand: ["items.data.price"],
            },
          );

          const userId = subscription.metadata?.userId;
          if (!userId) break;

          const priceId = subscription.items.data[0]?.price?.id;
          if (!priceId) break;

          const status = subscription.status;
          const currentPeriodEnd = subscription.current_period_end
            ? new Date(subscription.current_period_end * 1000)
            : null;

          await prisma.subscriptionEntitlement.upsert({
            where: { userId },
            create: {
              userId,
              plan: planName(priceId),
              status,
              stripeSubscriptionId: subscription.id,
              stripePriceId: priceId,
              currentPeriodEnd,
              featuresJson: featuresForPrice(priceId),
            },
            update: {
              plan: planName(priceId),
              status,
              stripeSubscriptionId: subscription.id,
              stripePriceId: priceId,
              currentPeriodEnd,
              featuresJson: featuresForPrice(priceId),
            },
          });

          break;
        }

        case "invoice.payment_failed": {
          const invoice = event.data.object as Stripe.Invoice;
          const subscriptionId =
            typeof invoice.subscription === "string"
              ? invoice.subscription
              : invoice.subscription?.id;
          if (!subscriptionId) break;

          const subscription = await createStripeClient().subscriptions.retrieve(
            subscriptionId,
          );
          const userId = subscription.metadata?.userId;
          if (!userId) break;

          await prisma.subscriptionEntitlement
            .update({
              where: { userId },
              data: { status: "past_due" },
            })
            .catch(() => undefined);

          break;
        }

        case "customer.subscription.deleted": {
          const subscription = event.data.object as Stripe.Subscription;
          const userId = subscription.metadata?.userId;
          if (!userId) break;

          await prisma.subscriptionEntitlement
            .update({
              where: { userId },
              data: { status: "canceled" },
            })
            .catch(() => undefined);

          break;
        }

        case "customer.subscription.updated": {
          const subscription = event.data.object as Stripe.Subscription;
          const userId = subscription.metadata?.userId;
          if (!userId) break;

          const priceId = subscription.items.data[0]?.price?.id ?? null;
          const currentPeriodEnd = subscription.current_period_end
            ? new Date(subscription.current_period_end * 1000)
            : null;

          await prisma.subscriptionEntitlement.upsert({
            where: { userId },
            create: {
              userId,
              plan: priceId ? planName(priceId) : "Unknown",
              status: subscription.status,
              stripeSubscriptionId: subscription.id,
              stripePriceId: priceId ?? undefined,
              currentPeriodEnd,
              featuresJson: priceId ? featuresForPrice(priceId) : {},
            },
            update: {
              plan: priceId ? planName(priceId) : "Unknown",
              status: subscription.status,
              stripeSubscriptionId: subscription.id,
              stripePriceId: priceId ?? undefined,
              currentPeriodEnd,
              featuresJson: priceId ? featuresForPrice(priceId) : {},
            },
          });

          break;
        }

        default:
          break;
      }

      return res.status(200).json({ received: true });
    } catch (err: any) {
      return res
        .status(500)
        .json({ error: err?.message ?? "Webhook handler error" });
    }
  },
);

billing.post("/paypal/order", async (req, res, next) => {
  const paypalConfig = config.getPayPalConfig();
  if (!paypalConfig.enabled) {
    return res.status(503).json({ error: "PayPal not configured" });
  }

  if (!paypalConfig.returnUrl || !paypalConfig.cancelUrl) {
    return res
      .status(503)
      .json({ error: "PayPal return/cancel URLs not configured" });
  }

  const returnUrl = paypalConfig.returnUrl;
  const cancelUrl = paypalConfig.cancelUrl;
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
    const links = order?.result?.links;
    const approvalUrl = Array.isArray(links)
      ? (() => {
          const approveLink = links.find(
            (link: { rel: string; href?: unknown }) => link.rel === "approve",
          );
          return typeof approveLink?.href === "string"
            ? approveLink.href
            : null;
        })()
      : null;

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

  if (!/^[A-Za-z0-9-]+$/.test(orderId)) {
    return res.status(400).json({ error: "invalid orderId format" });
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
declare const module:
  | {
      exports?: unknown;
    }
  | undefined;
if (typeof module !== "undefined" && module?.exports) {
  module.exports = billing;
}
