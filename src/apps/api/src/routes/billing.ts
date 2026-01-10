import { Router } from "express";
import Stripe from "stripe";
import paypal from "@paypal/checkout-server-sdk";
import config from "../config";
import { requireAuth, requireScope } from "../middleware/auth";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
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

// PRICING TIERS
const PLANS = {
  starter: {
    id: "starter",
    name: "Starter",
    monthlyPrice: 29900, // $299 in cents
    annualPrice: 29900 * 10, // 2 months free
    description: "10 active shipments, basic tracking",
    apiLimit: 100,
  },
  professional: {
    id: "professional",
    name: "Professional",
    monthlyPrice: 79900, // $799 in cents
    annualPrice: 79900 * 10,
    description: "Unlimited shipments, advanced features",
    apiLimit: 10000,
  },
  enterprise: {
    id: "enterprise",
    name: "Enterprise",
    monthlyPrice: 299900, // $2,999 in cents (custom)
    annualPrice: 299900 * 10,
    description: "Custom integrations, dedicated support",
    apiLimit: -1, // unlimited
  },
};

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

// ═══════════════════════════════════════════════════════════════════════════
// SUBSCRIPTION MANAGEMENT ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * POST /billing/checkout
 * Create a checkout session for subscription signup
 * Requires: tier (starter|professional|enterprise), billingCycle (monthly|annual)
 */
billing.post("/checkout", async (req, res, next) => {
  try {
    const { tier = "professional", billingCycle = "monthly" } = req.body;
    const userId = req.user?.sub as string;
    
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!PLANS[tier as keyof typeof PLANS]) {
      return res.status(400).json({ error: "Invalid tier" });
    }

    if (!["monthly", "annual"].includes(billingCycle)) {
      return res.status(400).json({ error: "Invalid billing cycle" });
    }

    const stripe = createStripeClient();
    const plan = PLANS[tier as keyof typeof PLANS];
    const price = billingCycle === "monthly" ? plan.monthlyPrice : plan.annualPrice;

    // Create Stripe checkout session
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: plan.name,
              description: plan.description,
            },
            unit_amount: price,
            recurring: {
              interval: billingCycle === "monthly" ? "month" : "year",
              interval_count: 1,
            },
          },
          quantity: 1,
        },
      ],
      success_url: `${config.get().WEB_URL}/billing/success?sessionId={CHECKOUT_SESSION_ID}`,
      cancel_url: `${config.get().WEB_URL}/pricing`,
      metadata: {
        userId,
        tier,
        billingCycle,
      },
      client_reference_id: userId,
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

/**
 * GET /billing/subscriptions
 * Get user's active subscriptions
 */
billing.get("/subscriptions", async (req, res, next) => {
  try {
    const organizationId = req.user?.org_id as string;
    
    if (!organizationId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const subscription = await prisma.subscription.findFirst({
      where: {
        organizationId,
        status: { in: ["active", "paused"] },
      },
    });

    return res.status(200).json({
      ok: true,
      subscription: subscription || null,
    });
  } catch (err) {
    return next(err);
  }
});

/**
 * POST /billing/webhook/stripe
 * Handle Stripe webhook events
 */
billing.post("/webhook/stripe", async (req, res, next) => {
  try {
    const stripe = createStripeClient();
    const sig = req.headers["stripe-signature"] as string;
    const stripeConfig = config.getStripeConfig();

    let event: Stripe.Event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        stripeConfig.webhookSecret,
      );
    } catch (err) {
      return res.status(400).json({ error: "Invalid signature" });
    }

    const { type, data } = event;
    const { object } = data;

    if (type === "checkout.session.completed") {
      const session = object as Stripe.Checkout.Session;
      const userId = session.client_reference_id;
      const metadata = session.metadata as Record<string, string>;

      if (!userId || !metadata) {
        return res.status(400).json({ error: "Missing metadata" });
      }

      // Create subscription in database
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const subscription = await prisma.subscription.create({
        data: {
          organizationId: user.organizationId,
          stripeCustomerId: session.customer as string,
          stripeSubId: session.subscription as string,
          tier: metadata.tier,
          priceMonthly: PLANS[metadata.tier as keyof typeof PLANS].monthlyPrice / 100,
          billingCycle: metadata.billingCycle,
          status: "active",
          isOnTrial: true,
          trialEndsAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
          currentPeriodStart: new Date(),
          currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        },
      });

      // Log revenue event
      await prisma.revenueEvent.create({
        data: {
          subscriptionId: subscription.id,
          organizationId: user.organizationId,
          eventType: "subscription_created",
          amount: subscription.priceMonthly,
          description: `${metadata.tier} subscription created`,
        },
      });
    }

    if (type === "invoice.payment_succeeded") {
      const invoice = object as Stripe.Invoice;
      const subscription = await prisma.subscription.findUnique({
        where: { stripeSubId: invoice.subscription as string },
      });

      if (subscription) {
        // Update subscription status
        await prisma.subscription.update({
          where: { id: subscription.id },
          data: {
            status: "active",
            isOnTrial: false,
          },
        });

        // Log revenue event
        await prisma.revenueEvent.create({
          data: {
            subscriptionId: subscription.id,
            organizationId: subscription.organizationId,
            eventType: "payment_succeeded",
            amount: (invoice.amount_paid || 0) / 100,
            description: "Payment successful",
          },
        });
      }
    }

    if (type === "invoice.payment_failed") {
      const invoice = object as Stripe.Invoice;
      const subscription = await prisma.subscription.findUnique({
        where: { stripeSubId: invoice.subscription as string },
      });

      if (subscription) {
        await prisma.subscription.update({
          where: { id: subscription.id },
          data: { status: "past_due" },
        });

        await prisma.revenueEvent.create({
          data: {
            subscriptionId: subscription.id,
            organizationId: subscription.organizationId,
            eventType: "payment_failed",
            description: "Payment failed - retry scheduled",
          },
        });
      }
    }

    if (type === "customer.subscription.deleted") {
      const sub = object as Stripe.Subscription;
      const subscription = await prisma.subscription.findUnique({
        where: { stripeSubId: sub.id },
      });

      if (subscription) {
        await prisma.subscription.update({
          where: { id: subscription.id },
          data: {
            status: "cancelled",
            cancelledAt: new Date(),
          },
        });

        await prisma.revenueEvent.create({
          data: {
            subscriptionId: subscription.id,
            organizationId: subscription.organizationId,
            eventType: "subscription_cancelled",
            description: "Subscription cancelled",
          },
        });
      }
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    return next(err);
  }
});

/**
 * GET /billing/revenue/metrics
 * Get revenue metrics for dashboard
 */
billing.get("/revenue/metrics", async (req, res, next) => {
  try {
    const organizationId = req.user?.org_id as string;

    if (!organizationId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get MRR
    const activeSubscriptions = await prisma.subscription.findMany({
      where: {
        organizationId,
        status: "active",
      },
    });

    const mrr = activeSubscriptions.reduce((sum, sub) => sum + sub.priceMonthly, 0);

    // Get churn rate (30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const cancelledCount = await prisma.subscription.count({
      where: {
        organizationId,
        status: "cancelled",
        cancelledAt: { gte: thirtyDaysAgo },
      },
    });

    const churnRate = activeSubscriptions.length > 0
      ? (cancelledCount / (activeSubscriptions.length + cancelledCount)) * 100
      : 0;

    // Get trial conversion rate
    const trials = await prisma.subscription.findMany({
      where: { organizationId, isOnTrial: true },
    });

    const conversions = await prisma.revenueEvent.count({
      where: {
        organizationId,
        eventType: "payment_succeeded",
        createdAt: { gte: thirtyDaysAgo },
      },
    });

    const conversionRate = trials.length > 0 ? (conversions / trials.length) * 100 : 0;

    // Get LTV
    const avgLifetime = 36; // 36 months
    const ltv = mrr > 0 ? (mrr * avgLifetime) : 0;

    // Get CAC
    const cac = 300; // $300 from GET_PAID_100_PERCENT.md

    return res.status(200).json({
      ok: true,
      metrics: {
        mrr: Math.round(mrr * 100) / 100,
        activeSubscriptions: activeSubscriptions.length,
        churnRate: Math.round(churnRate * 100) / 100,
        conversionRate: Math.round(conversionRate * 100) / 100,
        ltv: Math.round(ltv * 100) / 100,
        cac,
        ltvToCac: Math.round((ltv / cac) * 100) / 100,
      },
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
