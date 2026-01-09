import express, { Router } from "express";
import Stripe from "stripe";
import config from "../config";
import { prisma } from "../db/prisma";
import { requireAuth, requireScope } from "../middleware/auth";

const stripeApiVersion = "2024-06-20" as Stripe.LatestApiVersion;

function createStripeClient() {
  const stripeConfig = config.getStripeConfig();
  return new Stripe(stripeConfig.secretKey, { apiVersion: stripeApiVersion });
}

function requireUserId(req: express.Request) {
  const headerUserId = req.header("x-user-id");
  if (headerUserId) {
    return headerUserId;
  }

  const userId = req.user?.id;
  if (!userId) {
    throw new Error("Missing x-user-id header or authenticated user context.");
  }
  return userId;
}

const billingPortalRouter = Router();

billingPortalRouter.use(requireAuth);
billingPortalRouter.use(requireScope("billing:write"));

billingPortalRouter.post("/portal", async (req, res) => {
  const stripeConfig = config.getStripeConfig();
  if (!stripeConfig.enabled) {
    return res.status(503).json({ error: "Stripe not configured" });
  }

  const appUrl = config.getEnv("APP_URL", "");
  const returnUrl = config.getEnv(
    "STRIPE_PORTAL_RETURN_URL",
    appUrl ? `${appUrl}/billing` : "",
  );

  if (!returnUrl) {
    return res
      .status(503)
      .json({ error: "Stripe portal return URL not configured" });
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

    const session = await stripeClient.billingPortal.sessions.create({
      customer: stripeCustomer.stripeCustomerId,
      return_url: returnUrl,
    });

    return res.status(200).json({ url: session.url });
  } catch (error: any) {
    return res.status(500).json({ error: error?.message ?? "Unknown error" });
  }
});

export default billingPortalRouter;
