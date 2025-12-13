const express = require("express");
const { PrismaClient } = require("@prisma/client");
const {
  getPricingTiers,
  calculateUsageCost,
  createStripeSubscription,
  getOrCreateStripeCustomer,
  recordUsage,
} = require("../services/payments");

const router = express.Router();
const prisma = new PrismaClient();

/**
 * GET /api/billing/pricing
 * Get current pricing tiers for 2025
 */
router.get("/billing/pricing", (req, res) => {
  const tiers = getPricingTiers();
  res.json({
    ok: true,
    tiers: Object.values(tiers),
    currency: "usd",
    updated: "2025-12-05",
  });
});

/**
 * POST /api/billing/subscribe
 * Create a new subscription
 */
router.post("/billing/subscribe", async (req, res) => {
  const { email, name, tierId } = req.body;

  if (!email || !tierId) {
    return res.status(400).json({ error: "email and tierId required" });
  }

  try {
    const tiers = getPricingTiers();
    const tier = tiers[tierId];

    if (!tier) {
      return res.status(400).json({ error: "Invalid tier" });
    }

    // Get or create Stripe customer
    const customer = await getOrCreateStripeCustomer({
      email,
      name: name || email.split("@")[0],
      metadata: { tier: tierId },
    });

    // Note: You'll need to create price IDs in Stripe dashboard first
    // For now, return the tier info
    res.json({
      ok: true,
      message: "Subscription initiated",
      tier,
      customerId: customer.id,
      nextSteps: [
        "Complete Stripe setup",
        "Redirect to checkout",
        "Activate subscription",
      ],
    });
  } catch (err) {
    console.error("Subscription error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/billing/usage
 * Record usage for metered billing
 */
router.post("/billing/usage", async (req, res) => {
  const { userId, type, quantity } = req.body;

  if (!userId || !type || !quantity) {
    return res.status(400).json({
      error: "userId, type, and quantity required",
    });
  }

  const validTypes = ["shipment", "aiOptimization", "voiceMinute", "apiCall"];
  if (!validTypes.includes(type)) {
    return res.status(400).json({
      error: `type must be one of: ${validTypes.join(", ")}`,
    });
  }

  try {
    // Record usage in database
    await prisma.aiEvent.create({
      data: {
        type: `usage:${type}`,
        payload: {
          userId,
          quantity,
          timestamp: new Date().toISOString(),
        },
      },
    });

    res.json({
      ok: true,
      recorded: type,
      quantity,
      userId,
    });
  } catch (err) {
    console.error("Usage recording error:", err);
    res.status(500).json({ error: "Failed to record usage" });
  }
});

/**
 * GET /api/billing/usage/:userId
 * Get usage statistics for a user
 */
router.get("/billing/usage/:userId", async (req, res) => {
  const { userId } = req.params;
  const { startDate, endDate } = req.query;

  try {
    // Get usage events from database
    const events = await prisma.aiEvent.findMany({
      where: {
        type: { startsWith: "usage:" },
        payload: {
          path: ["userId"],
          equals: userId,
        },
        ...(startDate && {
          createdAt: { gte: new Date(startDate) },
        }),
        ...(endDate && {
          createdAt: { lte: new Date(endDate) },
        }),
      },
      orderBy: { createdAt: "desc" },
    });

    // Aggregate usage
    const usage = {
      shipments: 0,
      aiOptimizations: 0,
      voiceMinutes: 0,
      apiCalls: 0,
    };

    events.forEach((event) => {
      const type = event.type.replace("usage:", "");
      const quantity = event.payload?.quantity || 0;

      if (type === "shipment") usage.shipments += quantity;
      else if (type === "aiOptimization") usage.aiOptimizations += quantity;
      else if (type === "voiceMinute") usage.voiceMinutes += quantity;
      else if (type === "apiCall") usage.apiCalls += quantity;
    });

    const cost = calculateUsageCost(usage);

    res.json({
      ok: true,
      userId,
      period: {
        start: startDate || "billing_cycle_start",
        end: endDate || "now",
      },
      usage,
      cost,
    });
  } catch (err) {
    console.error("Usage retrieval error:", err);
    res.status(500).json({ error: "Failed to retrieve usage" });
  }
});

/**
 * GET /api/billing/estimate
 * Calculate cost estimate for given usage
 */
router.get("/billing/estimate", (req, res) => {
  const usage = {
    shipments: parseInt(req.query.shipments) || 0,
    aiOptimizations: parseInt(req.query.aiOptimizations) || 0,
    voiceMinutes: parseInt(req.query.voiceMinutes) || 0,
    apiCalls: parseInt(req.query.apiCalls) || 0,
  };

  const cost = calculateUsageCost(usage);

  res.json({
    ok: true,
    usage,
    cost,
    note: "This is an estimate. Actual charges may vary.",
  });
});

module.exports = router;
