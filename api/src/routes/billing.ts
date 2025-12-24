import { randomUUID } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { requireAuth } from "../middleware/auth";

const PLANS = {
  starter: {
    amountCents: 4900,
    currency: "usd",
    features: ["50 AI audits", "Voice commands", "Basic avatars"],
  },
  growth: {
    amountCents: 12900,
    currency: "usd",
    features: ["500 AI audits", "Route automation", "Avatar evolution"],
  },
  enterprise: {
    amountCents: 0,
    currency: "usd",
    features: ["Unlimited usage", "Dedicated SRE", "Custom compliance"],
  },
} as const;

type PlanId = keyof typeof PLANS;

const stripeSessionSchema = z.object({
  plan: z.enum(["starter", "growth", "enterprise"]).default("starter"),
  quantity: z.number().int().positive().max(100).default(1),
  successUrl: z.string().url().optional(),
  cancelUrl: z.string().url().optional(),
});

const paypalOrderSchema = z.object({
  plan: z.enum(["starter", "growth", "enterprise"]).default("starter"),
  quantity: z.number().int().positive().max(100).default(1),
  returnUrl: z.string().url().optional(),
  cancelUrl: z.string().url().optional(),
});

const paypalCaptureSchema = z.object({
  orderId: z.string().min(4, "orderId is required"),
  note: z.string().optional(),
});

function generateId(prefix: string) {
  return `${prefix}_${randomUUID().replace(/-/g, "").slice(0, 24)}`;
}

function sessionUrl(sessionId: string) {
  const base =
    process.env.STRIPE_CHECKOUT_URL ??
    "https://billing.stripe.com/p/test_checkout";
  return `${base}?session_id=${sessionId}`;
}

function paypalUrl(orderId: string) {
  const base =
    process.env.PAYPAL_APPROVAL_URL ??
    "https://www.sandbox.paypal.com/checkoutnow";
  return `${base}?token=${orderId}`;
}

export const billing = Router();

billing.use(requireAuth);

billing.post("/stripe/session", async (req, res) => {
  const parsed = stripeSessionSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const plan = PLANS[parsed.data.plan as PlanId];
  const amountCents =
    plan.amountCents > 0
      ? plan.amountCents * parsed.data.quantity
      : plan.amountCents;
  const sessionId = generateId("sess");

  await prisma.aiDecision.create({
    data: {
      organizationId: req.user.organizationId,
      type: "billing:stripe.session",
      confidence: 1,
      rationale: JSON.stringify({
        plan: parsed.data.plan,
        quantity: parsed.data.quantity,
        amountCents,
        userId: req.user.id,
      }),
    },
  });

  return res.status(201).json({
    ok: true,
    plan: parsed.data.plan,
    quantity: parsed.data.quantity,
    sessionId,
    url: sessionUrl(sessionId),
    amountCents,
    currency: plan.currency,
    features: plan.features,
    callbacks: {
      successUrl: parsed.data.successUrl,
      cancelUrl: parsed.data.cancelUrl,
    },
  });
});

billing.post("/paypal/order", async (req, res) => {
  const parsed = paypalOrderSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const plan = PLANS[parsed.data.plan];
  const orderId = generateId("order");
  const approvalUrl = paypalUrl(orderId);
  const amountCents =
    plan.amountCents > 0
      ? plan.amountCents * parsed.data.quantity
      : plan.amountCents;

  await prisma.aiDecision.create({
    data: {
      organizationId: req.user.organizationId,
      type: "billing:paypal.order",
      confidence: 1,
      rationale: JSON.stringify({
        orderId,
        plan: parsed.data.plan,
        quantity: parsed.data.quantity,
        amountCents,
        userId: req.user.id,
      }),
    },
  });

  return res.status(201).json({
    ok: true,
    orderId,
    approvalUrl,
    plan: parsed.data.plan,
    quantity: parsed.data.quantity,
    amountCents,
    currency: plan.currency,
    features: plan.features,
    callbacks: {
      returnUrl: parsed.data.returnUrl,
      cancelUrl: parsed.data.cancelUrl,
    },
  });
});

billing.post("/paypal/capture", async (req, res) => {
  const parsed = paypalCaptureSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const captureId = generateId("cap");

  await prisma.aiDecision.create({
    data: {
      organizationId: req.user.organizationId,
      type: "billing:paypal.capture",
      confidence: 1,
      rationale: JSON.stringify({
        captureId,
        orderId: parsed.data.orderId,
        note: parsed.data.note,
        userId: req.user.id,
      }),
    },
  });

  return res.json({
    ok: true,
    captureId,
    orderId: parsed.data.orderId,
    status: "captured",
    note: parsed.data.note,
  });
});
