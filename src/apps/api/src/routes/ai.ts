import { Router } from "express";
import { z } from "zod";
import { aiDecisionV1 } from "../ai/v1";
import { prisma } from "../db/prisma";
import { requireAuth } from "../middleware/auth";
import { driverCoach } from "../services/ai-engine/src/skills/driverCoach";
import { dispatchIntel } from "../services/ai-engine/src/skills/dispatchIntel";

export const ai = Router();
ai.post("/audit", (_, res) => res.json(aiDecisionV1()));

const driverCoachSchema = z.object({
  driverId: z.string(),
  event: z.object({
    lateMinutes: z.number().min(0).default(0),
    hardBrakes: z.number().min(0).default(0),
    dwellMinutes: z.number().min(0).optional(),
    routeId: z.string().optional(),
  }),
});

const dispatchSchema = z.object({
  route: z.object({
    id: z.string().optional(),
    trafficRisk: z.number().min(0).max(1), // Required field
    delayMinutes: z.number().optional(),
    etaMinutes: z.number().optional(),
    customerPriority: z.enum(["standard", "priority", "expedite"]).optional(),
  }),
  driver: z.object({
    id: z.string().optional(),
    name: z.string().optional(),
    safetyScore: z.number().min(0).max(1).optional(),
    utilization: z.number().min(0).max(1).optional(),
    currentLoad: z.number().min(0).optional(),
  }),
});

ai.post("/driver/coach", requireAuth, async (req, res) => {
  const parsed = driverCoachSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const result = await driverCoach(
    parsed.data.driverId,
    req.user!.organizationId,
    parsed.data.event,
  );

  return res.json({
    ...result,
    driverId: parsed.data.driverId,
    organizationId: req.user!.organizationId,
  });
});

ai.post("/dispatch/evaluate", requireAuth, async (req, res) => {
  const parsed = dispatchSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const result = dispatchIntel(
    parsed.data.route as any,
    parsed.data.driver as any,
  );
  const decision = await prisma.aiDecision.create({
    data: {
      organizationId: req.user!.organizationId,
      type: "dispatch:evaluate",
      confidence: result.confidence,
      rationale: JSON.stringify({
        route: parsed.data.route,
        driver: parsed.data.driver,
        recommendedNext: result.recommendedNext,
      }),
    },
  });

  return res.json({
    ...result,
    decisionId: decision.id,
    routeId: parsed.data.route.id ?? null,
    driverId: parsed.data.driver.id ?? null,
  });
});
