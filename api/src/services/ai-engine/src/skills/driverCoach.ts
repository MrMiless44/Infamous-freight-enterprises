import { prisma } from "../../../../db/prisma";

type DriverEvent = {
  lateMinutes?: number;
  hardBrakes?: number;
  dwellMinutes?: number;
  routeId?: string;
};

type DriverCoachResult = {
  type: "COACHING";
  message: string;
  confidenceImpact: number;
  tone: "positive" | "caution" | "urgent";
  memoryKey: string;
  decisionId: string;
};

function selectCoaching(event: DriverEvent): Omit<
  DriverCoachResult,
  "type" | "memoryKey"
> {
  const lateMinutes = event.lateMinutes ?? 0;
  const hardBrakes = event.hardBrakes ?? 0;
  const dwellMinutes = event.dwellMinutes ?? 0;

  if (hardBrakes > 3) {
    return {
      message: "Drive smoother to improve safety score.",
      confidenceImpact: 0.2,
      tone: "caution",
    };
  }

  if (lateMinutes > 15) {
    return {
      message: "You're running late. Reduce idle time at the next stop.",
      confidenceImpact: 0.18,
      tone: "urgent",
    };
  }

  if (lateMinutes > 7 || dwellMinutes > 10) {
    return {
      message:
        "Trend a tighter schedule on the next leg—minimize idle and keep pace.",
      confidenceImpact: 0.14,
      tone: "caution",
    };
  }

  return {
    message: "Good job maintaining schedule.",
    confidenceImpact: 0.1,
    tone: "positive",
  };
}

export async function driverCoach(
  driverId: string,
  organizationId: string,
  event: DriverEvent,
): Promise<DriverCoachResult> {
  const memoryKey = "driver:coaching:last";
  const prior = await prisma.avatarMemory.findFirst({
    where: { userId: driverId, organizationId, key: memoryKey },
    orderBy: { createdAt: "desc" },
  });

  const coaching = selectCoaching(event);

  let decisionId: string | undefined;

  if (prior) {
    await prisma.avatarMemory.update({
      where: { id: prior.id },
      data: { value: coaching.message, confidence: coaching.confidenceImpact },
    });
  } else {
    await prisma.avatarMemory.create({
      data: {
        userId: driverId,
        organizationId,
        category: "coaching",
        key: memoryKey,
        value: coaching.message,
        confidence: coaching.confidenceImpact,
        pinned: true,
      },
    });
  }

  const decision = await prisma.aiDecision.create({
    data: {
      organizationId,
      type: "driver:coaching",
      confidence: coaching.confidenceImpact,
      rationale: JSON.stringify({
        event,
        routeId: event.routeId,
        tone: coaching.tone,
        memoryKey,
      }),
    },
  });
  decisionId = decision.id;

  return {
    type: "COACHING",
    memoryKey,
    decisionId,
    ...coaching,
  };
}
