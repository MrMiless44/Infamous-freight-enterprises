/**
 * Driver Coach AI Role
 *
 * Provides driving behavior analysis, safety coaching, efficiency recommendations,
 * and performance tracking for drivers.
 */

import type {
  RoleContract,
  DecisionInput,
  DecisionResult,
  RoleContext,
  ConfidenceScore,
  GuardrailViolation,
} from "../contracts";
import { logDecision } from "../observability/logger";

/**
 * Helper: Generate coaching recommendation
 */
async function generateCoachingRecommendation(
  input: DecisionInput,
): Promise<Record<string, unknown>> {
  const params = input.parameters;
  const driverData = params.driverData || {};
  const behaviorMetrics = params.behaviorMetrics || {};

  // Analyze driving patterns
  const currentMPG = behaviorMetrics.fuelEfficiency || 6.2;
  const hardBrakingEvents = behaviorMetrics.hardBraking || 0;
  const rapidAcceleration = behaviorMetrics.rapidAcceleration || 0;
  const speedingEvents = behaviorMetrics.speeding || 0;
  const idlingTime = behaviorMetrics.idlingMinutes || 0;

  // Calculate target improvements
  const industryBenchmarkMPG = 7.5;
  const mpgGap = industryBenchmarkMPG - currentMPG;
  const potentialSavings = mpgGap * 15000 * 3.85; // 15k miles/year, $3.85/gal

  // Determine primary coaching focus
  let coachingType = "fuel-efficiency";
  let severity = "low";
  let message = "";
  let actionItems: string[] = [];

  if (speedingEvents > 10) {
    coachingType = "safety-critical";
    severity = "high";
    message = `${speedingEvents} speeding events detected this month. Speeding increases accident risk by 4x and fuel consumption by 20%.`;
    actionItems = [
      "Review speed limit awareness training",
      "Enable speed limit warnings in vehicle",
      "Schedule one-on-one safety review with supervisor",
      "Monitor speed compliance daily for next 2 weeks",
    ];
  } else if (hardBrakingEvents > 15) {
    coachingType = "safety-moderate";
    severity = "medium";
    message = `${hardBrakingEvents} hard braking events indicate following too closely or not anticipating traffic.`;
    actionItems = [
      "Practice 3-4 second following distance",
      "Review defensive driving techniques",
      "Watch traffic flow video training (15 min)",
      "Reduce hard braking by 50% in next 30 days",
    ];
  } else if (rapidAcceleration > 20) {
    coachingType = "fuel-efficiency";
    severity = "medium";
    message = `${rapidAcceleration} rapid acceleration events waste fuel and wear brakes. Smoother driving saves $200+/month.`;
    actionItems = [
      "Practice gradual acceleration (10-15 sec to speed)",
      "Use cruise control on highways",
      "Anticipate traffic lights and slowdowns",
      "Target 10% reduction in rapid acceleration",
    ];
  } else if (idlingTime > 60) {
    coachingType = "fuel-efficiency";
    severity = "low";
    message = `${idlingTime} minutes of idling wastes fuel and increases engine wear.`;
    actionItems = [
      "Turn off engine for stops over 3 minutes",
      "Use APU for cab climate control",
      "Plan rest stops at truck stops with amenities",
      "Reduce idling to under 30 min/day",
    ];
  } else {
    coachingType = "performance-excellence";
    severity = "low";
    message =
      "Excellent driving performance! Keep up the safe and efficient habits.";
    actionItems = [
      "Continue current driving practices",
      "Consider mentoring newer drivers",
      "Track for quarterly performance bonus",
    ];
  }

  return {
    coachingType,
    severity,
    message,
    actionItems,
    targetMetrics: {
      currentMPG: currentMPG.toFixed(1),
      targetMPG: industryBenchmarkMPG.toFixed(1),
      potentialSavings: `$${Math.round(potentialSavings)}/year`,
      improvementOpportunity: `${((mpgGap / currentMPG) * 100).toFixed(0)}%`,
    },
    behaviorScores: {
      safety: Math.max(0, 100 - speedingEvents * 2 - hardBrakingEvents),
      efficiency: Math.max(0, 100 - rapidAcceleration * 0.5 - idlingTime * 0.3),
      overall: Math.round(
        (100 -
          speedingEvents * 2 -
          hardBrakingEvents +
          100 -
          rapidAcceleration * 0.5) /
          2,
      ),
    },
    recommendedTraining:
      severity === "high"
        ? "Immediate safety refresher required"
        : "Optional efficiency workshop available",
  };
}

/**
 * Driver Coach AI Role Implementation
 */
export const driverCoachRole: RoleContract = {
  name: "driver-coach",
  version: "1.0.0",
  description:
    "AI role for driver coaching, safety analysis, and performance improvement recommendations",
  confidenceThreshold: 0.8,
  capabilities: [
    "driving-behavior-analysis",
    "safety-coaching",
    "efficiency-recommendations",
    "performance-tracking",
    "training-suggestions",
  ],

  async decide(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<DecisionResult> {
    const decisionId = `coach-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const violations = await this.checkGuardrails(input, context);
    const confidence = await this.calculateConfidence(input, context);
    const recommendation = await generateCoachingRecommendation(input);

    await logDecision({
      decisionId,
      timestamp: context.timestamp,
      role: this.name,
      userId: context.userId,
      requestId: context.requestId,
      action: input.action,
      input: input.parameters,
      confidence,
      recommendation,
      requiresHumanReview: confidence.value < this.confidenceThreshold,
    });

    return {
      decisionId,
      confidence,
      recommendation,
      requiresHumanReview: confidence.value < this.confidenceThreshold,
      guardrailViolations: violations,
    };
  },

  async checkGuardrails(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<GuardrailViolation[]> {
    const violations: GuardrailViolation[] = [];

    // Cannot initiate disciplinary actions
    if (
      input.action.includes("discipline") ||
      input.action.includes("terminate")
    ) {
      violations.push({
        type: "policy",
        severity: "critical",
        description: "Driver Coach AI cannot initiate disciplinary actions",
        remediation: "Escalate to human HR/management",
      });
    }

    // Cannot access personal driver information beyond performance data
    const personalFields = ["ssn", "address", "medical", "salary", "personal"];
    if (
      personalFields.some((field) =>
        JSON.stringify(input).toLowerCase().includes(field),
      )
    ) {
      violations.push({
        type: "data-access",
        severity: "high",
        description: "Attempted to access personal driver information",
        remediation: "Limit to performance and operational data only",
      });
    }

    return violations;
  },

  async calculateConfidence(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<ConfidenceScore> {
    const params = input.parameters;
    const behaviorMetrics = params.behaviorMetrics || {};
    const driverHistory = params.driverHistory || {};

    // Data quality assessment
    let dataQuality = 0.5;
    const dataPoints = [
      "fuelEfficiency",
      "hardBraking",
      "rapidAcceleration",
      "speeding",
      "idlingMinutes",
    ];
    const availableDataPoints = dataPoints.filter(
      (key) => behaviorMetrics[key] !== undefined,
    );
    dataQuality = availableDataPoints.length / dataPoints.length;

    // Data freshness
    const dataAge =
      Date.now() - (params.dataTimestamp || context.timestamp.getTime());
    const freshnessScore = dataAge < 86400000 ? 1.0 : 0.8; // < 24 hours

    // Historical data completeness
    const historicalCompleteness =
      driverHistory.tripsAnalyzed > 50
        ? 1.0
        : driverHistory.tripsAnalyzed > 20
          ? 0.85
          : 0.7;

    // Model certainty (coaching models are well-established)
    const modelCertainty = 0.88;

    // Historical coaching effectiveness
    const historicalAccuracy = driverHistory.coachingImprovementRate || 0.75;

    // Calculate weighted confidence
    const confidence =
      dataQuality * 0.3 +
      freshnessScore * 0.15 +
      historicalCompleteness * 0.2 +
      modelCertainty * 0.2 +
      historicalAccuracy * 0.15;

    const reasoningParts = [];
    if (dataQuality < 0.7) reasoningParts.push("limited behavior data");
    if (freshnessScore < 1.0) reasoningParts.push("data older than 24h");
    if (historicalCompleteness < 0.85)
      reasoningParts.push("insufficient trip history");
    if (historicalAccuracy < 0.8)
      reasoningParts.push("variable coaching response");

    return {
      value: Math.min(0.95, confidence),
      reasoning:
        reasoningParts.length > 0
          ? `Confidence based on ${reasoningParts.join(", ")}`
          : "High quality driving data with strong historical coaching effectiveness",
      factors: {
        dataQuality: Number(dataQuality.toFixed(2)),
        dataFreshness: freshnessScore,
        historicalCompleteness,
        modelCertainty,
        historicalAccuracy,
      },
    };
  },
};

export default driverCoachRole;
