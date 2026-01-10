/**
 * Dispatch Operator AI Role
 *
 * Handles route optimization, load assignments, real-time dispatching,
 * and delay prediction for freight operations.
 */

import type {
  RoleContract,
  DecisionInput,
  DecisionResult,
  RoleContext,
  ConfidenceScore,
  GuardrailViolation,
} from "../contracts";
import {
  logDecision,
  logConfidence,
  logGuardrailViolations,
} from "../observability/logger";

/**
 * Helper: Check if input involves billing data
 */
function involvesBillingData(input: DecisionInput): boolean {
  const billingFields = [
    "payment",
    "invoice",
    "billing",
    "price",
    "rate",
    "cost",
  ];
  const inputString = JSON.stringify(input).toLowerCase();
  return billingFields.some((field) => inputString.includes(field));
}

/**
 * Helper: Check if proposed dispatch violates hours-of-service
 */
async function violatesHoursOfService(input: DecisionInput): Promise<boolean> {
  // HOS validation based on FMCSA regulations (49 CFR Part 395)
  const driverId = input.parameters.driverId;
  const proposedDuration = input.parameters.estimatedHours || 0;

  if (!driverId || proposedDuration <= 0) {
    return false; // Cannot validate without required data
  }

  // Fetch driver's current hours (in production, this would query the database)
  const driverHours = {
    dailyDriving: input.parameters.currentDailyHours || 0,
    weeklyDriving: input.parameters.currentWeeklyHours || 0,
    dailyOnDuty: input.parameters.currentDailyOnDuty || 0,
    consecutiveDays: input.parameters.consecutiveDaysWorked || 0,
  };

  // FMCSA HOS limits:
  // - 11 hours max driving after 10 consecutive hours off duty
  // - 14 hours max on-duty after 10 consecutive hours off duty
  // - 60/70 hour rule (60 hours in 7 days or 70 hours in 8 days)
  const MAX_DAILY_DRIVING = 11;
  const MAX_WEEKLY_DRIVING = 60; // Using 7-day cycle
  const MAX_DAILY_ON_DUTY = 14;

  // Check if proposed dispatch would exceed daily driving limit
  if (driverHours.dailyDriving + proposedDuration > MAX_DAILY_DRIVING) {
    return true;
  }

  // Check if proposed dispatch would exceed weekly limit
  if (driverHours.weeklyDriving + proposedDuration > MAX_WEEKLY_DRIVING) {
    return true;
  }

  // Check if driver has worked 7+ consecutive days without 34-hour reset
  if (driverHours.consecutiveDays >= 7) {
    return true;
  }

  return false;
}

/**
 * Helper: Check if input accesses personal driver data
 */
function accessesPersonalDriverData(input: DecisionInput): boolean {
  const personalFields = ["ssn", "address", "medical", "personal", "salary"];
  const inputString = JSON.stringify(input).toLowerCase();
  return personalFields.some((field) => inputString.includes(field));
}

/**
 * Helper: Generate recommendation for the dispatch action
 */
async function generateRecommendation(
  input: DecisionInput,
  context: RoleContext,
): Promise<Record<string, unknown>> {
  // Production recommendation generation with real-world factors
  const params = input.parameters;
  const currentHour = new Date(context.timestamp).getHours();
  const isRushHour =
    (currentHour >= 7 && currentHour <= 9) ||
    (currentHour >= 16 && currentHour <= 18);

  switch (input.action) {
    case "route-optimization": {
      const origin = params.origin;
      const destination = params.destination;
      const distance = params.distance || 250;

      // Calculate time with traffic multiplier
      const baseTime = distance / 55; // 55 mph average
      const trafficMultiplier = isRushHour ? 1.4 : 1.0;
      const weatherMultiplier = params.weatherCondition === "poor" ? 1.3 : 1.0;
      const estimatedTime = baseTime * trafficMultiplier * weatherMultiplier;

      // Fuel calculation (6.5 MPG average for heavy trucks)
      const fuelGallons = distance / 6.5;
      const fuelCost = fuelGallons * (params.fuelPrice || 3.85);

      return {
        optimizedRoute: `route-${Date.now()}`,
        waypoints: [origin, destination],
        estimatedTime: `${estimatedTime.toFixed(1)} hours`,
        estimatedDistance: `${distance} miles`,
        fuelEstimate: `${fuelGallons.toFixed(1)} gallons`,
        estimatedCost: `$${fuelCost.toFixed(2)}`,
        trafficConditions: isRushHour ? "heavy" : "moderate",
        avoidTolls: params.avoidTolls || false,
        reasoning: `Route optimized for ${params.priority || "balanced"} considering traffic and weather`,
      };
    }

    case "load-assignment": {
      // Find best driver based on proximity, availability, and capacity
      const shipment = params.shipment;
      const availableDrivers = params.availableDrivers || [];

      // Score drivers (0-100)
      const scoredDrivers = availableDrivers.map((driver: any) => {
        let score = 50;

        // Proximity bonus (max +30)
        const proximityMiles = driver.distanceToPickup || 100;
        score += Math.max(0, 30 - proximityMiles / 10);

        // Availability bonus (max +20)
        const remainingHours = 11 - (driver.hoursToday || 0);
        score += (remainingHours / 11) * 20;

        // Experience bonus (max +10)
        score += Math.min(10, (driver.tripsCompleted || 0) / 100);

        // Vehicle capacity match (+10 if exact match)
        if (driver.vehicleCapacity >= shipment.weight) {
          score += 10;
        }

        return { ...driver, score };
      });

      const bestDriver = scoredDrivers.sort(
        (a: any, b: any) => b.score - a.score,
      )[0];

      return {
        assignedDriver: bestDriver?.id || "auto-assign",
        driverName: bestDriver?.name || "TBD",
        vehicle: bestDriver?.vehicleId || "TBD",
        pickupTime: params.requestedPickupTime || "08:00",
        score: bestDriver?.score.toFixed(1) || "N/A",
        proximityMiles: bestDriver?.distanceToPickup || "N/A",
        availableHours: (11 - (bestDriver?.hoursToday || 0)).toFixed(1),
        reasoning: `Best match based on proximity (${bestDriver?.distanceToPickup || "N/A"} miles), ${(11 - (bestDriver?.hoursToday || 0)).toFixed(1)}hrs available, and ${bestDriver?.tripsCompleted || 0} completed trips`,
      };
    }

    case "delay-prediction": {
      // Predict delay probability based on multiple factors
      const route = params.route;
      const weatherCondition = params.weatherCondition || "clear";
      const trafficDensity = isRushHour ? "high" : "low";

      let delayProbability = 0.05; // Base 5% delay risk
      const delayFactors: string[] = [];

      // Weather impact
      if (weatherCondition === "rain") {
        delayProbability += 0.15;
        delayFactors.push("Rainy conditions expected");
      } else if (weatherCondition === "snow") {
        delayProbability += 0.35;
        delayFactors.push("Snow/ice conditions expected");
      }

      // Traffic impact
      if (isRushHour) {
        delayProbability += 0.2;
        delayFactors.push("Peak traffic hours");
      }

      // Historical route performance
      if (params.historicalDelayRate && params.historicalDelayRate > 0.2) {
        delayProbability += 0.1;
        delayFactors.push("Route has history of delays");
      }

      // Construction/road closures
      if (params.roadClosures) {
        delayProbability += 0.25;
        delayFactors.push("Road construction reported");
      }

      const estimatedDelayMinutes = Math.round(delayProbability * 90);

      return {
        delayProbability: Math.min(0.95, delayProbability).toFixed(2),
        estimatedDelay: `${estimatedDelayMinutes} minutes`,
        confidence: (1 - delayProbability * 0.3).toFixed(2),
        factors: delayFactors,
        recommendation:
          delayProbability > 0.3
            ? "Notify customer proactively and consider alternative route"
            : "Monitor conditions but proceed as planned",
        alternativeRouteAvailable: params.hasAlternativeRoute || false,
      };
    }

    case "carrier-selection": {
      // Select optimal carrier based on cost, reliability, and capacity
      const carriers = params.availableCarriers || [];

      const rankedCarriers = carriers.map((carrier: any) => {
        let score = 0;

        // Cost efficiency (40% weight)
        const costScore =
          100 - ((carrier.rate - params.minRate) / params.minRate) * 100;
        score += costScore * 0.4;

        // Reliability (30% weight)
        score += (carrier.onTimeRate || 0.9) * 100 * 0.3;

        // Capacity availability (20% weight)
        score += carrier.availableCapacity >= params.requiredCapacity ? 20 : 0;

        // Insurance coverage (10% weight)
        score += carrier.insuranceCoverage >= params.cargoValue ? 10 : 0;

        return { ...carrier, score };
      });

      const topCarrier = rankedCarriers.sort(
        (a: any, b: any) => b.score - a.score,
      )[0];

      return {
        selectedCarrier: topCarrier?.id || "manual-selection-required",
        carrierName: topCarrier?.name || "TBD",
        rate: topCarrier?.rate || "N/A",
        onTimeRate: `${((topCarrier?.onTimeRate || 0.9) * 100).toFixed(1)}%`,
        insuranceCoverage: topCarrier?.insuranceCoverage || "N/A",
        score: topCarrier?.score.toFixed(1) || "N/A",
        reasoning: `Selected for optimal balance of cost ($${topCarrier?.rate}), reliability (${((topCarrier?.onTimeRate || 0.9) * 100).toFixed(1)}% on-time), and capacity`,
      };
    }

    default:
      return {
        message: `Action '${input.action}' not implemented`,
        supportedActions: [
          "route-optimization",
          "load-assignment",
          "delay-prediction",
          "carrier-selection",
        ],
      };
  }
}

/**
 * Dispatch Operator AI Role Implementation
 */
export const dispatchRole: RoleContract = {
  name: "dispatch-operator",
  version: "1.0.0",
  description:
    "AI role for autonomous dispatch operations, route optimization, and load assignments",
  confidenceThreshold: 0.85,
  capabilities: [
    "route-optimization",
    "load-assignment",
    "delay-prediction",
    "carrier-selection",
    "real-time-dispatching",
  ],

  /**
   * Main decision-making function for dispatch operations
   */
  async decide(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<DecisionResult> {
    const decisionId = `dispatch-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    try {
      // Step 1: Check guardrails
      const violations = await this.checkGuardrails(input, context);

      if (violations.length > 0) {
        await logGuardrailViolations(decisionId, this.name, violations);

        // Guardrail violations always trigger escalation to human review
        return {
          decisionId,
          confidence: { value: 0, reasoning: "Guardrail violations detected" },
          recommendation: { blocked: true, violations },
          requiresHumanReview: true,
          guardrailViolations: violations,
        };
      }

      // Step 2: Calculate confidence
      const confidence = await this.calculateConfidence(input, context);
      await logConfidence(decisionId, this.name, confidence);

      // Step 3: Generate recommendation
      const recommendation = await generateRecommendation(input, context);

      // Step 4: Determine if human review is needed
      const requiresHumanReview = confidence.value < this.confidenceThreshold;

      // Step 5: Create result
      const result: DecisionResult = {
        decisionId,
        confidence,
        recommendation,
        requiresHumanReview,
        guardrailViolations: [],
        metadata: {
          role: this.name,
          action: input.action,
          timestamp: context.timestamp,
        },
      };

      // Step 6: Log the decision
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
        requiresHumanReview,
      });

      return result;
    } catch (error) {
      // On error, escalate to human
      console.error("[Dispatch Role Error]", error);

      return {
        decisionId,
        confidence: { value: 0, reasoning: "Error during decision processing" },
        recommendation: {
          error: true,
          message: "Failed to process dispatch decision",
        },
        requiresHumanReview: true,
        guardrailViolations: [],
        metadata: {
          error: error instanceof Error ? error.message : "Unknown error",
        },
      };
    }
  },

  /**
   * Check if the proposed action violates any guardrails
   */
  async checkGuardrails(
    input: DecisionInput,
    _context: RoleContext,
  ): Promise<GuardrailViolation[]> {
    const violations: GuardrailViolation[] = [];

    // Guardrail 1: Cannot access billing data
    if (involvesBillingData(input)) {
      violations.push({
        type: "boundary",
        severity: "critical",
        description: "Dispatch role attempted to access billing data",
        remediation: "Remove billing-related parameters from request",
      });
    }

    // Guardrail 2: Cannot override human decisions without approval
    if (
      input.action === "override-dispatch" &&
      !input.parameters.humanApproval
    ) {
      violations.push({
        type: "policy",
        severity: "high",
        description:
          "Cannot override human dispatch decisions without explicit approval",
        remediation: "Obtain human approval before overriding dispatch",
      });
    }

    // Guardrail 3: Cannot violate hours-of-service regulations
    if (await violatesHoursOfService(input)) {
      violations.push({
        type: "safety",
        severity: "critical",
        description:
          "Proposed dispatch would violate hours-of-service regulations",
        remediation:
          "Adjust route or select different driver within compliance limits",
      });
    }

    // Guardrail 4: Cannot access personal driver information beyond operational needs
    if (accessesPersonalDriverData(input)) {
      violations.push({
        type: "data-access",
        severity: "high",
        description:
          "Attempted to access personal driver information beyond operational scope",
        remediation: "Limit data access to operational information only",
      });
    }

    return violations;
  },

  /**
   * Calculate confidence score for a dispatch decision
   */
  async calculateConfidence(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<ConfidenceScore> {
    // Multi-factor confidence calculation based on real-world metrics
    const params = input.parameters;

    // Factor 1: Data Quality (0-1)
    let dataQuality = 1.0;
    const requiredFields = ["origin", "destination", "shipmentId"];
    const missingFields = requiredFields.filter((field) => !params[field]);
    dataQuality -= missingFields.length * 0.15;

    // Check data freshness
    const dataAge =
      Date.now() - (params.dataTimestamp || context.timestamp.getTime());
    if (dataAge > 3600000) dataQuality -= 0.1; // Older than 1 hour

    // Factor 2: Model Certainty (based on action type)
    const modelCertainty: Record<string, number> = {
      "route-optimization": 0.92,
      "load-assignment": 0.88,
      "delay-prediction": 0.75,
      "carrier-selection": 0.85,
      "real-time-dispatching": 0.8,
    };
    const modelScore = modelCertainty[input.action] || 0.7;

    // Factor 3: Historical Accuracy (simulated from historical performance)
    const historicalAccuracy = params.historicalAccuracy || 0.87;

    // Factor 4: Context Completeness
    let contextCompleteness = 0.5;
    if (params.weatherCondition) contextCompleteness += 0.15;
    if (params.trafficData) contextCompleteness += 0.15;
    if (params.driverHistory) contextCompleteness += 0.1;
    if (params.vehicleData) contextCompleteness += 0.1;

    // Factor 5: Temporal factors (time-sensitive)
    const currentHour = new Date(context.timestamp).getHours();
    const isBusinessHours = currentHour >= 8 && currentHour <= 18;
    const temporalReliability = isBusinessHours ? 1.0 : 0.9;

    // Factor 6: External conditions
    let externalConditionsScore = 1.0;
    if (params.weatherCondition === "severe") externalConditionsScore -= 0.2;
    if (params.roadClosures) externalConditionsScore -= 0.15;

    // Weighted calculation
    const weights = {
      dataQuality: 0.25,
      modelCertainty: 0.25,
      historicalAccuracy: 0.2,
      contextCompleteness: 0.15,
      temporalReliability: 0.1,
      externalConditions: 0.05,
    };

    const finalConfidence = Math.max(
      0,
      Math.min(
        1,
        dataQuality * weights.dataQuality +
          modelScore * weights.modelCertainty +
          historicalAccuracy * weights.historicalAccuracy +
          contextCompleteness * weights.contextCompleteness +
          temporalReliability * weights.temporalReliability +
          externalConditionsScore * weights.externalConditions,
      ),
    );

    // Generate detailed reasoning
    const reasoningParts = [];
    if (dataQuality < 0.8) reasoningParts.push("incomplete data");
    if (modelScore >= 0.9) reasoningParts.push("high model certainty");
    if (historicalAccuracy >= 0.85)
      reasoningParts.push("strong historical performance");
    if (contextCompleteness < 0.7) reasoningParts.push("limited context");
    if (!isBusinessHours) reasoningParts.push("outside business hours");

    const reasoning =
      reasoningParts.length > 0
        ? `Confidence affected by: ${reasoningParts.join(", ")}`
        : "All factors indicate high confidence";

    return {
      value: finalConfidence,
      reasoning,
      factors: {
        dataQuality: Number(dataQuality.toFixed(2)),
        modelCertainty: modelScore,
        historicalAccuracy,
        contextCompleteness: Number(contextCompleteness.toFixed(2)),
        temporalReliability,
        externalConditions: Number(externalConditionsScore.toFixed(2)),
      },
    };
  },
};

/**
 * Export as default for easy importing
 */
export default dispatchRole;
