/**
 * Fleet Intelligence AI Role
 *
 * Handles predictive maintenance, fuel optimization, asset tracking,
 * and vehicle health monitoring for the fleet.
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
 * Helper: Generate fleet recommendation
 */
async function generateFleetRecommendation(
  input: DecisionInput,
): Promise<Record<string, unknown>> {
  const params = input.parameters;
  const vehicleData = params.vehicleData || {};
  const telemetry = params.telemetry || {};

  const action = input.action;

  switch (action) {
    case "predictive-maintenance": {
      // Analyze vehicle telemetry for maintenance needs
      const mileage = telemetry.odometer || 0;
      const engineHours = telemetry.engineHours || 0;
      const lastOilChange = vehicleData.lastOilChangeMiles || 0;
      const lastBrakeService = vehicleData.lastBrakeServiceMiles || 0;
      const daysUntilInspection = vehicleData.daysUntilInspection || 90;

      const issues: any[] = [];
      let urgency = "low";
      let estimatedCost = 0;

      // Oil change due?
      const milesSinceOilChange = mileage - lastOilChange;
      if (milesSinceOilChange > 22000) {
        issues.push({
          type: "oil-change",
          severity: "high",
          mileage: milesSinceOilChange,
          recommendation: "Schedule oil change within 500 miles",
          cost: 350,
        });
        urgency = "high";
        estimatedCost += 350;
      } else if (milesSinceOilChange > 18000) {
        issues.push({
          type: "oil-change",
          severity: "medium",
          mileage: milesSinceOilChange,
          recommendation: "Schedule oil change within 2000 miles",
          cost: 350,
        });
        if (urgency === "low") urgency = "medium";
        estimatedCost += 350;
      }

      // Brake service due?
      const milesSinceBrakeService = mileage - lastBrakeService;
      if (milesSinceBrakeService > 45000) {
        issues.push({
          type: "brake-service",
          severity: "critical",
          mileage: milesSinceBrakeService,
          recommendation: "Immediate brake inspection required",
          cost: 1200,
        });
        urgency = "critical";
        estimatedCost += 1200;
      } else if (milesSinceBrakeService > 35000) {
        issues.push({
          type: "brake-service",
          severity: "medium",
          mileage: milesSinceBrakeService,
          recommendation: "Schedule brake inspection within 30 days",
          cost: 1200,
        });
        estimatedCost += 1200;
      }

      // Tire wear from telemetry
      if (telemetry.tireWear && telemetry.tireWear > 70) {
        issues.push({
          type: "tire-replacement",
          severity: "high",
          percentage: telemetry.tireWear,
          recommendation: "Replace tires within 2 weeks",
          cost: 2400,
        });
        if (urgency === "low" || urgency === "medium") urgency = "high";
        estimatedCost += 2400;
      }

      // Annual inspection
      if (daysUntilInspection < 30) {
        issues.push({
          type: "annual-inspection",
          severity: daysUntilInspection < 7 ? "high" : "medium",
          daysRemaining: daysUntilInspection,
          recommendation: `Schedule DOT inspection (${daysUntilInspection} days remaining)`,
          cost: 150,
        });
        estimatedCost += 150;
      }

      return {
        maintenanceType: "preventive",
        vehicleId: params.vehicleId || "unknown",
        issues,
        urgency,
        estimatedCost: `$${estimatedCost}`,
        recommendedSchedule:
          urgency === "critical"
            ? "Immediate"
            : urgency === "high"
              ? "1-2 weeks"
              : urgency === "medium"
                ? "2-4 weeks"
                : "30+ days",
        downtimeEstimate: `${issues.length * 4} hours`,
        reasoning: `Analysis of ${Object.keys(telemetry).length} telemetry data points and maintenance history`,
      };
    }

    case "fuel-optimization": {
      const avgMPG = telemetry.fuelEfficiency || 6.5;
      const benchmarkMPG = 7.2;
      const annualMiles = params.annualMiles || 120000;
      const fuelPrice = params.fuelPrice || 3.85;

      const currentFuelCost = (annualMiles / avgMPG) * fuelPrice;
      const optimizedFuelCost = (annualMiles / benchmarkMPG) * fuelPrice;
      const potentialSavings = currentFuelCost - optimizedFuelCost;

      return {
        currentMPG: avgMPG.toFixed(1),
        targetMPG: benchmarkMPG.toFixed(1),
        improvementPotential: `${(((benchmarkMPG - avgMPG) / avgMPG) * 100).toFixed(0)}%`,
        annualSavings: `$${Math.round(potentialSavings)}`,
        recommendations: [
          "Driver training on efficient acceleration/braking",
          "Regular tire pressure checks (saves 0.3 MPG)",
          "Aerodynamic trailer skirts installation",
          "Cruise control usage on highways",
          "Route optimization to reduce miles",
        ],
        paybackPeriod: "3-6 months",
      };
    }

    case "asset-utilization": {
      const utilizationRate = telemetry.utilizationRate || 0.75;
      const idleDays = params.idleDays || 15;
      const potentialRevenue = params.revenuePerDay || 800;

      return {
        currentUtilization: `${(utilizationRate * 100).toFixed(0)}%`,
        targetUtilization: "85%",
        idleDays,
        lostRevenue: `$${idleDays * potentialRevenue}`,
        recommendations: [
          "Analyze idle patterns for root causes",
          "Consider contract freight for off-peak",
          "Optimize maintenance scheduling",
          "Cross-utilize with underutilized routes",
        ],
        improvementOpportunity: `$${Math.round((0.85 - utilizationRate) * 365 * potentialRevenue)}/year`,
      };
    }

    default:
      return {
        message: `Action '${action}' not yet implemented`,
        supportedActions: [
          "predictive-maintenance",
          "fuel-optimization",
          "asset-utilization",
        ],
      };
  }
}

/**
 * Fleet Intelligence AI Role Implementation
 */
export const fleetIntelRole: RoleContract = {
  name: "fleet-intel",
  version: "1.0.0",
  description:
    "AI role for fleet intelligence, predictive maintenance, and asset optimization",
  confidenceThreshold: 0.9,
  capabilities: [
    "predictive-maintenance",
    "fuel-optimization",
    "asset-utilization",
    "vehicle-health-monitoring",
    "procurement-planning",
  ],

  async decide(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<DecisionResult> {
    const decisionId = `fleet-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const violations = await this.checkGuardrails(input, context);
    const confidence = await this.calculateConfidence(input, context);
    const recommendation = await generateFleetRecommendation(input);

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

    // Cannot approve expenditures
    if (input.action.includes("approve") || input.action.includes("purchase")) {
      violations.push({
        type: "policy",
        severity: "high",
        description:
          "Fleet Intel AI cannot approve expenditures or make purchases",
        remediation: "Escalate to fleet manager for approval",
      });
    }

    // Cannot access vendor payment information
    if (JSON.stringify(input).toLowerCase().includes("payment")) {
      violations.push({
        type: "data-access",
        severity: "medium",
        description: "Cannot access vendor payment information",
        remediation: "Use procurement recommendations only",
      });
    }

    return violations;
  },

  async calculateConfidence(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<ConfidenceScore> {
    const params = input.parameters;
    const telemetry = params.telemetry || {};
    const vehicleHistory = params.vehicleHistory || {};

    // Telemetry data quality
    const telemetryPoints = [
      "odometer",
      "engineHours",
      "fuelEfficiency",
      "tireWear",
      "engineTemp",
      "oilPressure",
    ];
    const availableTelemetry = telemetryPoints.filter(
      (key) => telemetry[key] !== undefined,
    );
    const dataQuality = availableTelemetry.length / telemetryPoints.length;

    // Data freshness (telemetry should be recent)
    const dataAge =
      Date.now() - (params.telemetryTimestamp || context.timestamp.getTime());
    const freshnessScore =
      dataAge < 3600000
        ? 1.0 // < 1 hour
        : dataAge < 86400000
          ? 0.9 // < 1 day
          : 0.7;

    // Historical maintenance data completeness
    const historicalCompleteness =
      vehicleHistory.maintenanceRecords > 10
        ? 1.0
        : vehicleHistory.maintenanceRecords > 5
          ? 0.85
          : 0.7;

    // Model certainty (predictive maintenance models are well-established)
    const modelCertainty = 0.92;

    // Historical prediction accuracy
    const historicalAccuracy = vehicleHistory.predictionAccuracy || 0.88;

    // Calculate weighted confidence
    const confidence =
      dataQuality * 0.35 +
      freshnessScore * 0.2 +
      historicalCompleteness * 0.15 +
      modelCertainty * 0.2 +
      historicalAccuracy * 0.1;

    const reasoningParts = [];
    if (dataQuality < 0.7) reasoningParts.push("limited telemetry data");
    if (freshnessScore < 0.9) reasoningParts.push("telemetry not recent");
    if (historicalCompleteness < 0.85)
      reasoningParts.push("limited maintenance history");
    if (historicalAccuracy < 0.85)
      reasoningParts.push("variable prediction accuracy");

    return {
      value: Math.min(0.98, confidence),
      reasoning:
        reasoningParts.length > 0
          ? `Fleet intelligence confidence affected by: ${reasoningParts.join(", ")}`
          : "Comprehensive vehicle telemetry with strong maintenance history and prediction accuracy",
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

export default fleetIntelRole;
