import prisma from "../db/prisma";

interface Vehicle {
  id: string;
  mileage: number;
  lastMaintenance: Date | null;
  maintenanceLogs: Array<{
    type: string;
    cost: number;
    performedAt: Date;
    nextDue: Date | null;
  }>;
  [key: string]: unknown;
}

interface MaintenancePrediction {
  predictions: Array<{
    type: string;
    recommendedDate: Date;
    urgency: string;
    estimatedCost: number;
    reasoning: string;
  }>;
  overallRisk: string;
  confidence: number;
}

export async function predictMaintenance(
  vehicle: Vehicle,
): Promise<MaintenancePrediction> {
  const predictions: MaintenancePrediction["predictions"] = [];

  // Calculate days since last maintenance
  const daysSinceLastMaintenance = vehicle.lastMaintenance
    ? Math.floor(
        (Date.now() - new Date(vehicle.lastMaintenance).getTime()) /
          (1000 * 60 * 60 * 24),
      )
    : 365;

  // Oil change prediction
  if (vehicle.mileage % 5000 < 1000 || daysSinceLastMaintenance > 90) {
    predictions.push({
      type: "Oil Change",
      recommendedDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      urgency: daysSinceLastMaintenance > 120 ? "high" : "medium",
      estimatedCost: 75,
      reasoning:
        "Based on mileage and time since last service, oil change is due soon.",
    });
  }

  // Tire rotation prediction
  if (vehicle.mileage % 7500 < 1000) {
    predictions.push({
      type: "Tire Rotation",
      recommendedDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000), // 14 days
      urgency: "low",
      estimatedCost: 50,
      reasoning: "Tire rotation recommended every 7,500 miles.",
    });
  }

  // Brake inspection prediction
  if (vehicle.mileage > 30000 && vehicle.mileage % 15000 < 1000) {
    predictions.push({
      type: "Brake Inspection",
      recommendedDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      urgency: "medium",
      estimatedCost: 150,
      reasoning: "Brake systems should be inspected every 15,000 miles.",
    });
  }

  // Analyze maintenance history for patterns
  const recentMaintenance = vehicle.maintenanceLogs.filter((log) => {
    const logDate = new Date(log.performedAt);
    const threeMonthsAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    return logDate > threeMonthsAgo;
  });

  const averageMaintenanceCost =
    recentMaintenance.length > 0
      ? recentMaintenance.reduce((sum, log) => sum + log.cost, 0) /
        recentMaintenance.length
      : 0;

  // Determine overall risk
  let overallRisk = "low";
  if (predictions.some((p) => p.urgency === "high")) {
    overallRisk = "high";
  } else if (predictions.some((p) => p.urgency === "medium")) {
    overallRisk = "medium";
  }

  return {
    predictions,
    overallRisk,
    confidence: 0.82,
  };
}

export default {
  predictMaintenance,
};
