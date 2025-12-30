/**
 * AI Coaching Service
 * Provides intelligent coaching feedback for drivers
 */

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

interface Driver {
  id: string;
  safetyScore?: number;
  utilizationRate?: number;
  [key: string]: any;
}

interface CoachingFeedback {
  feedback: string;
  metrics: {
    safetyScore: number;
    utilizationRate: number;
    improvementPotential: number;
  };
  suggestions: string[];
}

/**
 * Generate AI coaching for a driver
 */
export async function generateCoaching(
  driver: Driver,
): Promise<CoachingFeedback> {
  try {
    // Fetch driver's recent performance data
    const recentLoads = await prisma.load.findMany({
      where: {
        driverId: driver.id,
        status: { in: ["DELIVERED", "IN_TRANSIT"] },
      },
      orderBy: { createdAt: "desc" },
      take: 10,
    });

    const safetyScore = driver.safetyScore || 0.7;
    const utilizationRate = driver.utilizationRate || 0.5;

    // Analyze performance
    const suggestions: string[] = [];
    let improvementPotential = 0;

    // Safety analysis
    if (safetyScore < 0.7) {
      suggestions.push(
        "Focus on defensive driving techniques and maintain safe following distances",
      );
      suggestions.push("Consider taking a refresher safety course");
      improvementPotential += 0.3;
    } else if (safetyScore < 0.85) {
      suggestions.push(
        "Good safety record! Keep maintaining awareness of road conditions",
      );
      improvementPotential += 0.15;
    } else {
      suggestions.push(
        "Excellent safety score! You're a model driver for the team",
      );
    }

    // Utilization analysis
    if (utilizationRate < 0.5) {
      suggestions.push(
        "Your schedule has capacity for additional loads. Consider volunteering for more routes",
      );
      improvementPotential += 0.25;
    } else if (utilizationRate > 0.85) {
      suggestions.push(
        "High utilization rate. Ensure you're getting adequate rest between trips",
      );
      suggestions.push("Consider discussing workload balance with dispatch");
      improvementPotential += 0.1;
    } else {
      suggestions.push("Good work-life balance with current load schedule");
    }

    // Delivery performance
    if (recentLoads.length < 5) {
      suggestions.push(
        "Building your delivery history. Focus on on-time deliveries and customer satisfaction",
      );
      improvementPotential += 0.2;
    } else {
      const onTimeRate =
        recentLoads.filter((load) => load.status === "DELIVERED").length /
        recentLoads.length;
      if (onTimeRate < 0.8) {
        suggestions.push(
          "Work on improving on-time delivery rate through better route planning",
        );
        improvementPotential += 0.2;
      }
    }

    // Generate overall feedback
    let feedback = `Performance Review:\n\n`;
    feedback += `Safety Score: ${Math.round(safetyScore * 100)}% - `;
    if (safetyScore >= 0.85) {
      feedback += "Excellent!\n";
    } else if (safetyScore >= 0.7) {
      feedback += "Good, with room for improvement.\n";
    } else {
      feedback += "Needs attention.\n";
    }

    feedback += `Utilization Rate: ${Math.round(utilizationRate * 100)}% - `;
    if (utilizationRate >= 0.5 && utilizationRate <= 0.85) {
      feedback += "Well balanced.\n";
    } else if (utilizationRate < 0.5) {
      feedback += "Opportunity for more loads.\n";
    } else {
      feedback += "Consider workload management.\n";
    }

    feedback += `\nRecent Activity: ${recentLoads.length} loads in recent history.\n`;

    feedback += `\nImprovement Potential: ${Math.round(improvementPotential * 100)}%\n`;

    return {
      feedback,
      metrics: {
        safetyScore: Math.round(safetyScore * 100) / 100,
        utilizationRate: Math.round(utilizationRate * 100) / 100,
        improvementPotential: Math.round(improvementPotential * 100) / 100,
      },
      suggestions,
    };
  } catch (error) {
    console.error("Error in generateCoaching:", error);
    throw new Error(
      `Failed to generate coaching: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

export default {
  generateCoaching,
};
