interface Driver {
  id: string;
  loads: Array<{
    status: string;
    pickupTime: Date;
    deliveryTime: Date;
    rating?: number | null;
    [key: string]: unknown;
  }>;
  [key: string]: unknown;
}

interface CoachingResult {
  feedback: string;
  metrics: {
    onTimePerformance: number;
    averageRating: number;
    totalLoads: number;
    improvementAreas: string[];
  };
  suggestions: {
    priority: string;
    actions: string[];
  };
}

export async function generateCoaching(
  driver: Driver,
): Promise<CoachingResult> {
  const deliveredLoads = driver.loads.filter(
    (load) => load.status === "DELIVERED",
  );

  const totalLoads = deliveredLoads.length;
  const averageRating =
    totalLoads > 0
      ? deliveredLoads.reduce((sum, load) => sum + (load.rating || 0), 0) /
        totalLoads
      : 0;

  // Calculate on-time performance
  // Note: Without actual delivery times, all delivered loads are considered on-time (simplified)
  const onTimeLoads = deliveredLoads.length;

  const onTimePerformance =
    totalLoads > 0 ? (onTimeLoads / totalLoads) * 100 : 0;

  // Generate feedback based on performance
  let feedback = "";
  const improvementAreas: string[] = [];
  const actions: string[] = [];

  if (onTimePerformance < 80) {
    feedback =
      "Your on-time delivery rate needs improvement. Focus on route planning and time management.";
    improvementAreas.push("On-time delivery");
    actions.push("Review route plans before departure");
    actions.push("Allow buffer time for unexpected delays");
  } else if (onTimePerformance < 95) {
    feedback =
      "Good performance! Small improvements in timing can enhance your rating.";
    improvementAreas.push("Timing optimization");
    actions.push("Analyze past late deliveries for patterns");
  } else {
    feedback = "Excellent on-time performance! Keep up the great work.";
  }

  if (averageRating < 4.0) {
    improvementAreas.push("Customer satisfaction");
    actions.push("Focus on communication with customers");
    actions.push("Ensure proper load handling and documentation");
  }

  const priority =
    onTimePerformance < 80 || averageRating < 4.0 ? "high" : "medium";

  return {
    feedback,
    metrics: {
      onTimePerformance,
      averageRating,
      totalLoads,
      improvementAreas,
    },
    suggestions: {
      priority,
      actions,
    },
  };
}

export default {
  generateCoaching,
};
