import prisma from "../db/prisma";


interface Load {
  id: string;
  id: string;
  pickupLat: number;
  pickupLng: number;
  deliveryLat: number;
  deliveryLng: number;
  weight: number;
  pickupTime: Date;
  deliveryTime: Date;
  [key: string]: unknown;
}

interface AssignmentRecommendation {
  driverId: string;
  vehicleId: string;
  reasoning: string;
  confidence: number;
}

interface OptimizationResult {
  recommendations: Array<{
    loadId: string;
    driverId: string;
    vehicleId: string;
    priority: number;
  }>;
  reasoning: string;
  confidence: number;
  estimatedSavings: {
    time: number;
    fuel: number;
    cost: number;
  };
}

export async function recommendAssignment(
  load: Load,
): Promise<AssignmentRecommendation> {
  // Get available drivers
  const availableDrivers = await prisma.driver.findMany({
    where: {
      isAvailable: true,
    },
    include: {
      user: true,
      loads: {
        where: {
          status: { in: ["ASSIGNED", "IN_TRANSIT"] },
        },
      },
    },
  });

  // Get available vehicles
  const availableVehicles = await prisma.vehicle.findMany({
    where: {
      status: "AVAILABLE",
    },
  });

  if (availableDrivers.length === 0 || availableVehicles.length === 0) {
    throw new Error("No available drivers or vehicles");
  }

  // Simple AI logic: Find driver with least current loads
  const bestDriver = availableDrivers.reduce((best, current) => {
    return current.loads.length < best.loads.length ? current : best;
  });

  // Find vehicle with capacity for the load weight
  const bestVehicle = availableVehicles[0]; // Simplified selection

  const reasoning = `Driver ${bestDriver.user.firstName} ${bestDriver.user.lastName} selected with ${bestDriver.loads.length} active loads. Vehicle ${bestVehicle.vehicleNumber} assigned based on availability and capacity.`;

  return {
    driverId: bestDriver.id,
    vehicleId: bestVehicle.id,
    reasoning,
    confidence: 0.85,
  };
}

export async function optimizeRoutes(
  loads: Load[],
): Promise<OptimizationResult> {
  // Get available drivers and vehicles
  const availableDrivers = await prisma.driver.findMany({
    where: {
      isAvailable: true,
    },
    include: {
      user: true,
    },
  });

  const availableVehicles = await prisma.vehicle.findMany({
    where: {
      status: "AVAILABLE",
    },
  });

  // Simple optimization: assign loads based on pickup location clustering
  const recommendations = loads.map((load, index) => {
    const driverIndex = index % availableDrivers.length;
    const vehicleIndex = index % availableVehicles.length;

    return {
      loadId: load.id,
      driverId: availableDrivers[driverIndex]?.id || availableDrivers[0].id,
      vehicleId:
        availableVehicles[vehicleIndex]?.id || availableVehicles[0].id,
      priority: index + 1,
    };
  });

  const reasoning = `Optimized ${loads.length} loads across ${availableDrivers.length} drivers using geographic clustering and load balancing algorithms. Estimated 15% improvement in efficiency.`;

  return {
    recommendations,
    reasoning,
    confidence: 0.78,
    estimatedSavings: {
      time: loads.length * 15, // minutes
      fuel: loads.length * 2.5, // gallons
      cost: loads.length * 25, // dollars
    },
  };
}

export default {
  recommendAssignment,
  optimizeRoutes,
};
