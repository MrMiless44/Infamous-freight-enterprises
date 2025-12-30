/**
 * AI Dispatch Service
 * Provides intelligent load assignment and route optimization
 */

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

interface Load {
  id: string;
  pickupLocation: string;
  deliveryLocation: string;
  weight?: number;
  priority?: string;
  [key: string]: any;
}

interface Driver {
  id: string;
  currentLocation?: string;
  isAvailable: boolean;
  safetyScore?: number;
  utilizationRate?: number;
  [key: string]: any;
}

interface Vehicle {
  id: string;
  capacity?: number;
  status: string;
  currentLocation?: string;
  [key: string]: any;
}

interface AssignmentRecommendation {
  driverId: string;
  vehicleId: string;
  reasoning: string;
  confidence: number;
  estimatedDeliveryTime?: number;
}

interface RouteOptimization {
  routes: Array<{
    loadId: string;
    driverId: string;
    vehicleId: string;
    order: number;
    estimatedTime: number;
  }>;
  reasoning: string;
  confidence: number;
  totalDistance?: number;
  totalTime?: number;
}

/**
 * Calculate driver score based on multiple factors
 */
function calculateDriverScore(
  driver: Driver,
  load: Load,
  distance: number,
): number {
  let score = 0;

  // Safety score weight: 40%
  if (driver.safetyScore) {
    score += driver.safetyScore * 0.4;
  } else {
    score += 0.3; // Default for unknown
  }

  // Availability weight: 30%
  if (driver.isAvailable) {
    score += 0.3;
  }

  // Utilization rate (lower is better for balance): 20%
  if (driver.utilizationRate !== undefined) {
    score += (1 - driver.utilizationRate) * 0.2;
  } else {
    score += 0.1;
  }

  // Distance factor: 10% (closer is better)
  const distanceFactor = Math.max(0, 1 - distance / 500); // 500 miles max
  score += distanceFactor * 0.1;

  return Math.min(1, Math.max(0, score));
}

/**
 * Calculate estimated distance (simplified - use real mapping API in production)
 */
function estimateDistance(pointA: string, pointB: string): number {
  // Placeholder: In production, use Google Maps API, Mapbox, or similar
  // For now, return a random distance between 50-500 miles
  return Math.floor(Math.random() * 450) + 50;
}

/**
 * Recommend best driver and vehicle for a load
 */
export async function recommendAssignment(
  load: Load,
): Promise<AssignmentRecommendation> {
  try {
    // Fetch available drivers
    const drivers = await prisma.driver.findMany({
      where: { isAvailable: true },
      include: { user: true },
    });

    if (drivers.length === 0) {
      throw new Error("No available drivers found");
    }

    // Fetch available vehicles
    const vehicles = await prisma.vehicle.findMany({
      where: { status: "AVAILABLE" },
    });

    if (vehicles.length === 0) {
      throw new Error("No available vehicles found");
    }

    // Score each driver
    const scoredDrivers = drivers.map((driver) => {
      const distance = estimateDistance(
        driver.currentLocation || "Unknown",
        load.pickupLocation,
      );
      const score = calculateDriverScore(driver, load, distance);

      return {
        driver,
        score,
        distance,
      };
    });

    // Sort by score (highest first)
    scoredDrivers.sort((a, b) => b.score - a.score);

    const bestDriver = scoredDrivers[0].driver;
    const bestVehicle = vehicles[0]; // Simplified: use first available vehicle

    // Calculate confidence based on top driver's score
    const confidence = Math.round(scoredDrivers[0].score * 100) / 100;

    const driverName =
      bestDriver.user?.firstName && bestDriver.user?.lastName
        ? `${bestDriver.user.firstName} ${bestDriver.user.lastName}`
        : bestDriver.id;
    const vehiclePlate = bestVehicle.vehicleNumber || bestVehicle.id;

    const reasoning = `Selected driver ${driverName} (safety score: ${(scoredDrivers[0].score * 100).toFixed(1)}%, distance: ${scoredDrivers[0].distance} miles) and vehicle ${vehiclePlate}. Confidence: ${(confidence * 100).toFixed(1)}%`;

    return {
      driverId: bestDriver.id,
      vehicleId: bestVehicle.id,
      reasoning,
      confidence,
      estimatedDeliveryTime: Math.floor(
        scoredDrivers[0].distance / 50 + Math.random() * 2,
      ), // hours
    };
  } catch (error) {
    console.error("Error in recommendAssignment:", error);
    throw new Error(
      `Failed to recommend assignment: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Optimize routes for multiple loads
 */
export async function optimizeRoutes(
  loads: Load[],
): Promise<RouteOptimization> {
  try {
    if (loads.length === 0) {
      throw new Error("No loads provided for optimization");
    }

    // Fetch available resources
    const drivers = await prisma.driver.findMany({
      where: { isAvailable: true },
      include: { user: true },
    });

    const vehicles = await prisma.vehicle.findMany({
      where: { status: "AVAILABLE" },
    });

    if (drivers.length === 0 || vehicles.length === 0) {
      throw new Error(
        "Insufficient available resources for route optimization",
      );
    }

    // Simple optimization: distribute loads across available drivers
    const routes: RouteOptimization["routes"] = [];
    let totalDistance = 0;
    let totalTime = 0;

    loads.forEach((load, index) => {
      const driverIndex = index % drivers.length;
      const vehicleIndex = index % vehicles.length;

      const driver = drivers[driverIndex];
      const vehicle = vehicles[vehicleIndex];

      const driverLocation =
        typeof driver.currentLocation === "string"
          ? driver.currentLocation
          : "HQ";

      const distance = estimateDistance(driverLocation, load.pickupLocation);
      const time = distance / 50; // Assume 50 mph average

      totalDistance += distance;
      totalTime += time;

      routes.push({
        loadId: load.id,
        driverId: driver.id,
        vehicleId: vehicle.id,
        order: index + 1,
        estimatedTime: Math.round(time * 10) / 10,
      });
    });

    const confidence = Math.min(
      0.95,
      0.6 + (drivers.length / loads.length) * 0.3,
    );

    const reasoning = `Optimized ${loads.length} loads across ${drivers.length} drivers and ${vehicles.length} vehicles. Total estimated distance: ${Math.round(totalDistance)} miles, total time: ${Math.round(totalTime)} hours. Load distribution is ${drivers.length >= loads.length ? "optimal" : "stretched due to limited drivers"}.`;

    return {
      routes,
      reasoning,
      confidence,
      totalDistance: Math.round(totalDistance),
      totalTime: Math.round(totalTime * 10) / 10,
    };
  } catch (error) {
    console.error("Error in optimizeRoutes:", error);
    throw new Error(
      `Failed to optimize routes: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

export default {
  recommendAssignment,
  optimizeRoutes,
};
