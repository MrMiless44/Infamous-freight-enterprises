/**
 * Integration tests for AI services
 */

import { describe, it, expect, beforeAll, afterAll } from "@jest/globals";
import * as aiDispatchService from "../../src/services/aiDispatchService";
import * as aiCoachService from "../../src/services/aiCoachService";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

describe("AI Dispatch Service", () => {
  beforeAll(async () => {
    // Set up test data
    await prisma.driver.deleteMany();
    await prisma.vehicle.deleteMany();
    await prisma.load.deleteMany();

    await prisma.driver.create({
      data: {
        id: "test-driver-1",
        userId: "test-user-1",
        licenseNumber: "TEST123",
        isAvailable: true,
        safetyScore: 0.85,
        currentLocation: "New York",
        organizationId: "test-org",
      },
    });

    await prisma.vehicle.create({
      data: {
        id: "test-vehicle-1",
        licensePlate: "TEST-001",
        status: "AVAILABLE",
        capacity: 5000,
        organizationId: "test-org",
      },
    });
  });

  afterAll(async () => {
    await prisma.driver.deleteMany();
    await prisma.vehicle.deleteMany();
    await prisma.load.deleteMany();
    await prisma.$disconnect();
  });

  it("should recommend assignment for a load", async () => {
    const load = {
      id: "test-load-1",
      pickupLocation: "Boston",
      deliveryLocation: "Philadelphia",
      weight: 2000,
      priority: "standard",
    };

    const recommendation = await aiDispatchService.recommendAssignment(load);

    expect(recommendation).toBeDefined();
    expect(recommendation.driverId).toBe("test-driver-1");
    expect(recommendation.vehicleId).toBe("test-vehicle-1");
    expect(recommendation.confidence).toBeGreaterThan(0);
    expect(recommendation.confidence).toBeLessThanOrEqual(1);
    expect(recommendation.reasoning).toContain("driver");
  });

  it("should throw error when no drivers available", async () => {
    await prisma.driver.updateMany({
      data: { isAvailable: false },
    });

    const load = {
      id: "test-load-2",
      pickupLocation: "Boston",
      deliveryLocation: "Philadelphia",
    };

    await expect(aiDispatchService.recommendAssignment(load)).rejects.toThrow(
      "No available drivers",
    );

    // Reset
    await prisma.driver.updateMany({
      data: { isAvailable: true },
    });
  });

  it("should optimize routes for multiple loads", async () => {
    const loads = [
      {
        id: "load-1",
        pickupLocation: "New York",
        deliveryLocation: "Boston",
      },
      {
        id: "load-2",
        pickupLocation: "Philadelphia",
        deliveryLocation: "Washington DC",
      },
    ];

    const optimization = await aiDispatchService.optimizeRoutes(loads);

    expect(optimization).toBeDefined();
    expect(optimization.routes).toHaveLength(2);
    expect(optimization.confidence).toBeGreaterThan(0);
    expect(optimization.totalDistance).toBeGreaterThan(0);
    expect(optimization.totalTime).toBeGreaterThan(0);
  });
});

describe("AI Coaching Service", () => {
  beforeAll(async () => {
    await prisma.load.deleteMany();
    await prisma.driver.deleteMany();

    await prisma.driver.create({
      data: {
        id: "coach-driver-1",
        userId: "coach-user-1",
        licenseNumber: "COACH123",
        isAvailable: true,
        safetyScore: 0.75,
        utilizationRate: 0.6,
        currentLocation: "New York",
        organizationId: "test-org",
      },
    });

    // Create some load history
    for (let i = 0; i < 5; i++) {
      await prisma.load.create({
        data: {
          loadNumber: `LOAD-${i}`,
          pickupLocation: "Origin",
          deliveryLocation: "Destination",
          status: "DELIVERED",
          customerId: "test-customer",
          driverId: "coach-driver-1",
          organizationId: "test-org",
        },
      });
    }
  });

  afterAll(async () => {
    await prisma.load.deleteMany();
    await prisma.driver.deleteMany();
    await prisma.$disconnect();
  });

  it("should generate coaching feedback for a driver", async () => {
    const driver = await prisma.driver.findUnique({
      where: { id: "coach-driver-1" },
    });

    const coaching = await aiCoachService.generateCoaching(driver!);

    expect(coaching).toBeDefined();
    expect(coaching.feedback).toContain("Performance Review");
    expect(coaching.metrics.safetyScore).toBe(0.75);
    expect(coaching.metrics.utilizationRate).toBe(0.6);
    expect(coaching.suggestions).toBeInstanceOf(Array);
    expect(coaching.suggestions.length).toBeGreaterThan(0);
  });

  it("should provide different suggestions based on safety score", async () => {
    // Low safety score
    await prisma.driver.update({
      where: { id: "coach-driver-1" },
      data: { safetyScore: 0.6 },
    });

    const driver = await prisma.driver.findUnique({
      where: { id: "coach-driver-1" },
    });

    const coaching = await aiCoachService.generateCoaching(driver!);

    expect(coaching.suggestions.some((s) => s.includes("safety"))).toBe(true);
    expect(coaching.metrics.improvementPotential).toBeGreaterThan(0.2);
  });
});
