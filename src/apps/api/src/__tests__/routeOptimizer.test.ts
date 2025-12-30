/**
 * Phase 3 Test Suite: Route Optimizer
 * Target: 15-20% route efficiency improvement
 */

import { RouteOptimizer } from "../services/routeOptimizer";

describe("RouteOptimizer", () => {
  let optimizer: RouteOptimizer;

  beforeEach(() => {
    optimizer = new RouteOptimizer();
  });

  describe("optimizeRoute()", () => {
    it("should optimize simple two-point route", () => {
      const start = { lat: 40.7128, lng: -74.006, name: "NYC" };
      const end = { lat: 40.758, lng: -73.9855, name: "Times Square" };

      const result = optimizer.optimizeRoute(start, end);

      expect(result.totalDistance).toBeGreaterThan(0);
      expect(result.estimatedTime).toBeGreaterThan(0);
      expect(result.waypoints).toHaveLength(2);
    });

    it("should calculate fuel and cost estimates", () => {
      const start = { lat: 40.7128, lng: -74.006, name: "Start" };
      const end = { lat: 41.7128, lng: -75.006, name: "End" };

      const result = optimizer.optimizeRoute(start, end);

      expect(result.fuel).toBeGreaterThan(0);
      expect(result.cost).toBeGreaterThan(0);
    });

    it("should apply traffic multipliers correctly", () => {
      const start = { lat: 40.7128, lng: -74.006, name: "Start" };
      const end = { lat: 40.758, lng: -73.9855, name: "End" };

      // Mock time to peak hours
      const peakTime = new Date("2025-12-30T08:00:00");
      jest.spyOn(global, "Date").mockImplementation(() => peakTime);

      const result = optimizer.optimizeRoute(start, end);

      // Peak hour should take longer
      expect(result.estimatedTime).toBeGreaterThan(10);
    });
  });

  describe("optimizeMultiStop()", () => {
    it("should optimize multi-stop delivery route", () => {
      const waypoints = [
        { lat: 40.7128, lng: -74.006, name: "Stop 1" },
        { lat: 40.758, lng: -73.9855, name: "Stop 2" },
        { lat: 40.7489, lng: -73.968, name: "Stop 3" },
        { lat: 40.7614, lng: -73.9776, name: "Stop 4" },
      ];

      const result = optimizer.optimizeMultiStop(waypoints);

      expect(result.waypoints.length).toBeGreaterThanOrEqual(waypoints.length);
      expect(result.efficiency).toContain("%");
      expect(parseFloat(result.efficiency)).toBeGreaterThan(0);
    });

    it("should achieve 15-20% efficiency improvement", () => {
      const waypoints = [
        { lat: 40.7128, lng: -74.006, name: "A" },
        { lat: 40.758, lng: -73.9855, name: "B" },
        { lat: 40.7489, lng: -73.968, name: "C" },
        { lat: 40.7614, lng: -73.9776, name: "D" },
        { lat: 40.7306, lng: -73.9352, name: "E" },
      ];

      const result = optimizer.optimizeMultiStop(waypoints);
      const efficiencyGain = parseFloat(result.efficiency.replace("%", ""));

      expect(efficiencyGain).toBeGreaterThanOrEqual(15);
      expect(efficiencyGain).toBeLessThanOrEqual(25);
    });

    it("should handle large number of stops", () => {
      const waypoints = Array.from({ length: 15 }, (_, i) => ({
        lat: 40.7128 + i * 0.01,
        lng: -74.006 + i * 0.01,
        name: `Stop ${i + 1}`,
      }));

      const start = Date.now();
      const result = optimizer.optimizeMultiStop(waypoints);
      const duration = Date.now() - start;

      expect(result.waypoints.length).toBeGreaterThanOrEqual(waypoints.length);
      expect(duration).toBeLessThan(1000); // Under 1 second
    });
  });

  describe("compareRoutes()", () => {
    it("should compare multiple route options", () => {
      const waypoints = [
        { lat: 40.7128, lng: -74.006, name: "Start" },
        { lat: 40.758, lng: -73.9855, name: "Mid" },
        { lat: 40.7614, lng: -73.9776, name: "End" },
      ];

      const comparison = optimizer.compareRoutes(waypoints);

      expect(comparison).toHaveProperty("fastest");
      expect(comparison).toHaveProperty("shortest");
      expect(comparison).toHaveProperty("mostEfficient");
    });
  });

  describe("haversineDistance()", () => {
    it("should calculate distance accurately", () => {
      const lat1 = 40.7128,
        lng1 = -74.006; // NYC
      const lat2 = 34.0522,
        lng2 = -118.2437; // LA

      const distance = optimizer.haversineDistance(lat1, lng1, lat2, lng2);

      // NYC to LA is approximately 3,944 km
      expect(distance).toBeGreaterThan(3900);
      expect(distance).toBeLessThan(4000);
    });
  });

  describe("performance", () => {
    it("should optimize route in under 500ms", () => {
      const waypoints = Array.from({ length: 10 }, (_, i) => ({
        lat: 40.7128 + i * 0.01,
        lng: -74.006 + i * 0.01,
        name: `Stop ${i}`,
      }));

      const start = Date.now();
      optimizer.optimizeMultiStop(waypoints);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(500);
    });
  });
});
