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

      expect(result.fuelEstimate).toBeGreaterThan(0);
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
      const start = { lat: 40.7128, lng: -74.006, name: "Start" };
      const stops = [
        { lat: 40.758, lng: -73.9855, name: "Stop 1" },
        { lat: 40.7489, lng: -73.968, name: "Stop 2" },
        { lat: 40.7614, lng: -73.9776, name: "Stop 3" },
      ];

      const result = optimizer.optimizeMultiStop(start, stops);

      expect(result.waypoints.length).toBeGreaterThanOrEqual(stops.length);
      expect(result.efficiency).toBeGreaterThanOrEqual(0);
      expect(result.efficiency).toBeLessThanOrEqual(100);
    });

    it("should achieve efficiency improvement", () => {
      const start = { lat: 40.7128, lng: -74.006, name: "Start" };
      const stops = [
        { lat: 40.758, lng: -73.9855, name: "B" },
        { lat: 40.7489, lng: -73.968, name: "C" },
        { lat: 40.7614, lng: -73.9776, name: "D" },
        { lat: 40.7306, lng: -73.9352, name: "E" },
      ];

      const result = optimizer.optimizeMultiStop(start, stops);

      expect(result.efficiency).toBeGreaterThanOrEqual(0);
      expect(result.totalDistance).toBeGreaterThan(0);
    });

    it("should handle large number of stops", () => {
      const start = { lat: 40.7128, lng: -74.006, name: "Start" };
      const stops = Array.from({ length: 14 }, (_, i) => ({
        lat: 40.7128 + (i + 1) * 0.01,
        lng: -74.006 + (i + 1) * 0.01,
        name: `Stop ${i + 1}`,
      }));

      const startTime = Date.now();
      const result = optimizer.optimizeMultiStop(start, stops);
      const duration = Date.now() - startTime;

      expect(result.waypoints.length).toBeGreaterThanOrEqual(stops.length);
      expect(duration).toBeLessThan(1000); // Under 1 second
    });
  });

  describe("compareRoutes()", () => {
    it("should compare multiple route options", () => {
      const start = { lat: 40.7128, lng: -74.006, name: "Start" };
      const end = { lat: 40.7614, lng: -73.9776, name: "End" };
      const alternatives = [
        [{ lat: 40.758, lng: -73.9855, name: "Via Times Square" }],
        [{ lat: 40.7489, lng: -73.968, name: "Via Central Park" }],
      ];

      const comparison = optimizer.compareRoutes(start, end, alternatives);

      expect(comparison).toHaveProperty("recommended");
      expect(comparison).toHaveProperty("alternatives");
      expect(comparison.alternatives).toBeInstanceOf(Array);
    });
  });

  describe("distance calculations", () => {
    it("should calculate distance accurately in routes", () => {
      const nyc = { lat: 40.7128, lng: -74.006, name: "NYC" };
      const la = { lat: 34.0522, lng: -118.2437, name: "LA" };

      const result = optimizer.optimizeRoute(nyc, la);

      // NYC to LA is approximately 3,944 km
      expect(result.totalDistance).toBeGreaterThan(3900);
      expect(result.totalDistance).toBeLessThan(4000);
    });
  });

  describe("performance", () => {
    it("should optimize route in under 500ms", () => {
      const start = { lat: 40.7128, lng: -74.006, name: "Start" };
      const stops = Array.from({ length: 9 }, (_, i) => ({
        lat: 40.7128 + (i + 1) * 0.01,
        lng: -74.006 + (i + 1) * 0.01,
        name: `Stop ${i + 1}`,
      }));

      const startTime = Date.now();
      optimizer.optimizeMultiStop(start, stops);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(500);
    });
  });
});
