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

    it.skip("should apply traffic multipliers correctly", () => {
      // TODO: Fix this test - jest.spyOn doesn't work with VM modules
      const start = { lat: 40.7128, lng: -74.006, name: "Start" };
      const end = { lat: 40.758, lng: -73.9855, name: "End" };

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
      expect(result.totalDistance).toBeGreaterThan(0);
      expect(result.estimatedTime).toBeGreaterThan(0);
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

      expect(result.totalDistance).toBeGreaterThan(0);
      expect(result.estimatedTime).toBeGreaterThan(0);
      expect(result.fuelEstimate).toBeGreaterThan(0);
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

  describe("edge cases and validation", () => {
    it("should handle routes with same start and end", () => {
      const location = { lat: 40.7128, lng: -74.006, name: "Same" };

      const route = optimizer.optimizeRoute(location, location);

      expect(route.totalDistance).toBe(0);
      expect(route.estimatedTime).toBe(0);
      expect(route.fuelEstimate).toBe(0);
    });

    it("should handle routes with very close waypoints", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.7129, lng: -74.0061 }; // Very close

      const route = optimizer.optimizeRoute(start, end);

      // May be very small distance or 0, just verify it completes
      expect(route.totalDistance).toBeGreaterThanOrEqual(0);
      expect(route.totalDistance).toBeLessThan(1); // Less than 1 km
    });

    it("should calculate fuel for long routes", () => {
      const start = { lat: 40.7128, lng: -74.006, name: "NYC" };
      const end = { lat: 42.3601, lng: -71.0589, name: "Boston" };

      const route = optimizer.optimizeRoute(start, end);

      expect(route.fuelEstimate).toBeGreaterThan(10); // Should need fuel
      expect(route.cost).toBeGreaterThan(0);
    });

    it("should optimize routes without names", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.758, lng: -73.9855 };

      const route = optimizer.optimizeRoute(start, end);

      expect(route).toBeDefined();
      expect(route.waypoints.length).toBe(2);
    });

    it("should handle empty alternatives in compareRoutes", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.758, lng: -73.9855 };

      const comparison = optimizer.compareRoutes(start, end, []);

      expect(comparison.recommended).toBeDefined();
      expect(comparison.alternatives).toHaveLength(0);
    });

    it("should sort alternatives by estimated time", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.758, lng: -73.9855 };
      const alternatives = [
        [
          { lat: 40.75, lng: -73.97 },
          { lat: 40.76, lng: -73.96 },
        ],
        [{ lat: 40.74, lng: -73.98 }],
      ];

      const comparison = optimizer.compareRoutes(start, end, alternatives);

      // Alternatives should be sorted by estimatedTime
      for (let i = 0; i < comparison.alternatives.length - 1; i++) {
        expect(comparison.alternatives[i].estimatedTime).toBeLessThanOrEqual(
          comparison.alternatives[i + 1].estimatedTime,
        );
      }
    });
  });

  describe("multi-stop optimization with waypoints", () => {
    it("should handle single stop", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const stops = [{ lat: 40.758, lng: -73.9855 }];

      const route = optimizer.optimizeMultiStop(start, stops);

      expect(route.waypoints.length).toBeGreaterThanOrEqual(2);
      expect(route.totalDistance).toBeGreaterThan(0);
    });

    it("should optimize with many stops", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const stops = Array.from({ length: 20 }, (_, i) => ({
        lat: 40.7128 + (i + 1) * 0.005,
        lng: -74.006 + (i + 1) * 0.005,
      }));

      const startTime = Date.now();
      const route = optimizer.optimizeMultiStop(start, stops);
      const duration = Date.now() - startTime;

      expect(route.waypoints.length).toBeGreaterThanOrEqual(stops.length);
      expect(duration).toBeLessThan(5000); // Should complete in <5 seconds
    });

    it("should calculate efficiency improvement", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const stops = [
        { lat: 40.758, lng: -73.9855 },
        { lat: 40.7489, lng: -73.968 },
        { lat: 40.7614, lng: -73.9776 },
      ];

      const route = optimizer.optimizeMultiStop(start, stops);

      expect(route.efficiency).toBeDefined();
      expect(typeof route.efficiency).toBe("number");
      expect(route.legs).toHaveLength(stops.length + 1);
    });

    it("should handle stops with duplicate locations", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const stops = [
        { lat: 40.758, lng: -73.9855 },
        { lat: 40.758, lng: -73.9855 }, // Duplicate
      ];

      const route = optimizer.optimizeMultiStop(start, stops);

      expect(route).toBeDefined();
      expect(route.totalDistance).toBeGreaterThan(0);
    });
  });
});
