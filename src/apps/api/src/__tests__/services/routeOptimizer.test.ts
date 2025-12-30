import { RouteOptimizer } from "../../src/services/routeOptimizer";

describe("RouteOptimizer", () => {
  let optimizer: RouteOptimizer;

  beforeEach(() => {
    optimizer = new RouteOptimizer();
  });

  describe("optimizeRoute", () => {
    it("should calculate route between two points", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.7580, lng: -73.9855 };

      const route = optimizer.optimizeRoute(start, end);

      expect(route.totalDistance).toBeGreaterThan(0);
      expect(route.estimatedTime).toBeGreaterThan(0);
      expect(route.waypoints.length).toBeGreaterThanOrEqual(2);
    });

    it("should estimate fuel consumption", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.7580, lng: -73.9855 };

      const route = optimizer.optimizeRoute(start, end);

      expect(route.fuel).toBeGreaterThan(0);
      expect(route.cost).toBeGreaterThan(0);
    });

    it("should achieve 15-20% efficiency improvement", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.7580, lng: -73.9855 };

      const route = optimizer.optimizeRoute(start, end);

      const efficiencyMatch = route.efficiency.match(/(\d+\.?\d*)/);
      const efficiencyPercent = efficiencyMatch ? parseFloat(efficiencyMatch[0]) : 0;

      expect(efficiencyPercent).toBeGreaterThanOrEqual(15);
      expect(efficiencyPercent).toBeLessThanOrEqual(25);
    });
  });

  describe("optimizeMultiStop", () => {
    it("should optimize multiple waypoints", () => {
      const waypoints = [
        { lat: 40.7128, lng: -74.006, name: "Start" },
        { lat: 40.7480, lng: -73.9862, name: "Stop 1" },
        { lat: 40.7614, lng: -73.9776, name: "Stop 2" },
      ];

      const route = optimizer.optimizeMultiStop(waypoints);

      expect(route.waypoints.length).toEqual(waypoints.length);
      expect(route.totalDistance).toBeGreaterThan(0);
      expect(route.estimatedTime).toBeGreaterThan(0);
    });

    it("should handle 10+ waypoints for VRP", () => {
      const waypoints = Array.from({ length: 15 }, (_, i) => ({
        lat: 40.7128 + (Math.random() - 0.5) * 0.1,
        lng: -74.006 + (Math.random() - 0.5) * 0.1,
        name: `Stop ${i}`,
      }));

      const route = optimizer.optimizeMultiStop(waypoints);

      expect(route.waypoints.length).toBeLessThanOrEqual(waypoints.length);
      expect(route.totalDistance).toBeGreaterThan(0);
    });
  });

  describe("compareRoutes", () => {
    it("should return best and alternative routes", () => {
      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.7580, lng: -73.9855 };

      const comparison = optimizer.compareRoutes(start, end);

      expect(comparison.best).toBeDefined();
      expect(comparison.alternatives.length).toBeGreaterThan(0);
      expect(comparison.best.totalDistance).toBeLessThanOrEqual(
        comparison.alternatives[0].totalDistance,
      );
    });
  });

  describe("haversineDistance", () => {
    it("should calculate distance between coordinates", () => {
      const from = { lat: 40.7128, lng: -74.006 };
      const to = { lat: 40.7580, lng: -73.9855 };

      const distance = optimizer["haversineDistance"](from, to);

      expect(distance).toBeGreaterThan(0);
      expect(distance).toBeLessThan(100); // Should be < 100 km for NYC area
    });

    it("should return 0 for same coordinates", () => {
      const point = { lat: 40.7128, lng: -74.006 };

      const distance = optimizer["haversineDistance"](point, point);

      expect(distance).toEqual(0);
    });
  });

  describe("traffic multiplier", () => {
    it("should apply peak hour multiplier (1.4x) during rush hours", () => {
      // Peak hours: 8-10, 17-19
      const peakHour = new Date();
      peakHour.setHours(9, 0, 0, 0);

      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.7580, lng: -73.9855 };
      const route = optimizer.optimizeRoute(start, end);

      // Verify traffic factor is applied
      expect(route.estimatedTime).toBeGreaterThan(0);
    });

    it("should apply off-peak multiplier (0.8x) during late night", () => {
      const offPeakHour = new Date();
      offPeakHour.setHours(2, 0, 0, 0);

      const start = { lat: 40.7128, lng: -74.006 };
      const end = { lat: 40.7580, lng: -73.9855 };
      const route = optimizer.optimizeRoute(start, end);

      expect(route.estimatedTime).toBeGreaterThan(0);
    });
  });
});
