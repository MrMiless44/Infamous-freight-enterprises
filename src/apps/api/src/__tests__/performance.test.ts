/**
 * Performance and Load Tests
 */

import { jest } from "@jest/globals";

describe("Performance Tests", () => {
  describe("GPS Tracking Performance", () => {
    it("should handle 100 location updates in under 1 second", async () => {
      const { updateLocation } = await import("../services/gpsTracking");
      
      const startTime = Date.now();
      const promises = [];

      for (let i = 0; i < 100; i++) {
        const req = {
          body: {
            driverId: `driver-${i}`,
            latitude: 40.7128 + (i * 0.001),
            longitude: -74.006 + (i * 0.001),
            speed: 60,
          },
        };
        const res = {
          json: jest.fn(),
          status: jest.fn().mockReturnThis(),
        };

        promises.push(updateLocation(req as any, res as any));
      }

      await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(1000);
    });

    it("should calculate ETA for 50 drivers concurrently", async () => {
      const { getETA, updateLocation } = await import("../services/gpsTracking");
      
      // First, add some locations
      for (let i = 0; i < 50; i++) {
        const req = {
          body: {
            driverId: `driver-perf-${i}`,
            latitude: 40.7128,
            longitude: -74.006,
            speed: 50,
          },
        };
        const res = {
          json: jest.fn(),
          status: jest.fn().mockReturnThis(),
        };
        await updateLocation(req as any, res as any);
      }

      const startTime = Date.now();
      const promises = [];

      for (let i = 0; i < 50; i++) {
        const req = {
          body: {
            driverId: `driver-perf-${i}`,
            destinationLat: 40.758,
            destinationLng: -73.9855,
          },
        };
        const res = {
          json: jest.fn(),
          status: jest.fn().mockReturnThis(),
        };

        promises.push(getETA(req as any, res as any));
      }

      await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(2000);
    });
  });

  describe("Route Optimizer Performance", () => {
    it("should optimize 20 routes in under 2 seconds", async () => {
      const { optimizeRoute } = await import("../services/routeOptimizer");
      
      const startTime = Date.now();
      const promises = [];

      for (let i = 0; i < 20; i++) {
        const req = {
          body: {
            start: { lat: 40.7128, lng: -74.006 },
            end: { lat: 40.758 + (i * 0.01), lng: -73.9855 + (i * 0.01) },
          },
        };
        const res = {
          json: jest.fn(),
          status: jest.fn().mockReturnThis(),
        };

        promises.push(optimizeRoute(req, res));
      }

      await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(2000);
    });

    it("should handle multi-stop optimization with 15 stops", async () => {
      const { optimizeMultiStop } = await import("../services/routeOptimizer");
      
      const stops = Array.from({ length: 15 }, (_, i) => ({
        lat: 40.7128 + (i * 0.01),
        lng: -74.006 + (i * 0.01),
      }));

      const req = {
        body: {
          start: { lat: 40.7128, lng: -74.006 },
          stops,
        },
      };
      const res = {
        json: jest.fn(),
        status: jest.fn().mockReturnThis(),
      };

      const startTime = Date.now();
      await optimizeMultiStop(req, res);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(1000);
    });
  });

  describe("Memory Usage", () => {
    it("should not leak memory during repeated operations", async () => {
      const { updateLocation } = await import("../services/gpsTracking");
      
      const initialMemory = process.memoryUsage().heapUsed;

      // Perform 1000 operations
      for (let i = 0; i < 1000; i++) {
        const req = {
          body: {
            driverId: "memory-test-driver",
            latitude: 40.7128,
            longitude: -74.006,
            speed: 60,
          },
        };
        const res = {
          json: jest.fn(),
          status: jest.fn().mockReturnThis(),
        };

        await updateLocation(req as any, res as any);
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      const memoryIncreaseMB = memoryIncrease / 1024 / 1024;

      // Memory increase should be reasonable (less than 50MB for 1000 operations)
      expect(memoryIncreaseMB).toBeLessThan(50);
    });
  });

  describe("Throughput", () => {
    it("should handle sustained load of 500 requests", async () => {
      const { getActiveDrivers } = await import("../services/gpsTracking");
      
      const startTime = Date.now();
      const promises = [];

      for (let i = 0; i < 500; i++) {
        const req = {};
        const res = {
          json: jest.fn(),
          status: jest.fn().mockReturnThis(),
        };

        promises.push(getActiveDrivers(req as any, res as any));
      }

      await Promise.all(promises);
      const duration = Date.now() - startTime;
      const throughput = 500 / (duration / 1000);

      // Should handle at least 100 requests per second
      expect(throughput).toBeGreaterThan(100);
    });
  });
});
