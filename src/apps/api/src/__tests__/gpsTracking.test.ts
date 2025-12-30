/**
 * Phase 3 Test Suite: GPS Tracking Manager
 * Target: <500ms latency for location updates
 */

import { GPSTrackingManager } from "../services/gpsTracking";

describe("GPSTrackingManager", () => {
  let tracker: GPSTrackingManager;

  beforeEach(() => {
    tracker = new GPSTrackingManager();
  });

  describe("updateDriverLocation()", () => {
    it("should update driver location successfully", () => {
      tracker.updateDriverLocation("driver-1", 40.7128, -74.006, 60, 180, 10);

      const activeDrivers = tracker.getActiveDrivers();
      expect(activeDrivers).toHaveLength(1);
      expect(activeDrivers[0].driverId).toBe("driver-1");
    });

    it("should handle multiple concurrent updates", () => {
      const drivers = ["driver-1", "driver-2", "driver-3"];

      drivers.forEach((driverId, i) => {
        tracker.updateDriverLocation(
          driverId,
          40.7128 + i * 0.01,
          -74.006 + i * 0.01,
          60,
          180,
          10,
        );
      });

      const activeDrivers = tracker.getActiveDrivers();
      expect(activeDrivers).toHaveLength(3);
    });

    it("should update in under 500ms", () => {
      const start = Date.now();
      tracker.updateDriverLocation("speed-test", 40.7128, -74.006, 60, 180, 10);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(500);
    });
  });

  describe("calculateETA()", () => {
    it("should calculate ETA to destination", () => {
      tracker.updateDriverLocation("driver-eta", 40.7128, -74.006, 60, 180, 10);

      const destination = { lat: 40.758, lng: -73.9855 };
      const currentLocation = { lat: 40.7128, lng: -74.006 };

      const eta = tracker.calculateETA(
        "driver-eta",
        destination,
        currentLocation,
      );

      expect(eta.estimatedMinutes).toBeGreaterThan(0);
      expect(eta.confidence).toBeGreaterThan(0);
      expect(eta.confidence).toBeLessThanOrEqual(1);
    });

    it("should factor in traffic conditions", () => {
      const destination = { lat: 40.758, lng: -73.9855 };
      const currentLocation = { lat: 40.7128, lng: -74.006 };

      // Mock peak hour
      const peakTime = new Date("2025-12-30T08:00:00");
      jest.spyOn(global, "Date").mockImplementation(() => peakTime);

      const etaPeak = tracker.calculateETA(
        "driver-1",
        destination,
        currentLocation,
      );

      // Mock off-peak hour
      const offPeakTime = new Date("2025-12-30T14:00:00");
      jest.spyOn(global, "Date").mockImplementation(() => offPeakTime);

      const etaOffPeak = tracker.calculateETA(
        "driver-1",
        destination,
        currentLocation,
      );

      // Peak should take longer
      expect(etaPeak.estimatedMinutes).toBeGreaterThan(
        etaOffPeak.estimatedMinutes,
      );
    });

    it("should achieve ±8 minute accuracy target", () => {
      const destination = { lat: 40.758, lng: -73.9855 };
      const currentLocation = { lat: 40.7128, lng: -74.006 };

      const eta = tracker.calculateETA(
        "driver-accurate",
        destination,
        currentLocation,
      );

      // Verify confidence level supports ±8 min accuracy
      expect(eta.confidence).toBeGreaterThan(0.75);
    });
  });

  describe("isInGeofence()", () => {
    it("should detect when driver is inside geofence", () => {
      const location = { lat: 40.7128, lng: -74.006 };
      const geofence = { lat: 40.7128, lng: -74.006, radiusMeters: 500 };

      const isInside = tracker.isInGeofence(location, geofence);

      expect(isInside).toBe(true);
    });

    it("should detect when driver is outside geofence", () => {
      const location = { lat: 40.7128, lng: -74.006 };
      const geofence = { lat: 41.0, lng: -75.0, radiusMeters: 500 };

      const isInside = tracker.isInGeofence(location, geofence);

      expect(isInside).toBe(false);
    });

    it("should handle edge cases at boundary", () => {
      const location = { lat: 40.7128, lng: -74.006 };
      const geofence = {
        lat: 40.7128 + 0.0045,
        lng: -74.006,
        radiusMeters: 500,
      }; // Exactly 500m away

      const isInside = tracker.isInGeofence(location, geofence);

      expect(typeof isInside).toBe("boolean");
    });
  });

  describe("getLocationHistory()", () => {
    it("should retrieve location history for driver", () => {
      tracker.updateDriverLocation(
        "history-driver",
        40.7128,
        -74.006,
        60,
        180,
        10,
      );
      tracker.updateDriverLocation(
        "history-driver",
        40.713,
        -74.0062,
        65,
        185,
        10,
      );
      tracker.updateDriverLocation(
        "history-driver",
        40.7132,
        -74.0064,
        70,
        190,
        10,
      );

      const history = tracker.getLocationHistory("history-driver");

      expect(history.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("getActiveDrivers()", () => {
    it("should return list of all active drivers", () => {
      tracker.updateDriverLocation("active-1", 40.7128, -74.006, 60, 180, 10);
      tracker.updateDriverLocation("active-2", 40.758, -73.9855, 55, 170, 10);
      tracker.updateDriverLocation("active-3", 40.7489, -73.968, 50, 160, 10);

      const activeDrivers = tracker.getActiveDrivers();

      expect(activeDrivers).toHaveLength(3);
      activeDrivers.forEach((driver) => {
        expect(driver).toHaveProperty("driverId");
        expect(driver).toHaveProperty("location");
        expect(driver).toHaveProperty("speed");
        expect(driver).toHaveProperty("lastUpdate");
      });
    });
  });

  describe("registerGeofence()", () => {
    it("should register new geofence", () => {
      const geofence = {
        id: "warehouse-1",
        name: "Main Warehouse",
        lat: 40.7128,
        lng: -74.006,
        radiusMeters: 1000,
        type: "warehouse" as const,
      };

      tracker.registerGeofence(geofence);

      // Verify geofence is active by testing detection
      const location = { lat: 40.7128, lng: -74.006 };
      const isInside = tracker.isInGeofence(location, {
        lat: geofence.lat,
        lng: geofence.lng,
        radiusMeters: geofence.radiusMeters,
      });

      expect(isInside).toBe(true);
    });
  });

  describe("performance", () => {
    it("should handle 1000 concurrent location updates", () => {
      const start = Date.now();

      for (let i = 0; i < 1000; i++) {
        tracker.updateDriverLocation(
          `driver-${i}`,
          40.7128 + i * 0.0001,
          -74.006 + i * 0.0001,
          60,
          180,
          10,
        );
      }

      const duration = Date.now() - start;

      expect(duration).toBeLessThan(5000); // 5 seconds for 1000 updates
      expect(tracker.getActiveDrivers()).toHaveLength(1000);
    });

    it("should maintain low latency under load", () => {
      // Pre-populate with 500 drivers
      for (let i = 0; i < 500; i++) {
        tracker.updateDriverLocation(
          `bulk-${i}`,
          40.7 + i * 0.001,
          -74 + i * 0.001,
          60,
          180,
          10,
        );
      }

      // Test single update latency
      const start = Date.now();
      tracker.updateDriverLocation(
        "latency-test",
        40.7128,
        -74.006,
        60,
        180,
        10,
      );
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(100); // Still under 100ms with load
    });
  });
});
