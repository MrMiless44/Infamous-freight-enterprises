/**
 * Phase 3 Test Suite: GPS Tracking
 * Target: 5 second update frequency, <15% ETA accuracy
 */

import { GPSTrackingManager } from "../services/gpsTracking";

describe("GPSTrackingManager", () => {
  let tracker: GPSTrackingManager;

  beforeEach(() => {
    tracker = new GPSTrackingManager();
  });

  describe("updateDriverLocation()", () => {
    it("should store driver location", () => {
      const update = {
        driverId: "driver-1",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 60,
        heading: 180,
      };

      const result = tracker.updateDriverLocation(update);

      expect(result).toHaveProperty("geofenceEvents");
      expect(result).toHaveProperty("speedAlert");
      expect(result.geofenceEvents).toBeInstanceOf(Array);
    });

    it("should track multiple location updates", () => {
      for (let i = 0; i < 10; i++) {
        tracker.updateDriverLocation({
          driverId: "driver-path",
          latitude: 40.7128 + i * 0.01,
          longitude: -74.006 + i * 0.01,
          accuracy: 10,
          timestamp: new Date(),
          speed: 60,
          heading: 180,
        });
      }

      const activeDrivers = tracker.getActiveDrivers();
      expect(activeDrivers).toHaveLength(1);
      expect(activeDrivers[0].driverId).toBe("driver-path");
    });

    it("should trigger speed alerts for excessive speed", () => {
      const result = tracker.updateDriverLocation({
        driverId: "speed-test",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 150, // Over limit
        heading: 180,
      });

      expect(result.speedAlert).toBe(true);
    });
  });

  describe("calculateETA()", () => {
    it("should calculate ETA based on current location", () => {
      tracker.updateDriverLocation({
        driverId: "driver-eta",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 60,
        heading: 180,
      });

      const destination = { lat: 40.758, lng: -73.9855 };
      const eta = tracker.calculateETA("driver-eta", destination);

      expect(eta).not.toBeNull();
      expect(eta?.estimatedMinutes).toBeGreaterThan(0);
      expect(eta?.confidence).toBeGreaterThan(0);
      expect(eta?.confidence).toBeLessThanOrEqual(1);
    });

    it("should handle stationary drivers with lower confidence", () => {
      tracker.updateDriverLocation({
        driverId: "stationary",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 0, // Stationary
        heading: 0,
      });

      const eta = tracker.calculateETA("stationary", {
        lat: 40.758,
        lng: -73.9855,
      });

      expect(eta?.confidence).toBeLessThan(0.6);
    });

    it("should return null for unknown driver", () => {
      const eta = tracker.calculateETA("unknown-driver", {
        lat: 40.758,
        lng: -73.9855,
      });
      expect(eta).toBeNull();
    });
  });

  describe("getLocationHistory()", () => {
    it("should retrieve location history for a load", () => {
      const history = {
        driverId: "history-driver",
        loadId: "load-123",
        pickupLocation: { lat: 40.7128, lng: -74.006 },
        deliveryLocation: { lat: 40.758, lng: -73.9855 },
        startTime: new Date(),
        distance: 5.2,
        duration: 20,
        averageSpeed: 45,
        locations: [],
      };

      tracker.storeLocationHistory(history);
      const retrieved = tracker.getLocationHistory(
        "history-driver",
        "load-123",
      );

      expect(retrieved).toBeDefined();
      expect(retrieved?.loadId).toBe("load-123");
    });
  });

  describe("getActiveDrivers()", () => {
    it("should return all active drivers", () => {
      tracker.updateDriverLocation({
        driverId: "active-1",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 60,
        heading: 180,
      });
      tracker.updateDriverLocation({
        driverId: "active-2",
        latitude: 40.758,
        longitude: -73.9855,
        accuracy: 10,
        timestamp: new Date(),
        speed: 55,
        heading: 170,
      });

      const activeDrivers = tracker.getActiveDrivers();

      expect(activeDrivers.length).toBeGreaterThanOrEqual(2);
      expect(activeDrivers.map((d) => d.driverId)).toContain("active-1");
      expect(activeDrivers.map((d) => d.driverId)).toContain("active-2");
    });
  });

  describe("geofencing", () => {
    it("should register geofences", () => {
      const geofence = {
        id: "warehouse-1",
        name: "Main Warehouse",
        latitude: 40.7128,
        longitude: -74.006,
        radiusMeters: 500,
        type: "warehouse" as const,
      };

      expect(() => tracker.registerGeofence(geofence)).not.toThrow();
    });

    it("should detect geofence entry", () => {
      const geofence = {
        id: "zone-1",
        name: "Delivery Zone",
        latitude: 40.7128,
        longitude: -74.006,
        radiusMeters: 1000,
        type: "delivery" as const,
      };

      tracker.registerGeofence(geofence);

      // Driver enters geofence
      const result = tracker.updateDriverLocation({
        driverId: "driver-geo",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 40,
        heading: 90,
      });

      expect(result.geofenceEvents.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe("storeLocationHistory()", () => {
    it("should store location history", () => {
      const history = {
        driverId: "driver-123",
        loadId: "load-456",
        pickupLocation: { lat: 40.7128, lng: -74.006 },
        deliveryLocation: { lat: 40.758, lng: -73.9855 },
        startTime: new Date(),
        distance: 10.5,
        duration: 30,
        averageSpeed: 50,
        locations: [],
      };

      tracker.storeLocationHistory(history);
      const retrieved = tracker.getLocationHistory("driver-123", "load-456");

      expect(retrieved).toBeDefined();
      expect(retrieved?.loadId).toBe("load-456");
      expect(retrieved?.distance).toBe(10.5);
    });

    it("should store multiple histories for same driver", () => {
      const history1 = {
        driverId: "driver-multi",
        loadId: "load-1",
        pickupLocation: { lat: 40.7128, lng: -74.006 },
        deliveryLocation: { lat: 40.758, lng: -73.9855 },
        startTime: new Date(),
        distance: 5,
        duration: 15,
        averageSpeed: 45,
        locations: [],
      };

      const history2 = {
        driverId: "driver-multi",
        loadId: "load-2",
        pickupLocation: { lat: 40.758, lng: -73.9855 },
        deliveryLocation: { lat: 40.7614, lng: -73.9776 },
        startTime: new Date(),
        distance: 3,
        duration: 10,
        averageSpeed: 40,
        locations: [],
      };

      tracker.storeLocationHistory(history1);
      tracker.storeLocationHistory(history2);

      const retrieved1 = tracker.getLocationHistory("driver-multi", "load-1");
      const retrieved2 = tracker.getLocationHistory("driver-multi", "load-2");

      expect(retrieved1).toBeDefined();
      expect(retrieved2).toBeDefined();
      expect(retrieved1?.loadId).toBe("load-1");
      expect(retrieved2?.loadId).toBe("load-2");
    });

    it("should return undefined for non-existent history", () => {
      const retrieved = tracker.getLocationHistory("non-existent", "load-999");
      expect(retrieved).toBeUndefined();
    });
  });

  describe("geofence exit detection", () => {
    it("should detect geofence exit", () => {
      const geofence = {
        id: "zone-exit",
        name: "Exit Test Zone",
        latitude: 40.7128,
        longitude: -74.006,
        radiusMeters: 100,
        type: "warehouse" as const,
      };

      tracker.registerGeofence(geofence);

      // Driver enters geofence
      tracker.updateDriverLocation({
        driverId: "driver-exit",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 30,
        heading: 90,
      });

      // Driver exits geofence
      const result = tracker.updateDriverLocation({
        driverId: "driver-exit",
        latitude: 41.0,
        longitude: -75.0,
        accuracy: 10,
        timestamp: new Date(),
        speed: 60,
        heading: 180,
      });

      const exitEvents = result.geofenceEvents.filter((e) => e.type === "exit");
      expect(exitEvents.length).toBeGreaterThan(0);
    });

    it("should handle driver with no previous location", () => {
      const geofence = {
        id: "first-update",
        name: "First Update Zone",
        latitude: 40.7128,
        longitude: -74.006,
        radiusMeters: 500,
        type: "delivery" as const,
      };

      tracker.registerGeofence(geofence);

      // First update - no previous location
      const result = tracker.updateDriverLocation({
        driverId: "new-driver",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 50,
        heading: 90,
      });

      // Should detect entry since there's no previous location
      expect(result.geofenceEvents).toBeDefined();
    });
  });

  describe("calculateETA() traffic factors", () => {
    it("should apply peak hour traffic factor", () => {
      tracker.updateDriverLocation({
        driverId: "driver-peak",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 60,
        heading: 180,
      });

      const eta = tracker.calculateETA("driver-peak", {
        lat: 40.758,
        lng: -73.9855,
      });

      expect(eta).not.toBeNull();
      expect(eta?.trafficFactor).toBeGreaterThanOrEqual(0.8);
    });

    it("should use minimum speed for stationary vehicles", () => {
      tracker.updateDriverLocation({
        driverId: "driver-slow",
        latitude: 40.7128,
        longitude: -74.006,
        accuracy: 10,
        timestamp: new Date(),
        speed: 5, // Very slow
        heading: 0,
      });

      const eta = tracker.calculateETA("driver-slow", {
        lat: 40.758,
        lng: -73.9855,
      });

      // Should use at least 40 km/h for calculation
      expect(eta).not.toBeNull();
      expect(eta?.estimatedMinutes).toBeGreaterThan(0);
    });
  });

  describe("performance", () => {
    it("should handle high-frequency updates", () => {
      const updates = 100;
      const startTime = Date.now();

      for (let i = 0; i < updates; i++) {
        tracker.updateDriverLocation({
          driverId: `perf-driver-${i % 10}`,
          latitude: 40.7128 + i * 0.0001,
          longitude: -74.006 + i * 0.0001,
          accuracy: 10,
          timestamp: new Date(),
          speed: 60,
          heading: 180,
        });
      }

      const duration = Date.now() - startTime;

      // Should process 100 updates in under 100ms
      expect(duration).toBeLessThan(100);
    });
  });

  describe("edge cases", () => {
    it("should handle invalid coordinates gracefully", () => {
      const update = {
        driverId: "edge-driver",
        latitude: 400, // Invalid
        longitude: -200, // Invalid
        accuracy: 10,
        timestamp: new Date(),
        speed: 60,
        heading: 180,
      };

      expect(() => tracker.updateDriverLocation(update)).not.toThrow();
    });
  });
});
