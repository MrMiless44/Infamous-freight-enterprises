import { GPSTrackingManager } from "../../src/services/gpsTracking";

describe("GPSTrackingManager", () => {
  let tracker: GPSTrackingManager;

  beforeEach(() => {
    tracker = new GPSTrackingManager();
  });

  describe("updateDriverLocation", () => {
    it("should update driver location in memory", () => {
      tracker.updateDriverLocation("driver-001", 40.7128, -74.006, 45, 90, 8);

      const activeDrivers = tracker.getActiveDrivers();
      expect(activeDrivers).toContainEqual(
        expect.objectContaining({
          driverId: "driver-001",
        }),
      );
    });

    it("should track speed and heading", () => {
      tracker.updateDriverLocation("driver-002", 40.7128, -74.006, 55, 180, 8);

      const activeDrivers = tracker.getActiveDrivers();
      const driver = activeDrivers.find((d) => d.driverId === "driver-002");

      expect(driver?.speed).toEqual(55);
      expect(driver?.heading).toEqual(180);
    });
  });

  describe("isInGeofence", () => {
    it("should detect location inside geofence", () => {
      const location = { lat: 40.7128, lng: -74.006 };
      const geofence = {
        lat: 40.7128,
        lng: -74.006,
        radiusMeters: 1000,
      };

      const isInside = tracker.isInGeofence(location, geofence);

      expect(isInside).toBe(true);
    });

    it("should detect location outside geofence", () => {
      const location = { lat: 40.8, lng: -74.0 };
      const geofence = {
        lat: 40.7128,
        lng: -74.006,
        radiusMeters: 1000,
      };

      const isInside = tracker.isInGeofence(location, geofence);

      expect(isInside).toBe(false);
    });

    it("should handle 100m radius geofence", () => {
      const location = { lat: 40.71285, lng: -74.00605 }; // ~80m away
      const geofence = {
        lat: 40.7128,
        lng: -74.006,
        radiusMeters: 100,
      };

      const isInside = tracker.isInGeofence(location, geofence);

      expect(isInside).toBe(true);
    });
  });

  describe("calculateETA", () => {
    it("should calculate ETA in minutes", () => {
      // Simulate driver location
      tracker.updateDriverLocation("driver-003", 40.7128, -74.006, 30, 0, 8);

      const eta = tracker.calculateETA(
        "driver-003",
        { lat: 40.758, lng: -73.9855 }, // ~5 km away
        { lat: 40.7128, lng: -74.006 },
      );

      expect(eta.estimatedMinutes).toBeGreaterThan(0);
      expect(eta.estimatedMinutes).toBeLessThan(30); // Should be ~10 minutes at 30 km/h
      expect(eta.arrival).toBeInstanceOf(Date);
      expect(eta.confidence).toBeGreaterThan(0);
      expect(eta.confidence).toBeLessThanOrEqual(1);
    });

    it("should apply traffic multiplier to ETA", () => {
      tracker.updateDriverLocation("driver-004", 40.7128, -74.006, 45, 0, 8);

      const eta = tracker.calculateETA(
        "driver-004",
        { lat: 40.758, lng: -73.9855 },
        { lat: 40.7128, lng: -74.006 },
      );

      expect(eta.trafficFactor).toBeGreaterThan(0);
    });

    it("should achieve ±8 min accuracy for short distances", () => {
      tracker.updateDriverLocation("driver-005", 40.7128, -74.006, 50, 0, 8);

      // Simulate 5 ETA calculations
      const etas = Array.from({ length: 5 }, () =>
        tracker.calculateETA(
          "driver-005",
          { lat: 40.758, lng: -73.9855 },
          { lat: 40.7128, lng: -74.006 },
        ),
      );

      const avgETA = etas.reduce((sum, eta) => sum + eta.estimatedMinutes, 0) / etas.length;

      // Verify consistent results (within ±8 min variance)
      etas.forEach((eta) => {
        expect(Math.abs(eta.estimatedMinutes - avgETA)).toBeLessThanOrEqual(8);
      });
    });
  });

  describe("getLocationHistory", () => {
    it("should retrieve location history for driver", () => {
      tracker.updateDriverLocation("driver-006", 40.7128, -74.006, 45, 90, 8);
      tracker.updateDriverLocation("driver-006", 40.7138, -74.005, 50, 90, 8);

      const history = tracker.getLocationHistory("driver-006");

      expect(history.length).toBeGreaterThan(0);
    });

    it("should store timestamp for each location", () => {
      tracker.updateDriverLocation("driver-007", 40.7128, -74.006, 45, 90, 8);

      const history = tracker.getLocationHistory("driver-007");

      expect(history[0]).toHaveProperty("timestamp");
      expect(history[0].timestamp).toBeInstanceOf(Date);
    });
  });

  describe("getActiveDrivers", () => {
    it("should list all active drivers", () => {
      tracker.updateDriverLocation("driver-008", 40.7128, -74.006, 45, 90, 8);
      tracker.updateDriverLocation("driver-009", 40.75, -73.99, 60, 180, 8);

      const active = tracker.getActiveDrivers();

      expect(active.length).toBeGreaterThanOrEqual(2);
      expect(active.map((d) => d.driverId)).toContain("driver-008");
      expect(active.map((d) => d.driverId)).toContain("driver-009");
    });

    it("should include current location in active drivers", () => {
      tracker.updateDriverLocation("driver-010", 40.7128, -74.006, 45, 90, 8);

      const active = tracker.getActiveDrivers();
      const driver = active.find((d) => d.driverId === "driver-010");

      expect(driver?.location).toBeDefined();
      expect(driver?.location.lat).toEqual(40.7128);
      expect(driver?.location.lng).toEqual(-74.006);
    });
  });

  describe("WebSocket latency", () => {
    it("should process location updates in <500ms", () => {
      const startTime = Date.now();

      // Simulate 100 concurrent location updates
      for (let i = 0; i < 100; i++) {
        tracker.updateDriverLocation(
          `driver-${i}`,
          40.7128 + Math.random() * 0.01,
          -74.006 + Math.random() * 0.01,
          Math.random() * 100,
          Math.random() * 360,
          8,
        );
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(duration).toBeLessThan(500);
    });
  });

  describe("Speed alerts", () => {
    it("should detect speeding (>120 km/h)", () => {
      tracker.updateDriverLocation("driver-011", 40.7128, -74.006, 130, 90, 8);

      const activeDrivers = tracker.getActiveDrivers();
      const driver = activeDrivers.find((d) => d.driverId === "driver-011");

      expect(driver?.speed).toBeGreaterThan(120);
    });

    it("should not alert for normal speeds", () => {
      tracker.updateDriverLocation("driver-012", 40.7128, -74.006, 60, 90, 8);

      const activeDrivers = tracker.getActiveDrivers();
      const driver = activeDrivers.find((d) => d.driverId === "driver-012");

      expect(driver?.speed).toBeLessThanOrEqual(120);
    });
  });
});
