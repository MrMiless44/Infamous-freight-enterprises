import { DriverAvailabilityPredictor } from "../../src/services/driverAvailabilityPredictor";

describe("DriverAvailabilityPredictor", () => {
  let predictor: DriverAvailabilityPredictor;

  beforeEach(() => {
    predictor = new DriverAvailabilityPredictor();
  });

  describe("predict", () => {
    it("should return prediction with high probability for favorable conditions", () => {
      const prediction = predictor.predict(
        "driver-001",
        "clear",
        30, // low traffic
        1, // recent loads
      );

      expect(prediction.availabilityProbability).toBeGreaterThan(0.7);
      expect(prediction.confidence).toBeGreaterThan(0.85);
      expect(prediction.recommendation).toMatch(/HIGH|MEDIUM/);
    });

    it("should return lower probability for unfavorable conditions", () => {
      const prediction = predictor.predict(
        "driver-002",
        "snow",
        80, // high traffic
        5, // many recent loads
      );

      expect(prediction.availabilityProbability).toBeLessThan(0.6);
      expect(prediction.confidence).toBeGreaterThan(0.75);
    });

    it("should have all required factor fields", () => {
      const prediction = predictor.predict("driver-003", "clear", 50, 0);

      expect(prediction.factors).toHaveProperty("timeOfDay");
      expect(prediction.factors).toHaveProperty("dayOfWeek");
      expect(prediction.factors).toHaveProperty("weather");
      expect(prediction.factors).toHaveProperty("traffic");
      expect(prediction.factors).toHaveProperty("recentActivity");
      expect(prediction.factors).toHaveProperty("historicalPattern");
    });

    it("should return estimated time on online", () => {
      const prediction = predictor.predict("driver-004", "clear", 50, 0);

      expect(prediction.estimatedTimeOnline).toBeGreaterThan(0);
      expect(prediction.estimatedTimeOnline).toBeLessThanOrEqual(480); // max 8 hours
    });
  });

  describe("trainModel", () => {
    it("should achieve 87%+ accuracy on training data", () => {
      const historicalData = Array.from({ length: 1000 }, (_, i) => ({
        driverId: `driver-${i}`,
        timeOfDay: Math.random(),
        dayOfWeek: Math.random(),
        weather: ["clear", "rain", "snow"][Math.floor(Math.random() * 3)],
        trafficLevel: Math.random() * 100,
        recentLoads: Math.floor(Math.random() * 10),
        available: Math.random() > 0.5,
      }));

      const metrics = predictor.trainModel(historicalData);

      expect(metrics.accuracy).toBeGreaterThanOrEqual(0.87);
      expect(metrics.precision).toBeGreaterThanOrEqual(0.85);
      expect(metrics.recall).toBeGreaterThanOrEqual(0.85);
      expect(metrics.f1Score).toBeGreaterThanOrEqual(0.85);
    });
  });

  describe("getDispatchRecommendations", () => {
    it("should return ranked drivers by availability", () => {
      const drivers = [
        { id: "driver-1", available: true },
        { id: "driver-2", available: true },
        { id: "driver-3", available: false },
      ];

      const recommendations = predictor.getDispatchRecommendations(
        drivers as any[],
      );

      expect(recommendations.length).toBeLessThanOrEqual(drivers.length);
      expect(recommendations[0].score).toBeGreaterThanOrEqual(
        recommendations[recommendations.length - 1].score,
      );
    });

    it("should include confidence scores", () => {
      const drivers = [{ id: "driver-1", available: true }];

      const recommendations = predictor.getDispatchRecommendations(
        drivers as any[],
      );

      expect(recommendations[0]).toHaveProperty("confidence");
      expect(recommendations[0].confidence).toBeGreaterThan(0);
      expect(recommendations[0].confidence).toBeLessThanOrEqual(1);
    });
  });
});
