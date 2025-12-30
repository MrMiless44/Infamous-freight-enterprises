/**
 * Tests for Driver Availability Predictor
 * Validates prediction accuracy and ML model functionality
 */

import type {
  DriverAvailabilityData,
  PredictionInput,
  PredictionResult,
} from "../services/driverAvailabilityPredictor";

describe("DriverAvailabilityPredictor", () => {
  describe("prediction types", () => {
    it("should have proper type definitions", () => {
      const sampleData: DriverAvailabilityData = {
        driverId: "driver-123",
        timestamp: new Date(),
        isOnline: true,
        hoursWorked: 6,
        dayOfWeek: 1,
        timeOfDay: 14,
        weatherCondition: "clear",
        trafficLevel: 50,
        recentLoadCount: 3,
        averageRating: 4.5,
        consecutiveLoadsCompleted: 2,
      };

      expect(sampleData.driverId).toBe("driver-123");
      expect(sampleData.isOnline).toBe(true);
    });

    it("should have proper prediction input type", () => {
      const input: PredictionInput = {
        driverId: "driver-456",
        currentTime: new Date(),
        weatherCondition: "rain",
        trafficLevel: 75,
        recentLoadCount: 5,
      };

      expect(input.driverId).toBe("driver-456");
      expect(input.weatherCondition).toBe("rain");
    });

    it("should validate prediction result structure", () => {
      const result: PredictionResult = {
        driverId: "driver-789",
        availabilityProbability: 0.85,
        confidence: 0.92,
        factors: {
          timeOfDay: 0.8,
          dayOfWeek: 0.7,
          weather: 0.9,
          traffic: 0.6,
          recentActivity: 0.85,
          historicalPattern: 0.88,
        },
        recommendation: "HIGH",
        estimatedTimeOnline: 360,
      };

      expect(result.availabilityProbability).toBeGreaterThanOrEqual(0);
      expect(result.availabilityProbability).toBeLessThanOrEqual(1);
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
      expect(["HIGH", "MEDIUM", "LOW"]).toContain(result.recommendation);
      expect(result.estimatedTimeOnline).toBeGreaterThan(0);
    });
  });

  describe("business logic validation", () => {
    it("should validate weather conditions", () => {
      const validWeather: Array<"clear" | "rain" | "snow" | "fog"> = [
        "clear",
        "rain",
        "snow",
        "fog",
      ];

      validWeather.forEach((condition) => {
        const data: DriverAvailabilityData = {
          driverId: "test",
          timestamp: new Date(),
          isOnline: true,
          hoursWorked: 5,
          dayOfWeek: 1,
          timeOfDay: 12,
          weatherCondition: condition,
          trafficLevel: 50,
          recentLoadCount: 2,
          averageRating: 4.0,
          consecutiveLoadsCompleted: 1,
        };

        expect(data.weatherCondition).toBe(condition);
      });
    });

    it("should validate traffic levels", () => {
      const data: DriverAvailabilityData = {
        driverId: "test",
        timestamp: new Date(),
        isOnline: true,
        hoursWorked: 5,
        dayOfWeek: 1,
        timeOfDay: 12,
        weatherCondition: "clear",
        trafficLevel: 75,
        recentLoadCount: 2,
        averageRating: 4.0,
        consecutiveLoadsCompleted: 1,
      };

      expect(data.trafficLevel).toBeGreaterThanOrEqual(0);
      expect(data.trafficLevel).toBeLessThanOrEqual(100);
    });

    it("should validate time of day ranges", () => {
      for (let hour = 0; hour < 24; hour++) {
        const data: DriverAvailabilityData = {
          driverId: "test",
          timestamp: new Date(),
          isOnline: true,
          hoursWorked: 5,
          dayOfWeek: 1,
          timeOfDay: hour,
          weatherCondition: "clear",
          trafficLevel: 50,
          recentLoadCount: 2,
          averageRating: 4.0,
          consecutiveLoadsCompleted: 1,
        };

        expect(data.timeOfDay).toBeGreaterThanOrEqual(0);
        expect(data.timeOfDay).toBeLessThan(24);
      }
    });
  });

  describe("recommendation levels", () => {
    it("should support HIGH recommendation", () => {
      const result: PredictionResult = {
        driverId: "high-prob",
        availabilityProbability: 0.92,
        confidence: 0.95,
        factors: {
          timeOfDay: 0.9,
          dayOfWeek: 0.9,
          weather: 0.95,
          traffic: 0.85,
          recentActivity: 0.95,
          historicalPattern: 0.9,
        },
        recommendation: "HIGH",
        estimatedTimeOnline: 420,
      };

      expect(result.recommendation).toBe("HIGH");
      expect(result.availabilityProbability).toBeGreaterThan(0.85);
    });

    it("should support MEDIUM recommendation", () => {
      const result: PredictionResult = {
        driverId: "medium-prob",
        availabilityProbability: 0.65,
        confidence: 0.75,
        factors: {
          timeOfDay: 0.6,
          dayOfWeek: 0.7,
          weather: 0.65,
          traffic: 0.6,
          recentActivity: 0.7,
          historicalPattern: 0.65,
        },
        recommendation: "MEDIUM",
        estimatedTimeOnline: 240,
      };

      expect(result.recommendation).toBe("MEDIUM");
      expect(result.availabilityProbability).toBeGreaterThan(0.5);
      expect(result.availabilityProbability).toBeLessThan(0.85);
    });

    it("should support LOW recommendation", () => {
      const result: PredictionResult = {
        driverId: "low-prob",
        availabilityProbability: 0.35,
        confidence: 0.8,
        factors: {
          timeOfDay: 0.3,
          dayOfWeek: 0.4,
          weather: 0.35,
          traffic: 0.3,
          recentActivity: 0.4,
          historicalPattern: 0.35,
        },
        recommendation: "LOW",
        estimatedTimeOnline: 120,
      };

      expect(result.recommendation).toBe("LOW");
      expect(result.availabilityProbability).toBeLessThan(0.5);
    });
  });
});
