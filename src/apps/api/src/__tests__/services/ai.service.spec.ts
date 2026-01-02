import { AIService } from "../../services/aiService";
import { OpenAI } from "openai";
import { Anthropic } from "@anthropic-ai/sdk";

jest.mock("openai");
jest.mock("@anthropic-ai/sdk");

describe("AIService", () => {
  let aiService: AIService;

  beforeEach(() => {
    jest.clearAllMocks();
    aiService = new AIService();
  });

  describe("processCommand", () => {
    it("should process voice command", async () => {
      const command = "Find me a driver for pickup in New York";

      const result = await aiService.processCommand(command);

      expect(result).toHaveProperty("action");
      expect(result).toHaveProperty("confidence");
    });

    it("should handle complex commands", async () => {
      const command =
        "Schedule a shipment from Boston to Chicago with priority handling";

      const result = await aiService.processCommand(command);

      expect(result).toHaveProperty("action");
      expect(result.action).toMatch(/schedule|create|dispatch|route/i);
    });

    it("should validate command text", async () => {
      await expect(aiService.processCommand("")).rejects.toThrow();
    });
  });

  describe("generateResponse", () => {
    it("should generate contextual response", async () => {
      const prompt = "What is the status of shipment #123?";
      const context = { shipmentId: "ship-123" };

      const result = await aiService.generateResponse(prompt, context);

      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
    });
  });

  describe("analyzeRoute", () => {
    it("should analyze route efficiency", async () => {
      const waypoints = [
        { lat: 40.7128, lng: -74.006 },
        { lat: 40.758, lng: -73.9855 },
        { lat: 40.7489, lng: -73.968 },
      ];

      const result = await aiService.analyzeRoute(waypoints);

      expect(result).toHaveProperty("suggestions");
      expect(result).toHaveProperty("optimizationScore");
    });

    it("should detect inefficiencies", async () => {
      const waypoints = [
        { lat: 40.7128, lng: -74.006 },
        { lat: 40.7128, lng: -74.006 }, // Duplicate
        { lat: 40.758, lng: -73.9855 },
      ];

      const result = await aiService.analyzeRoute(waypoints);

      expect(result.suggestions).toContain(
        expect.stringContaining(/duplicate|ineffic/i),
      );
    });
  });

  describe("predictDeliveryTime", () => {
    it("should predict delivery time", async () => {
      const prediction = await aiService.predictDeliveryTime({
        origin: { lat: 40.7128, lng: -74.006 },
        destination: { lat: 40.758, lng: -73.9855 },
        weight: 5000,
        serviceType: "standard",
      });

      expect(prediction).toHaveProperty("estimatedMinutes");
      expect(prediction).toHaveProperty("confidence");
      expect(prediction.estimatedMinutes).toBeGreaterThan(0);
    });
  });

  describe("sentimentAnalysis", () => {
    it("should analyze positive sentiment", async () => {
      const result = await aiService.analyzeSentiment(
        "The delivery was excellent and on time!",
      );

      expect(result).toHaveProperty("sentiment");
      expect(result.sentiment).toMatch(/positive|good/i);
      expect(result).toHaveProperty("score");
      expect(result.score).toBeGreaterThan(0.5);
    });

    it("should analyze negative sentiment", async () => {
      const result = await aiService.analyzeSentiment(
        "The delivery was late and damaged",
      );

      expect(result).toHaveProperty("sentiment");
      expect(result.sentiment).toMatch(/negative|bad/i);
      expect(result.score).toBeLessThan(0.5);
    });
  });

  describe("demandForecast", () => {
    it("should forecast demand", async () => {
      const forecast = await aiService.forecastDemand("Northeast", 7);

      expect(forecast).toHaveProperty("forecast");
      expect(Array.isArray(forecast.forecast)).toBe(true);
      expect(forecast.forecast.length).toBeGreaterThan(0);
    });

    it("should include confidence intervals", async () => {
      const forecast = await aiService.forecastDemand("Northeast", 7);

      forecast.forecast.forEach((day: any) => {
        expect(day).toHaveProperty("prediction");
        expect(day).toHaveProperty("confidence");
      });
    });
  });
});
