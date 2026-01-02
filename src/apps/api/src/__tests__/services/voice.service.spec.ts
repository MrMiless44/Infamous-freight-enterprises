import { VoiceService } from "../../services/voiceService";
import Twilio from "twilio";

jest.mock("twilio");

describe("VoiceService", () => {
  let voiceService: VoiceService;

  beforeEach(() => {
    jest.clearAllMocks();
    voiceService = new VoiceService();
  });

  describe("ingestVoiceCall", () => {
    it("should ingest voice call", async () => {
      const callData = {
        phoneNumber: "+15551234567",
        audioUrl: "https://example.com/audio.mp3",
      };

      const result = await voiceService.ingestVoiceCall(callData);

      expect(result).toHaveProperty("callId");
      expect(result).toHaveProperty("status", "received");
    });

    it("should validate phone number", async () => {
      const callData = {
        phoneNumber: "invalid",
        audioUrl: "https://example.com/audio.mp3",
      };

      await expect(voiceService.ingestVoiceCall(callData)).rejects.toThrow();
    });
  });

  describe("transcribeAudio", () => {
    it("should transcribe audio successfully", async () => {
      const result = await voiceService.transcribeAudio(
        "https://example.com/audio.mp3",
        "en",
      );

      expect(result).toHaveProperty("transcript");
      expect(typeof result.transcript).toBe("string");
      expect(result.transcript.length).toBeGreaterThan(0);
    });

    it("should handle different languages", async () => {
      const result = await voiceService.transcribeAudio(
        "https://example.com/audio.mp3",
        "es",
      );

      expect(result).toHaveProperty("transcript");
      expect(result).toHaveProperty("language", "es");
    });

    it("should handle transcription errors", async () => {
      await expect(
        voiceService.transcribeAudio("invalid-url", "en"),
      ).rejects.toThrow();
    });
  });

  describe("processVoiceCommand", () => {
    it("should process voice command", async () => {
      const result = await voiceService.processVoiceCommand(
        "Find me a driver for New York",
      );

      expect(result).toHaveProperty("action");
      expect(result).toHaveProperty("confidence");
    });

    it("should extract parameters from command", async () => {
      const result = await voiceService.processVoiceCommand(
        "Schedule shipment from Boston to Chicago",
      );

      expect(result).toHaveProperty("parameters");
      expect(result.parameters).toHaveProperty("origin");
      expect(result.parameters).toHaveProperty("destination");
    });
  });

  describe("initiateCall", () => {
    it("should initiate outbound call", async () => {
      const result = await voiceService.initiateCall({
        toNumber: "+15551234567",
        fromNumber: "+15559999999",
        message: "Your shipment has arrived",
      });

      expect(result).toHaveProperty("callSid");
      expect(result).toHaveProperty("status");
    });
  });

  describe("recordCall", () => {
    it("should record call", async () => {
      const result = await voiceService.recordCall("call-123");

      expect(result).toHaveProperty("recordingUrl");
      expect(result).toHaveProperty("duration");
    });
  });

  describe("getCallHistory", () => {
    it("should retrieve call history", async () => {
      const result = await voiceService.getCallHistory("+15551234567");

      expect(Array.isArray(result)).toBe(true);
      result.forEach((call: any) => {
        expect(call).toHaveProperty("callId");
        expect(call).toHaveProperty("duration");
      });
    });
  });
});
