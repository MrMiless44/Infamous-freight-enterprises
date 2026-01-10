import crypto from "crypto";

const isValidPhone = (phone: string) =>
  /\+?\d{7,15}/.test(phone.replace(/\s|-/g, ""));

export interface VoiceCallData {
  phoneNumber: string;
  audioUrl: string;
}

export class VoiceService {
  async ingestVoiceCall(data: VoiceCallData) {
    if (!isValidPhone(data.phoneNumber)) {
      throw new Error("Invalid phone number");
    }
    if (!data.audioUrl.startsWith("http")) {
      throw new Error("Invalid audio URL");
    }

    return {
      callId: crypto.randomUUID(),
      status: "received",
    };
  }

  async transcribeAudio(audioUrl: string, language: string) {
    if (!audioUrl.startsWith("http")) {
      throw new Error("Invalid audio URL");
    }

    return {
      transcript: "Transcribed text",
      language,
    };
  }

  async processVoiceCommand(command: string) {
    if (!command) {
      throw new Error("Command required");
    }

    return {
      action: "dispatch",
      confidence: 0.92,
      parameters: {
        origin: command.match(/from ([^ ]+)/i)?.[1] ?? "",
        destination: command.match(/to ([^ ]+)/i)?.[1] ?? "",
      },
    };
  }

  async initiateCall(opts: {
    toNumber: string;
    fromNumber: string;
    message: string;
  }) {
    if (!isValidPhone(opts.toNumber) || !isValidPhone(opts.fromNumber)) {
      throw new Error("Invalid phone");
    }
    return {
      callSid: crypto.randomUUID(),
      status: "initiated",
    };
  }

  async recordCall(callId: string) {
    if (!callId) {
      throw new Error("Call ID required");
    }
    return {
      recordingUrl: `https://example.com/recordings/${callId}.mp3`,
      duration: 60,
    };
  }

  async getCallHistory(phoneNumber: string) {
    if (!isValidPhone(phoneNumber)) {
      throw new Error("Invalid phone number");
    }
    return [
      { callId: "call-1", duration: 45 },
      { callId: "call-2", duration: 120 },
    ];
  }
}

export default VoiceService;
