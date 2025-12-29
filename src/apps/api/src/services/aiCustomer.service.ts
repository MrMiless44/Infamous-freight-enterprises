import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

interface SupportRequest {
  question: string;
  customerId?: string;
  context?: unknown;
}

interface SupportResponse {
  answer: string;
  suggestions: string[];
  confidence: number;
  escalationNeeded: boolean;
}

export async function getSupport(
  request: SupportRequest,
): Promise<SupportResponse> {
  const { question, customerId } = request;

  // Simple keyword-based AI support
  const lowerQuestion = question.toLowerCase();

  let answer = "";
  const suggestions: string[] = [];
  let confidence = 0.7;
  let escalationNeeded = false;

  // Tracking questions
  if (
    lowerQuestion.includes("track") ||
    lowerQuestion.includes("where") ||
    lowerQuestion.includes("status")
  ) {
    answer =
      "You can track your shipment by visiting the tracking page with your load number. Our system provides real-time updates on your load's location and estimated delivery time.";
    suggestions.push("View tracking page");
    suggestions.push("Contact your assigned driver");
    confidence = 0.9;
  }
  // Pricing questions
  else if (
    lowerQuestion.includes("cost") ||
    lowerQuestion.includes("price") ||
    lowerQuestion.includes("rate")
  ) {
    answer =
      "Pricing depends on distance, weight, and delivery timeline. You can get an instant quote by using our quote calculator or contacting our dispatch team.";
    suggestions.push("Get instant quote");
    suggestions.push("Contact dispatch");
    confidence = 0.85;
  }
  // Delivery time questions
  else if (
    lowerQuestion.includes("how long") ||
    lowerQuestion.includes("delivery time") ||
    lowerQuestion.includes("eta")
  ) {
    answer =
      "Delivery times vary based on distance and route complexity. Standard deliveries typically take 2-5 business days. Expedited options are available for urgent shipments.";
    suggestions.push("View delivery estimates");
    suggestions.push("Upgrade to expedited delivery");
    confidence = 0.8;
  }
  // Issues or complaints
  else if (
    lowerQuestion.includes("problem") ||
    lowerQuestion.includes("issue") ||
    lowerQuestion.includes("complaint") ||
    lowerQuestion.includes("damage")
  ) {
    answer =
      "I'm sorry to hear you're experiencing an issue. I'll connect you with our customer support team who can help resolve this immediately.";
    suggestions.push("File a claim");
    suggestions.push("Speak with support team");
    escalationNeeded = true;
    confidence = 0.95;
  }
  // Generic fallback
  else {
    answer =
      "I'd be happy to help! Could you provide more details about your question? You can also contact our support team directly for immediate assistance.";
    suggestions.push("Contact support");
    suggestions.push("View FAQ");
    confidence = 0.6;
    escalationNeeded = true;
  }

  return {
    answer,
    suggestions,
    confidence,
    escalationNeeded,
  };
}

export default {
  getSupport,
};
