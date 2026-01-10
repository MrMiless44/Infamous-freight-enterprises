/**
 * Customer Ops AI Role
 *
 * Handles customer inquiries, shipment status updates, proactive communication,
 * and issue escalation.
 */

import type {
  RoleContract,
  DecisionInput,
  DecisionResult,
  RoleContext,
  ConfidenceScore,
  GuardrailViolation,
} from "../contracts";
import { logDecision } from "../observability/logger";

/**
 * Helper: Generate customer response
 */
async function generateCustomerResponse(
  input: DecisionInput,
): Promise<Record<string, unknown>> {
  const params = input.parameters;
  const query = params.query || "";
  const customer = params.customer || {};
  const shipment = params.shipment || {};

  const action = input.action;
  const queryLower = query.toLowerCase();

  switch (action) {
    case "inquiry-handling": {
      // Determine query intent
      let responseType = "general";
      let message = "";
      let escalationNeeded = false;
      let suggestedActions: string[] = [];

      // Status inquiries
      if (
        queryLower.includes("where") ||
        queryLower.includes("status") ||
        queryLower.includes("track")
      ) {
        responseType = "status-update";
        const status = shipment.status || "in-transit";
        const location = shipment.currentLocation || "Distribution Center";
        const estimatedDelivery =
          shipment.estimatedDelivery ||
          new Date(Date.now() + 86400000).toISOString();

        message = `Your shipment #${shipment.id || "N/A"} is currently ${status.replace("-", " ")} at ${location}. Estimated delivery: ${new Date(estimatedDelivery).toLocaleDateString("en-US", { weekday: "long", month: "short", day: "numeric" })} by 5 PM.`;
        suggestedActions = [
          "View real-time tracking map",
          "Set delivery alerts",
          "Contact carrier for details",
        ];
      }
      // Delay inquiries
      else if (
        queryLower.includes("delay") ||
        queryLower.includes("late") ||
        queryLower.includes("when")
      ) {
        responseType = "delay-explanation";
        const delayReason = params.delayReason || "weather conditions";
        const newEstimate =
          shipment.revisedDelivery ||
          new Date(Date.now() + 172800000).toISOString();

        message = `We sincerely apologize for the delay. Your shipment has been affected by ${delayReason}. Our new estimated delivery is ${new Date(newEstimate).toLocaleDateString("en-US", { weekday: "long", month: "short", day: "numeric" })}. We're actively monitoring and will provide updates every 4 hours.`;
        suggestedActions = [
          "View detailed delay explanation",
          "Request expedited delivery (if available)",
          "Speak with customer service manager",
        ];
        escalationNeeded =
          queryLower.includes("frustrated") ||
          queryLower.includes("unacceptable");
      }
      // Damage/claims
      else if (
        queryLower.includes("damage") ||
        queryLower.includes("broken") ||
        queryLower.includes("claim")
      ) {
        responseType = "claims-process";
        message =
          "I'm sorry to hear about the damage. Please document the damage with photos and submit a claim within 48 hours. Our claims team will review and respond within 2 business days. Typical claims are processed in 5-7 days.";
        suggestedActions = [
          "Start damage claim",
          "Upload photos",
          "Speak with claims specialist",
        ];
        escalationNeeded = true;
      }
      // Pricing inquiries
      else if (
        queryLower.includes("cost") ||
        queryLower.includes("price") ||
        queryLower.includes("quote")
      ) {
        responseType = "pricing-inquiry";
        message =
          "For custom pricing and quotes, our sales team will provide the most accurate information based on your specific shipment needs. I can connect you with a representative right away.";
        suggestedActions = [
          "Request custom quote",
          "View standard rates",
          "Schedule sales call",
        ];
        escalationNeeded = true; // Escalate to sales
      }
      // General inquiries
      else {
        responseType = "general-info";
        message =
          "Thank you for contacting us. How can I help you today? I can assist with shipment tracking, delivery schedules, account information, or connect you with a specialist for specific needs.";
        suggestedActions = [
          "Track shipment",
          "View account details",
          "Contact support team",
        ];
      }

      return {
        responseType,
        message,
        tone: escalationNeeded ? "empathetic" : "helpful",
        escalationNeeded,
        suggestedActions,
        sentiment: params.customerSentiment || "neutral",
        trackingInfo: shipment.status
          ? {
              status: shipment.status,
              location: shipment.currentLocation,
              estimatedDelivery: shipment.estimatedDelivery,
            }
          : null,
      };
    }

    case "proactive-communication": {
      // Generate proactive notifications
      const eventType = params.eventType || "delivery-today";
      let subject = "";
      let message = "";

      switch (eventType) {
        case "delivery-today":
          subject = "Your delivery arrives today!";
          message = `Good news! Your shipment #${shipment.id} will be delivered today between 2-6 PM. Please ensure someone is available to receive it.`;
          break;
        case "delay-notification":
          subject = "Shipment delay notification";
          message = `We wanted to notify you that your shipment #${shipment.id} has been delayed by approximately ${params.delayHours || 24} hours due to ${params.delayReason || "unforeseen circumstances"}. We apologize for the inconvenience.`;
          break;
        case "out-for-delivery":
          subject = "Out for delivery";
          message = `Your shipment #${shipment.id} is out for delivery and will arrive within the next 4 hours. Track in real-time using your tracking link.`;
          break;
        case "delivered":
          subject = "Delivery complete";
          message = `Your shipment #${shipment.id} has been successfully delivered. Thank you for choosing Infæmous Freight!`;
          break;
        default:
          subject = "Shipment update";
          message = `Update on your shipment #${shipment.id}.`;
      }

      return {
        notificationType: eventType,
        channel: params.preferredChannel || "email",
        subject,
        message,
        priority: eventType === "delay-notification" ? "high" : "normal",
        actionRequired: eventType === "delivery-today",
      };
    }

    case "satisfaction-tracking": {
      return {
        surveyType: "post-delivery",
        questions: [
          "How satisfied were you with the delivery time?",
          "Was your shipment in good condition?",
          "How would you rate our communication?",
          "Would you recommend our service?",
        ],
        channel: "email",
        timing: "Send 24 hours after delivery",
        incentive: params.offerIncentive
          ? "$10 account credit for completing survey"
          : null,
      };
    }

    default:
      return {
        message: `Action '${action}' not implemented`,
        supportedActions: [
          "inquiry-handling",
          "proactive-communication",
          "satisfaction-tracking",
        ],
      };
  }
}

/**
 * Customer Ops AI Role Implementation
 */
export const customerOpsRole: RoleContract = {
  name: "customer-ops",
  version: "1.0.0",
  description:
    "AI role for customer operations, inquiry handling, and communication",
  confidenceThreshold: 0.9,
  capabilities: [
    "inquiry-handling",
    "status-updates",
    "proactive-communication",
    "issue-escalation",
    "satisfaction-tracking",
  ],

  async decide(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<DecisionResult> {
    const decisionId = `custops-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const violations = await this.checkGuardrails(input, context);
    const confidence = await this.calculateConfidence(input, context);
    const recommendation = await generateCustomerResponse(input);

    await logDecision({
      decisionId,
      timestamp: context.timestamp,
      role: this.name,
      userId: context.userId,
      requestId: context.requestId,
      action: input.action,
      input: input.parameters,
      confidence,
      recommendation,
      requiresHumanReview: confidence.value < this.confidenceThreshold,
    });

    return {
      decisionId,
      confidence,
      recommendation,
      requiresHumanReview: confidence.value < this.confidenceThreshold,
      guardrailViolations: violations,
    };
  },

  async checkGuardrails(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<GuardrailViolation[]> {
    const violations: GuardrailViolation[] = [];

    // Cannot make pricing decisions
    if (
      input.action.includes("price") ||
      input.action.includes("rate") ||
      input.action.includes("quote")
    ) {
      violations.push({
        type: "policy",
        severity: "high",
        description: "Customer Ops AI cannot make pricing or rate decisions",
        remediation: "Escalate to sales team for pricing decisions",
      });
    }

    // Cannot issue refunds without approval
    if (
      (input.action.includes("refund") || input.action.includes("credit")) &&
      !input.parameters.humanApproval
    ) {
      violations.push({
        type: "policy",
        severity: "high",
        description: "Cannot issue refunds or credits without human approval",
        remediation: "Obtain approval from customer service manager",
      });
    }

    // Cannot access customer financial information
    if (
      JSON.stringify(input)
        .toLowerCase()
        .match(/payment|credit.?card|bank|financial/)
    ) {
      violations.push({
        type: "data-access",
        severity: "critical",
        description: "Cannot access customer payment or financial information",
        remediation: "Limit to shipment and communication data only",
      });
    }

    return violations;
  },

  async calculateConfidence(
    input: DecisionInput,
    context: RoleContext,
  ): Promise<ConfidenceScore> {
    const params = input.parameters;
    const query = params.query || "";
    const customerHistory = params.customerHistory || {};

    // Query complexity assessment
    const queryWords = query.split(" ").length;
    const complexKeywords = [
      "refund",
      "damage",
      "claim",
      "legal",
      "manager",
      "complaint",
    ];
    const isComplex = complexKeywords.some((keyword) =>
      query.toLowerCase().includes(keyword),
    );

    let queryComplexity = 1.0;
    if (isComplex) queryComplexity = 0.6;
    else if (queryWords > 30) queryComplexity = 0.75;
    else if (queryWords > 15) queryComplexity = 0.85;

    // Data completeness
    const hasShipmentData =
      params.shipment && Object.keys(params.shipment).length > 0;
    const hasCustomerData =
      params.customer && Object.keys(params.customer).length > 0;
    const dataCompleteness =
      (hasShipmentData ? 0.5 : 0) + (hasCustomerData ? 0.5 : 0);

    // Historical resolution rate
    const historicalResolution = customerHistory.successfulResolutions || 0;
    const historicalTotal = customerHistory.totalInquiries || 1;
    const resolutionRate = historicalResolution / historicalTotal;

    // Model certainty (NLP models for customer service)
    const modelCertainty = 0.88;

    // Sentiment analysis confidence
    const sentimentClarity =
      params.customerSentiment &&
      ["positive", "negative", "neutral"].includes(params.customerSentiment)
        ? 0.95
        : 0.7;

    // Calculate weighted confidence
    const confidence =
      queryComplexity * 0.3 +
      dataCompleteness * 0.25 +
      resolutionRate * 0.2 +
      modelCertainty * 0.15 +
      sentimentClarity * 0.1;

    const reasoningParts = [];
    if (isComplex)
      reasoningParts.push("complex query requiring human judgment");
    if (dataCompleteness < 0.5)
      reasoningParts.push("incomplete shipment/customer data");
    if (resolutionRate < 0.8)
      reasoningParts.push("lower historical resolution rate");
    if (!params.customerSentiment) reasoningParts.push("sentiment unclear");

    return {
      value: Math.min(0.95, confidence),
      reasoning:
        reasoningParts.length > 0
          ? `Customer ops confidence: ${reasoningParts.join(", ")}`
          : "Straightforward query with complete data and high historical resolution rate",
      factors: {
        queryComplexity,
        dataCompleteness,
        historicalResolutionRate: resolutionRate,
        modelCertainty,
        sentimentClarity,
      },
    };
  },
};

export default customerOpsRole;
