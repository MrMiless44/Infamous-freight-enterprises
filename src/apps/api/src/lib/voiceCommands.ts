/**
 * Voice Commands Integration
 * Alexa and Google Assistant integration for hands-free shipment management
 */

import axios from "axios";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/**
 * Alexa Skill handler
 */
export class AlexaSkillHandler {
  /**
   * Handle Alexa request
   */
  async handleRequest(request: any): Promise<any> {
    const requestType = request.request.type;

    if (requestType === "LaunchRequest") {
      return this.buildResponse(
        "Welcome to Infamous Freight. You can ask about your shipments, create new shipments, or check driver status. What would you like to do?",
      );
    }

    if (requestType === "IntentRequest") {
      const intentName = request.request.intent.name;

      switch (intentName) {
        case "TrackShipmentIntent":
          return await this.handleTrackShipment(request);
        case "CreateShipmentIntent":
          return await this.handleCreateShipment(request);
        case "CheckDriverStatusIntent":
          return await this.handleCheckDriverStatus(request);
        case "GetShipmentCountIntent":
          return await this.handleGetShipmentCount(request);
        case "AMAZON.HelpIntent":
          return this.buildResponse(
            "You can say things like: track shipment INF-2024-001, create a new shipment, or check driver status.",
          );
        case "AMAZON.CancelIntent":
        case "AMAZON.StopIntent":
          return this.buildResponse("Goodbye!", true);
        default:
          return this.buildResponse(
            "I didn't understand that. Please try again.",
          );
      }
    }

    return this.buildResponse("Something went wrong. Please try again.");
  }

  /**
   * Track shipment intent
   */
  private async handleTrackShipment(request: any): Promise<any> {
    const trackingNumber = request.request.intent.slots.TrackingNumber?.value;

    if (!trackingNumber) {
      return this.buildResponse(
        "Please provide a tracking number. You can say: track shipment INF-2024-001",
      );
    }

    try {
      const shipment = await prisma.shipment.findUnique({
        where: { trackingNumber },
        include: {
          driver: {
            include: { user: true },
          },
        },
      });

      if (!shipment) {
        return this.buildResponse(
          `I couldn't find shipment ${trackingNumber}. Please check the tracking number and try again.`,
        );
      }

      let statusMessage = `Your shipment ${trackingNumber} is currently ${shipment.status.toLowerCase().replace("_", " ")}.`;

      if (shipment.status === "IN_TRANSIT" && shipment.driver) {
        statusMessage += ` It's being delivered by ${shipment.driver.user.name}.`;
      }

      if (shipment.status === "DELIVERED" && shipment.deliveryTime) {
        statusMessage += ` It was delivered on ${new Date(shipment.deliveryTime).toLocaleDateString()}.`;
      }

      return this.buildResponse(statusMessage);
    } catch (error) {
      console.error("Alexa track shipment error:", error);
      return this.buildResponse(
        "Sorry, I had trouble tracking that shipment. Please try again later.",
      );
    }
  }

  /**
   * Create shipment intent
   */
  private async handleCreateShipment(request: any): Promise<any> {
    const origin = request.request.intent.slots.Origin?.value;
    const destination = request.request.intent.slots.Destination?.value;

    if (!origin || !destination) {
      return this.buildResponse(
        "To create a shipment, please provide both origin and destination. For example: create shipment from New York to Los Angeles.",
      );
    }

    // Note: In production, you'd need user authentication via Account Linking
    return this.buildResponse(
      `I've started creating a shipment from ${origin} to ${destination}. Please complete the details in the Infamous Freight app.`,
    );
  }

  /**
   * Check driver status intent
   */
  private async handleCheckDriverStatus(request: any): Promise<any> {
    const driverName = request.request.intent.slots.DriverName?.value;

    if (!driverName) {
      return this.buildResponse("Which driver would you like to check on?");
    }

    try {
      const driver = await prisma.driver.findFirst({
        where: {
          user: {
            name: {
              contains: driverName,
              mode: "insensitive",
            },
          },
        },
        include: {
          user: true,
          assignedShipments: {
            where: {
              status: "IN_TRANSIT",
            },
          },
        },
      });

      if (!driver) {
        return this.buildResponse(
          `I couldn't find a driver named ${driverName}.`,
        );
      }

      const activeShipments = driver.assignedShipments.length;
      let message = `${driver.user.name} is currently ${driver.status.toLowerCase()}.`;

      if (activeShipments > 0) {
        message += ` They have ${activeShipments} active ${activeShipments === 1 ? "shipment" : "shipments"}.`;
      }

      return this.buildResponse(message);
    } catch (error) {
      console.error("Alexa check driver error:", error);
      return this.buildResponse(
        "Sorry, I had trouble checking driver status. Please try again later.",
      );
    }
  }

  /**
   * Get shipment count intent
   */
  private async handleGetShipmentCount(request: any): Promise<any> {
    try {
      const [active, delivered, pending] = await Promise.all([
        prisma.shipment.count({ where: { status: "IN_TRANSIT" } }),
        prisma.shipment.count({ where: { status: "DELIVERED" } }),
        prisma.shipment.count({ where: { status: "PENDING" } }),
      ]);

      return this.buildResponse(
        `You currently have ${active} shipments in transit, ${pending} pending, and ${delivered} delivered today.`,
      );
    } catch (error) {
      console.error("Alexa get count error:", error);
      return this.buildResponse(
        "Sorry, I had trouble getting shipment counts. Please try again later.",
      );
    }
  }

  /**
   * Build Alexa response
   */
  private buildResponse(
    speechText: string,
    shouldEndSession: boolean = false,
  ): any {
    return {
      version: "1.0",
      response: {
        outputSpeech: {
          type: "PlainText",
          text: speechText,
        },
        shouldEndSession,
      },
    };
  }
}

/**
 * Google Assistant handler
 */
export class GoogleAssistantHandler {
  /**
   * Handle Google Assistant webhook
   */
  async handleWebhook(request: any): Promise<any> {
    const intent = request.queryResult.intent.displayName;

    switch (intent) {
      case "Track Shipment":
        return await this.handleTrackShipment(request);
      case "Create Shipment":
        return await this.handleCreateShipment(request);
      case "Check Driver Status":
        return await this.handleCheckDriverStatus(request);
      case "Get Shipment Count":
        return await this.handleGetShipmentCount(request);
      default:
        return this.buildResponse(
          "I didn't understand that. Please try again.",
        );
    }
  }

  /**
   * Track shipment intent
   */
  private async handleTrackShipment(request: any): Promise<any> {
    const trackingNumber = request.queryResult.parameters.trackingNumber;

    if (!trackingNumber) {
      return this.buildResponse("Please provide a tracking number.");
    }

    try {
      const shipment = await prisma.shipment.findUnique({
        where: { trackingNumber },
        include: { driver: { include: { user: true } } },
      });

      if (!shipment) {
        return this.buildResponse(
          `I couldn't find shipment ${trackingNumber}.`,
        );
      }

      let statusMessage = `Your shipment ${trackingNumber} is ${shipment.status.toLowerCase().replace("_", " ")}.`;

      if (shipment.status === "IN_TRANSIT" && shipment.driver) {
        statusMessage += ` Driver: ${shipment.driver.user.name}.`;
      }

      return this.buildResponse(statusMessage);
    } catch (error) {
      console.error("Google Assistant track error:", error);
      return this.buildResponse("Sorry, I had trouble tracking that shipment.");
    }
  }

  /**
   * Create shipment intent
   */
  private async handleCreateShipment(request: any): Promise<any> {
    const origin = request.queryResult.parameters.origin;
    const destination = request.queryResult.parameters.destination;

    if (!origin || !destination) {
      return this.buildResponse("Please provide both origin and destination.");
    }

    return this.buildResponse(
      `I've started creating a shipment from ${origin} to ${destination}. Please complete the details in the app.`,
    );
  }

  /**
   * Check driver status
   */
  private async handleCheckDriverStatus(request: any): Promise<any> {
    const driverName = request.queryResult.parameters.driverName;

    if (!driverName) {
      return this.buildResponse("Which driver would you like to check on?");
    }

    try {
      const driver = await prisma.driver.findFirst({
        where: {
          user: {
            name: { contains: driverName, mode: "insensitive" },
          },
        },
        include: {
          user: true,
          assignedShipments: { where: { status: "IN_TRANSIT" } },
        },
      });

      if (!driver) {
        return this.buildResponse(`I couldn't find driver ${driverName}.`);
      }

      return this.buildResponse(
        `${driver.user.name} is ${driver.status.toLowerCase()} with ${driver.assignedShipments.length} active shipments.`,
      );
    } catch (error) {
      console.error("Google Assistant driver check error:", error);
      return this.buildResponse("Sorry, I had trouble checking driver status.");
    }
  }

  /**
   * Get shipment count
   */
  private async handleGetShipmentCount(request: any): Promise<any> {
    try {
      const [active, delivered, pending] = await Promise.all([
        prisma.shipment.count({ where: { status: "IN_TRANSIT" } }),
        prisma.shipment.count({ where: { status: "DELIVERED" } }),
        prisma.shipment.count({ where: { status: "PENDING" } }),
      ]);

      return this.buildResponse(
        `You have ${active} in transit, ${pending} pending, and ${delivered} delivered today.`,
      );
    } catch (error) {
      console.error("Google Assistant count error:", error);
      return this.buildResponse(
        "Sorry, I had trouble getting shipment counts.",
      );
    }
  }

  /**
   * Build Google Assistant response
   */
  private buildResponse(text: string): any {
    return {
      fulfillmentText: text,
      fulfillmentMessages: [
        {
          text: {
            text: [text],
          },
        },
      ],
    };
  }
}

/**
 * Voice command routes setup:
 *
 * // api/src/routes/voice-commands.js
 * const express = require('express');
 * const router = express.Router();
 * const { AlexaSkillHandler, GoogleAssistantHandler } = require('../lib/voiceCommands');
 *
 * const alexaHandler = new AlexaSkillHandler();
 * const googleHandler = new GoogleAssistantHandler();
 *
 * // Alexa endpoint
 * router.post('/alexa', async (req, res) => {
 *   try {
 *     const response = await alexaHandler.handleRequest(req.body);
 *     res.json(response);
 *   } catch (error) {
 *     console.error('Alexa error:', error);
 *     res.status(500).json({ error: 'Internal server error' });
 *   }
 * });
 *
 * // Google Assistant endpoint
 * router.post('/google-assistant', async (req, res) => {
 *   try {
 *     const response = await googleHandler.handleWebhook(req.body);
 *     res.json(response);
 *   } catch (error) {
 *     console.error('Google Assistant error:', error);
 *     res.status(500).json({ error: 'Internal server error' });
 *   }
 * });
 *
 * module.exports = router;
 *
 * Example voice commands:
 * - "Alexa, ask Infamous Freight to track shipment INF-2024-001"
 * - "Alexa, ask Infamous Freight to create a shipment from New York to LA"
 * - "Alexa, ask Infamous Freight about driver John's status"
 * - "Alexa, ask Infamous Freight how many shipments are active"
 *
 * - "Hey Google, ask Infamous Freight to track my shipment"
 * - "Hey Google, tell Infamous Freight to create a shipment"
 * - "Hey Google, ask Infamous Freight about driver status"
 *
 * Benefits:
 * - Hands-free operation
 * - Perfect for drivers on the road
 * - Quick status checks
 * - Better accessibility
 * - Modern user experience
 */
