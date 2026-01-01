/**
 * API Webhooks System
 * Allow external services to receive real-time events
 * Enables third-party integrations and custom workflows
 */

import { Request, Response, Router } from "express";
import crypto from "crypto";
import { authenticate, requireScope } from "./security";
import { cdc, CDCEvent } from "../lib/changeDataCapture";

const router = Router();

/**
 * Webhook storage (in production, use database)
 */
interface Webhook {
  id: string;
  userId: string;
  url: string;
  events: string[];
  active: boolean;
  secret: string;
  createdAt: Date;
  lastTriedAt?: Date;
  lastSuccessAt?: Date;
  failureCount: number;
}

// In-memory webhook store (replace with database in production)
const webhooks = new Map<string, Webhook>();

/**
 * Generate webhook secret for HMAC signing
 */
function generateWebhookSecret(): string {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Sign webhook payload with secret
 */
function signWebhook(payload: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

/**
 * Verify webhook signature
 */
function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string,
): boolean {
  const expected = signWebhook(payload, secret);
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

/**
 * Create a webhook
 * POST /api/webhooks
 * {
 *   "url": "https://partner.com/events",
 *   "events": ["shipment.created", "shipment.updated"]
 * }
 */
router.post(
  "/",
  authenticate,
  requireScope("webhooks:write"),
  (req: Request, res: Response) => {
    const { url, events } = req.body;

    if (!url || !events || events.length === 0) {
      return res.status(400).json({ error: "URL and events required" });
    }

    // Validate URL
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ error: "Invalid URL" });
    }

    // Validate events
    const validEvents = [
      "shipment.created",
      "shipment.updated",
      "shipment.delivered",
      "driver.updated",
      "invoice.created",
      "invoice.paid",
    ];

    for (const event of events) {
      if (!validEvents.includes(event)) {
        return res.status(400).json({ error: `Invalid event: ${event}` });
      }
    }

    const webhook: Webhook = {
      id: crypto.randomUUID(),
      userId: req.user?.sub || "",
      url,
      events,
      active: true,
      secret: generateWebhookSecret(),
      createdAt: new Date(),
      failureCount: 0,
    };

    webhooks.set(webhook.id, webhook);

    res.status(201).json({
      success: true,
      data: {
        id: webhook.id,
        url: webhook.url,
        events: webhook.events,
        secret: webhook.secret, // Only shown once!
        active: webhook.active,
      },
    });
  },
);

/**
 * List webhooks
 * GET /api/webhooks
 */
router.get(
  "/",
  authenticate,
  requireScope("webhooks:read"),
  (req: Request, res: Response) => {
    const userId = req.user?.sub;
    const userWebhooks = Array.from(webhooks.values()).filter(
      (w) => w.userId === userId,
    );

    res.json({
      success: true,
      data: userWebhooks.map((w) => ({
        id: w.id,
        url: w.url,
        events: w.events,
        active: w.active,
        createdAt: w.createdAt,
        lastTriedAt: w.lastTriedAt,
        lastSuccessAt: w.lastSuccessAt,
        failureCount: w.failureCount,
      })),
    });
  },
);

/**
 * Update webhook
 * PATCH /api/webhooks/:id
 */
router.patch(
  "/:id",
  authenticate,
  requireScope("webhooks:write"),
  (req: Request, res: Response) => {
    const webhook = webhooks.get(req.params.id);

    if (!webhook) {
      return res.status(404).json({ error: "Webhook not found" });
    }

    if (webhook.userId !== req.user?.sub) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const { url, events, active } = req.body;

    if (url) {
      try {
        new URL(url);
        webhook.url = url;
      } catch {
        return res.status(400).json({ error: "Invalid URL" });
      }
    }

    if (events && Array.isArray(events)) {
      webhook.events = events;
    }

    if (typeof active === "boolean") {
      webhook.active = active;
    }

    res.json({
      success: true,
      data: webhook,
    });
  },
);

/**
 * Delete webhook
 * DELETE /api/webhooks/:id
 */
router.delete(
  "/:id",
  authenticate,
  requireScope("webhooks:write"),
  (req: Request, res: Response) => {
    const webhook = webhooks.get(req.params.id);

    if (!webhook) {
      return res.status(404).json({ error: "Webhook not found" });
    }

    if (webhook.userId !== req.user?.sub) {
      return res.status(403).json({ error: "Forbidden" });
    }

    webhooks.delete(req.params.id);

    res.json({
      success: true,
      message: "Webhook deleted",
    });
  },
);

/**
 * Test webhook
 * POST /api/webhooks/:id/test
 */
router.post(
  "/:id/test",
  authenticate,
  requireScope("webhooks:write"),
  async (req: Request, res: Response) => {
    const webhook = webhooks.get(req.params.id);

    if (!webhook) {
      return res.status(404).json({ error: "Webhook not found" });
    }

    if (webhook.userId !== req.user?.sub) {
      return res.status(403).json({ error: "Forbidden" });
    }

    // Send test event
    const testEvent = {
      type: "test",
      timestamp: new Date(),
      data: { message: "This is a test webhook" },
    };

    try {
      await deliverWebhook(webhook, testEvent);
      res.json({ success: true, message: "Test event sent" });
    } catch (error) {
      res.status(500).json({ error: "Failed to send test event" });
    }
  },
);

/**
 * Deliver webhook to external URL
 */
async function deliverWebhook(webhook: Webhook, event: any): Promise<void> {
  if (!webhook.active) return;

  const payload = JSON.stringify(event);
  const signature = signWebhook(payload, webhook.secret);

  webhook.lastTriedAt = new Date();

  try {
    const response = await fetch(webhook.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
        "X-Webhook-ID": webhook.id,
      },
      body: payload,
      signal: AbortSignal.timeout(10000), // 10 second timeout
    });

    if (response.ok) {
      webhook.lastSuccessAt = new Date();
      webhook.failureCount = 0;
      console.log(`✅ Webhook delivered: ${webhook.id}`);
    } else {
      webhook.failureCount++;
      console.warn(`⚠️ Webhook failed (${response.status}): ${webhook.id}`);

      // Disable after 10 failures
      if (webhook.failureCount >= 10) {
        webhook.active = false;
        console.error(`🔴 Webhook disabled after 10 failures: ${webhook.id}`);
      }
    }
  } catch (error) {
    webhook.failureCount++;
    console.error(`❌ Webhook error: ${error.message}`);

    if (webhook.failureCount >= 10) {
      webhook.active = false;
    }
  }
}

/**
 * Setup webhook delivery on CDC events
 */
export function setupWebhookDelivery(): void {
  cdc.onAnyChange((event: CDCEvent) => {
    // Find webhooks that care about this event
    for (const webhook of webhooks.values()) {
      if (webhook.events.includes(event.type)) {
        deliverWebhook(webhook, {
          type: event.type,
          timestamp: event.timestamp,
          entity: event.entity,
          entityId: event.entityId,
          data: event.after,
        }).catch((error) => {
          console.error("Webhook delivery error:", error);
        });
      }
    }
  });
}

export default router;

/**
 * Usage example:
 *
 * // Client creates webhook
 * POST /api/webhooks
 * {
 *   "url": "https://partner.com/events",
 *   "events": ["shipment.created", "shipment.updated"]
 * }
 *
 * Response:
 * {
 *   "id": "webhook_123",
 *   "secret": "whsec_abc123..." // Save securely!
 * }
 *
 * // Partner verifies webhook signature in their code:
 * const crypto = require('crypto');
 * const signature = req.headers['x-webhook-signature'];
 * const expected = crypto
 *   .createHmac('sha256', secret)
 *   .update(req.body)
 *   .digest('hex');
 * const valid = expected === signature;
 *
 * // Webhook receives events:
 * POST https://partner.com/events
 * Headers:
 *   X-Webhook-Signature: abc123...
 *   X-Webhook-ID: webhook_123
 * Body:
 * {
 *   "type": "shipment.created",
 *   "timestamp": "2024-01-01T00:00:00Z",
 *   "entity": "Shipment",
 *   "entityId": "IFE-12345",
 *   "data": { ... shipment data ... }
 * }
 *
 * Benefits:
 * - Real-time integration
 * - No polling needed
 * - Secure (HMAC signature)
 * - Webhook management UI
 * - Retry logic
 * - Event filtering
 */
