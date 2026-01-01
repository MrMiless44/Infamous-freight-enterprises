/**
 * Server-Sent Events (SSE) for Real-Time Updates
 * Lightweight alternative to WebSocket for one-way server→client streaming
 * Benefits: Works through proxies, built-in reconnection, native browser support
 */

import { Request, Response, Router } from "express";
import { authenticate, requireScope } from "./security";

const router = Router();

/**
 * Simple event subscription manager
 */
class EventSubscriptionManager {
  private subscriptions = new Map<string, Set<Response>>();
  private eventLog = new Map<string, any[]>();

  subscribe(channel: string, res: Response): () => void {
    if (!this.subscriptions.has(channel)) {
      this.subscriptions.set(channel, new Set());
      this.eventLog.set(channel, []);
    }

    this.subscriptions.get(channel)!.add(res);

    // Send any missed events from the log
    const missedEvents = this.eventLog.get(channel) || [];
    for (const event of missedEvents.slice(-10)) {
      res.write(`data: ${JSON.stringify(event)}\n\n`);
    }

    // Return unsubscribe function
    return () => {
      this.subscriptions.get(channel)?.delete(res);
    };
  }

  publish(channel: string, data: any): void {
    const subscribers = this.subscriptions.get(channel);
    if (!subscribers) return;

    const event = {
      timestamp: Date.now(),
      data,
    };

    // Log event for late subscribers
    const log = this.eventLog.get(channel) || [];
    log.push(event);
    if (log.length > 50) {
      log.shift(); // Keep only last 50 events
    }
    this.eventLog.set(channel, log);

    // Send to all subscribers
    for (const res of subscribers) {
      try {
        res.write(`data: ${JSON.stringify(event)}\n\n`);
      } catch (error) {
        // Subscriber disconnected, will be cleaned up in close handler
      }
    }
  }

  getSubscriberCount(channel: string): number {
    return this.subscriptions.get(channel)?.size || 0;
  }
}

export const subscriptionManager = new EventSubscriptionManager();

/**
 * SSE endpoint: Real-time shipment tracking
 */
router.get(
  "/shipments/stream/:trackingNumber",
  authenticate,
  requireScope("shipments:track"),
  (req: Request, res: Response) => {
    const trackingNumber = req.params.trackingNumber;
    const channel = `shipment:${trackingNumber}`;

    // Setup SSE response
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("X-Accel-Buffering", "no"); // Disable buffering in proxies

    // Send initial connection success message
    res.write(":connection established\n\n");

    // Subscribe to updates
    const unsubscribe = subscriptionManager.subscribe(channel, res);

    // Handle client disconnect
    req.on("close", () => {
      console.log(`Client disconnected from ${channel}`);
      unsubscribe();
      res.end();
    });

    // Heartbeat to keep connection alive
    const heartbeatInterval = setInterval(() => {
      try {
        res.write(":heartbeat\n\n");
      } catch (error) {
        clearInterval(heartbeatInterval);
      }
    }, 30000); // Every 30 seconds

    res.on("finish", () => {
      clearInterval(heartbeatInterval);
      unsubscribe();
    });
  },
);

/**
 * SSE endpoint: Real-time driver location updates
 */
router.get(
  "/drivers/:driverId/location/stream",
  authenticate,
  requireScope("drivers:track"),
  (req: Request, res: Response) => {
    const driverId = req.params.driverId;
    const channel = `driver:${driverId}:location`;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    res.write(":connection established\n\n");

    const unsubscribe = subscriptionManager.subscribe(channel, res);

    req.on("close", () => {
      unsubscribe();
      res.end();
    });

    const heartbeat = setInterval(() => {
      try {
        res.write(":heartbeat\n\n");
      } catch {
        clearInterval(heartbeat);
      }
    }, 30000);

    res.on("finish", () => {
      clearInterval(heartbeat);
    });
  },
);

/**
 * SSE endpoint: Real-time notifications for user
 */
router.get(
  "/notifications/stream",
  authenticate,
  (req: Request, res: Response) => {
    const userId = req.user?.sub;
    const channel = `user:${userId}:notifications`;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    res.write(":connection established\n\n");

    const unsubscribe = subscriptionManager.subscribe(channel, res);

    req.on("close", () => {
      unsubscribe();
      res.end();
    });

    const heartbeat = setInterval(() => {
      try {
        res.write(":heartbeat\n\n");
      } catch {
        clearInterval(heartbeat);
      }
    }, 30000);

    res.on("finish", () => {
      clearInterval(heartbeat);
    });
  },
);

/**
 * Helper function: Publish shipment update
 */
export function publishShipmentUpdate(
  trackingNumber: string,
  update: any,
): void {
  subscriptionManager.publish(`shipment:${trackingNumber}`, {
    type: "shipment.updated",
    trackingNumber,
    update,
  });
}

/**
 * Helper function: Publish driver location
 */
export function publishDriverLocation(driverId: string, location: any): void {
  subscriptionManager.publish(`driver:${driverId}:location`, {
    type: "driver.location",
    driverId,
    location,
  });
}

/**
 * Helper function: Publish notification
 */
export function publishNotification(userId: string, notification: any): void {
  subscriptionManager.publish(`user:${userId}:notifications`, {
    type: "notification",
    userId,
    notification,
  });
}

/**
 * Admin endpoint: Get subscription stats
 */
router.get(
  "/admin/subscriptions/stats",
  authenticate,
  (req: Request, res: Response) => {
    if (req.user?.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }

    const stats = {
      shipments: subscriptionManager.getSubscriberCount("shipment:*"),
      drivers: subscriptionManager.getSubscriberCount("driver:*"),
      notifications: subscriptionManager.getSubscriberCount(
        "user:*:notifications",
      ),
    };

    res.json({ success: true, data: stats });
  },
);

export default router;

/**
 * Client-side usage (JavaScript):
 *
 * const eventSource = new EventSource('/api/shipments/stream/IFE-12345', {
 *   headers: {
 *     'Authorization': `Bearer ${token}`
 *   }
 * });
 *
 * eventSource.addEventListener('message', (event) => {
 *   const update = JSON.parse(event.data);
 *   console.log('Shipment updated:', update);
 *   updateUI(update);
 * });
 *
 * eventSource.addEventListener('error', (event) => {
 *   if (event.eventPhase === EventSource.CLOSED) {
 *     console.log('Connection closed');
 *     // Attempt to reconnect
 *   }
 * });
 *
 * // Automatic reconnection on disconnect (built-in)
 * // Browser automatically reconnects with exponential backoff
 *
 * Advantages over WebSocket:
 * - Simpler protocol (HTTP-based)
 * - Works through HTTP proxies
 * - Automatic reconnection with Last-Event-ID
 * - Built-in message ordering
 * - Lower overhead than WebSocket
 *
 * When to use SSE vs WebSocket:
 * - SSE: One-way updates (server→client), less complex, better compatibility
 * - WebSocket: Two-way communication, lower latency, real-time bidirectional
 */
