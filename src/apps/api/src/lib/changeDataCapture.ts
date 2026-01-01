/**
 * Change Data Capture (CDC) for Real-Time Analytics
 * Emits events whenever data changes, enabling real-time analytics and integrations
 */

import { PrismaClient } from "@prisma/client";
import { EventEmitter } from "events";

/**
 * CDC Event types
 */
export enum CDCEventType {
  SHIPMENT_CREATED = "shipment.created",
  SHIPMENT_UPDATED = "shipment.updated",
  SHIPMENT_DELETED = "shipment.deleted",

  DRIVER_CREATED = "driver.created",
  DRIVER_UPDATED = "driver.updated",
  DRIVER_DELETED = "driver.deleted",

  USER_CREATED = "user.created",
  USER_UPDATED = "user.updated",
  USER_DELETED = "user.deleted",

  INVOICE_CREATED = "invoice.created",
  INVOICE_PAID = "invoice.paid",
}

export interface CDCEvent {
  type: CDCEventType;
  timestamp: Date;
  entity: string;
  entityId: string;
  before?: Record<string, any>; // Previous values (for updates)
  after: Record<string, any>; // Current values
  changes?: Record<string, { before: any; after: any }>; // Specific field changes
  userId?: string; // Who made the change
  source: "api" | "internal" | "migration";
}

/**
 * Change Data Capture Manager
 */
class ChangeDataCaptureManager extends EventEmitter {
  private eventLog: CDCEvent[] = [];
  private maxLogSize = 10000;

  /**
   * Emit a CDC event
   */
  emitChange(event: CDCEvent): void {
    // Add to log for replay/auditing
    this.eventLog.push(event);
    if (this.eventLog.length > this.maxLogSize) {
      this.eventLog.shift();
    }

    // Emit event for subscribers
    this.emit(event.type, event);
    this.emit("change", event); // All changes listener
  }

  /**
   * Get recent events
   */
  getRecentEvents(limit: number = 100): CDCEvent[] {
    return this.eventLog.slice(-limit);
  }

  /**
   * Get events for specific entity
   */
  getEventsForEntity(entityId: string, limit: number = 50): CDCEvent[] {
    return this.eventLog.filter((e) => e.entityId === entityId).slice(-limit);
  }

  /**
   * Subscribe to specific event type
   */
  onChange(type: CDCEventType, handler: (event: CDCEvent) => void): () => void {
    this.on(type, handler);
    return () => this.off(type, handler);
  }

  /**
   * Subscribe to all changes
   */
  onAnyChange(handler: (event: CDCEvent) => void): () => void {
    this.on("change", handler);
    return () => this.off("change", handler);
  }
}

export const cdc = new ChangeDataCaptureManager();

/**
 * Enable CDC on Prisma models
 */
export function enableCDC(prisma: PrismaClient): void {
  // Intercept all Prisma operations
  prisma.$use(async (params, next) => {
    const result = await next(params);

    const { model, action, args } = params;

    // Only capture write operations
    if (
      !["create", "update", "delete", "updateMany", "deleteMany"].includes(
        action,
      )
    ) {
      return result;
    }

    // Map model names to event types
    const eventTypeMap: Record<string, Record<string, CDCEventType>> = {
      Shipment: {
        create: CDCEventType.SHIPMENT_CREATED,
        update: CDCEventType.SHIPMENT_UPDATED,
        delete: CDCEventType.SHIPMENT_DELETED,
      },
      Driver: {
        create: CDCEventType.DRIVER_CREATED,
        update: CDCEventType.DRIVER_UPDATED,
        delete: CDCEventType.DRIVER_DELETED,
      },
      User: {
        create: CDCEventType.USER_CREATED,
        update: CDCEventType.USER_UPDATED,
        delete: CDCEventType.USER_DELETED,
      },
      Invoice: {
        create: CDCEventType.INVOICE_CREATED,
        update: CDCEventType.INVOICE_UPDATED,
      },
    };

    const eventType = eventTypeMap[model]?.[action];
    if (!eventType) return result;

    // Get ID from result or args
    const entityId = result.id || args.where?.id || "unknown";

    // Emit CDC event
    cdc.emitChange({
      type: eventType,
      timestamp: new Date(),
      entity: model,
      entityId,
      after: result,
      before: action === "update" ? args.data : undefined,
      source: "api",
    });

    return result;
  });
}

/**
 * Example subscribers that react to CDC events
 */
export function setupCDCSubscribers(): void {
  // Update analytics on shipment created
  cdc.onChange(CDCEventType.SHIPMENT_CREATED, (event) => {
    console.log(`📦 New shipment: ${event.entityId}`);
    // Could trigger:
    // - Send to data warehouse (BigQuery, Redshift)
    // - Update cache/Redis
    // - Send webhook to external systems
  });

  // Update metrics on shipment delivered
  cdc.onChange(CDCEventType.SHIPMENT_UPDATED, (event) => {
    if (event.after.status === "DELIVERED") {
      console.log(`✅ Shipment delivered: ${event.entityId}`);
      // Could trigger:
      // - Update customer notification
      // - Generate invoice
      // - Update driver stats
    }
  });

  // Audit log all changes
  cdc.onAnyChange((event) => {
    console.log(
      `[AUDIT] ${event.type} - ${event.entity}:${event.entityId} by ${event.userId || "system"}`,
    );
    // Could send to:
    // - Elasticsearch for searchable audit log
    // - Sentry for compliance tracking
    // - S3 for long-term storage
  });
}

/**
 * Send CDC events to external system (webhook/Kafka)
 */
export async function forwardCDCEvent(event: CDCEvent): Promise<void> {
  // Send to webhook endpoint
  if (process.env.CDC_WEBHOOK_URL) {
    try {
      await fetch(process.env.CDC_WEBHOOK_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.CDC_WEBHOOK_SECRET}`,
        },
        body: JSON.stringify(event),
      });
    } catch (error) {
      console.error("Failed to forward CDC event:", error);
    }
  }

  // Send to Kafka topic
  if (process.env.KAFKA_ENABLED === "true") {
    // Implement Kafka producer
    // await kafkaProducer.send({
    //   topic: 'data-changes',
    //   messages: [{
    //     key: event.entityId,
    //     value: JSON.stringify(event)
    //   }]
    // });
  }
}

/**
 * API endpoint: Get CDC events
 */
export async function handleCDCEvents(req: any, res: any) {
  const { entityId, type, limit = 50 } = req.query;

  let events: CDCEvent[];

  if (entityId) {
    events = cdc.getEventsForEntity(entityId, parseInt(limit, 10));
  } else if (type) {
    events = cdc
      .getRecentEvents(parseInt(limit, 10))
      .filter((e) => e.type === type);
  } else {
    events = cdc.getRecentEvents(parseInt(limit, 10));
  }

  res.json({
    success: true,
    data: events,
  });
}

/**
 * Usage example:
 *
 * // Enable CDC on startup
 * const prisma = new PrismaClient();
 * enableCDC(prisma);
 * setupCDCSubscribers();
 *
 * // Example Prisma operation triggers CDC
 * const shipment = await prisma.shipment.create({
 *   data: {
 *     trackingNumber: 'IFE-12345',
 *     origin: 'NYC',
 *     destination: 'LA',
 *     status: 'PENDING'
 *   }
 * });
 * // Automatically emits CDCEventType.SHIPMENT_CREATED event
 *
 * // Subscribe to events
 * cdc.onChange(CDCEventType.SHIPMENT_UPDATED, (event) => {
 *   console.log('Shipment updated:', event.after);
 *   // Send notification, trigger workflow, etc.
 * });
 *
 * Benefits:
 * - Real-time analytics (no batch delays)
 * - Audit trail (who changed what, when)
 * - Event-driven architecture
 * - Integration with external systems
 * - Replay capability (audit log)
 * - Compliance ready
 */
