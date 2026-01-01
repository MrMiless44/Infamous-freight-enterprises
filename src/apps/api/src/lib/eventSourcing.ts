/**
 * Event Sourcing Implementation
 * Complete audit trail with event replay capability
 * Store all state changes as immutable events
 */

import { EventEmitter } from "events";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/**
 * Base event interface
 */
export interface DomainEvent {
  id: string;
  aggregateId: string;
  aggregateType: string;
  eventType: string;
  data: Record<string, any>;
  metadata: {
    userId?: string;
    tenantId?: string;
    timestamp: Date;
    version: number;
    causationId?: string; // Event that caused this event
    correlationId?: string; // Group related events
  };
}

/**
 * Event store for persisting events
 */
export class EventStore extends EventEmitter {
  /**
   * Append event to store
   */
  async append(event: Omit<DomainEvent, "id">): Promise<DomainEvent> {
    const savedEvent = await prisma.event.create({
      data: {
        aggregateId: event.aggregateId,
        aggregateType: event.aggregateType,
        eventType: event.eventType,
        data: event.data,
        metadata: event.metadata,
        version: event.metadata.version,
        timestamp: event.metadata.timestamp,
      },
    });

    const domainEvent: DomainEvent = {
      id: savedEvent.id,
      aggregateId: savedEvent.aggregateId,
      aggregateType: savedEvent.aggregateType,
      eventType: savedEvent.eventType,
      data: savedEvent.data as Record<string, any>,
      metadata: savedEvent.metadata as DomainEvent["metadata"],
    };

    // Emit event for real-time processing
    this.emit(event.eventType, domainEvent);
    this.emit("*", domainEvent);

    return domainEvent;
  }

  /**
   * Get all events for an aggregate
   */
  async getEvents(aggregateId: string): Promise<DomainEvent[]> {
    const events = await prisma.event.findMany({
      where: { aggregateId },
      orderBy: { version: "asc" },
    });

    return events.map((e) => ({
      id: e.id,
      aggregateId: e.aggregateId,
      aggregateType: e.aggregateType,
      eventType: e.eventType,
      data: e.data as Record<string, any>,
      metadata: e.metadata as DomainEvent["metadata"],
    }));
  }

  /**
   * Get events by type
   */
  async getEventsByType(
    eventType: string,
    limit = 100,
  ): Promise<DomainEvent[]> {
    const events = await prisma.event.findMany({
      where: { eventType },
      orderBy: { timestamp: "desc" },
      take: limit,
    });

    return events.map((e) => ({
      id: e.id,
      aggregateId: e.aggregateId,
      aggregateType: e.aggregateType,
      eventType: e.eventType,
      data: e.data as Record<string, any>,
      metadata: e.metadata as DomainEvent["metadata"],
    }));
  }

  /**
   * Get events in time range
   */
  async getEventsByTimeRange(
    startTime: Date,
    endTime: Date,
  ): Promise<DomainEvent[]> {
    const events = await prisma.event.findMany({
      where: {
        timestamp: {
          gte: startTime,
          lte: endTime,
        },
      },
      orderBy: { timestamp: "asc" },
    });

    return events.map((e) => ({
      id: e.id,
      aggregateId: e.aggregateId,
      aggregateType: e.aggregateType,
      eventType: e.eventType,
      data: e.data as Record<string, any>,
      metadata: e.metadata as DomainEvent["metadata"],
    }));
  }

  /**
   * Replay events to rebuild state
   */
  async replay(
    aggregateId: string,
    handlers: Record<string, (event: DomainEvent) => void>,
  ): Promise<void> {
    const events = await this.getEvents(aggregateId);

    for (const event of events) {
      const handler = handlers[event.eventType];
      if (handler) {
        handler(event);
      }
    }
  }
}

/**
 * Shipment aggregate with event sourcing
 */
export class ShipmentAggregate {
  private eventStore: EventStore;
  private state: {
    id: string;
    trackingNumber: string;
    status: string;
    origin: string;
    destination: string;
    weight: number;
    customerId: string;
    driverId?: string;
    version: number;
    createdAt: Date;
  };

  constructor(eventStore: EventStore, id: string) {
    this.eventStore = eventStore;
    this.state = {
      id,
      trackingNumber: "",
      status: "",
      origin: "",
      destination: "",
      weight: 0,
      customerId: "",
      version: 0,
      createdAt: new Date(),
    };
  }

  /**
   * Create new shipment
   */
  async create(data: {
    trackingNumber: string;
    origin: string;
    destination: string;
    weight: number;
    customerId: string;
    tenantId: string;
  }): Promise<void> {
    await this.eventStore.append({
      aggregateId: this.state.id,
      aggregateType: "Shipment",
      eventType: "ShipmentCreated",
      data: {
        trackingNumber: data.trackingNumber,
        origin: data.origin,
        destination: data.destination,
        weight: data.weight,
        customerId: data.customerId,
      },
      metadata: {
        tenantId: data.tenantId,
        timestamp: new Date(),
        version: ++this.state.version,
      },
    });

    // Update local state
    this.state = {
      ...this.state,
      ...data,
      status: "PENDING",
      createdAt: new Date(),
    };
  }

  /**
   * Assign driver to shipment
   */
  async assignDriver(
    driverId: string,
    userId: string,
    tenantId: string,
  ): Promise<void> {
    if (this.state.status !== "PENDING") {
      throw new Error("Can only assign driver to pending shipments");
    }

    await this.eventStore.append({
      aggregateId: this.state.id,
      aggregateType: "Shipment",
      eventType: "DriverAssigned",
      data: {
        driverId,
        previousDriverId: this.state.driverId,
      },
      metadata: {
        userId,
        tenantId,
        timestamp: new Date(),
        version: ++this.state.version,
      },
    });

    this.state.driverId = driverId;
  }

  /**
   * Mark shipment as picked up
   */
  async markPickedUp(userId: string, tenantId: string): Promise<void> {
    if (this.state.status !== "PENDING") {
      throw new Error("Can only pick up pending shipments");
    }

    await this.eventStore.append({
      aggregateId: this.state.id,
      aggregateType: "Shipment",
      eventType: "ShipmentPickedUp",
      data: {
        pickupTime: new Date(),
        driverId: this.state.driverId,
      },
      metadata: {
        userId,
        tenantId,
        timestamp: new Date(),
        version: ++this.state.version,
      },
    });

    this.state.status = "IN_TRANSIT";
  }

  /**
   * Mark shipment as delivered
   */
  async markDelivered(
    userId: string,
    tenantId: string,
    signature?: string,
  ): Promise<void> {
    if (this.state.status !== "IN_TRANSIT") {
      throw new Error("Can only deliver in-transit shipments");
    }

    await this.eventStore.append({
      aggregateId: this.state.id,
      aggregateType: "Shipment",
      eventType: "ShipmentDelivered",
      data: {
        deliveryTime: new Date(),
        driverId: this.state.driverId,
        signature,
      },
      metadata: {
        userId,
        tenantId,
        timestamp: new Date(),
        version: ++this.state.version,
      },
    });

    this.state.status = "DELIVERED";
  }

  /**
   * Cancel shipment
   */
  async cancel(
    userId: string,
    tenantId: string,
    reason: string,
  ): Promise<void> {
    if (
      this.state.status === "DELIVERED" ||
      this.state.status === "CANCELLED"
    ) {
      throw new Error("Cannot cancel delivered or already cancelled shipments");
    }

    await this.eventStore.append({
      aggregateId: this.state.id,
      aggregateType: "Shipment",
      eventType: "ShipmentCancelled",
      data: {
        reason,
        cancelledAt: new Date(),
      },
      metadata: {
        userId,
        tenantId,
        timestamp: new Date(),
        version: ++this.state.version,
      },
    });

    this.state.status = "CANCELLED";
  }

  /**
   * Rebuild state from events
   */
  async rehydrate(): Promise<void> {
    await this.eventStore.replay(this.state.id, {
      ShipmentCreated: (event) => {
        this.state = {
          ...this.state,
          ...event.data,
          status: "PENDING",
          createdAt: event.metadata.timestamp,
        };
      },
      DriverAssigned: (event) => {
        this.state.driverId = event.data.driverId;
      },
      ShipmentPickedUp: (event) => {
        this.state.status = "IN_TRANSIT";
      },
      ShipmentDelivered: (event) => {
        this.state.status = "DELIVERED";
      },
      ShipmentCancelled: (event) => {
        this.state.status = "CANCELLED";
      },
    });
  }

  /**
   * Get current state
   */
  getState() {
    return { ...this.state };
  }
}

/**
 * Event handlers for projections
 */
export class ShipmentProjection {
  private eventStore: EventStore;

  constructor(eventStore: EventStore) {
    this.eventStore = eventStore;

    // Subscribe to events
    this.eventStore.on(
      "ShipmentCreated",
      this.handleShipmentCreated.bind(this),
    );
    this.eventStore.on("DriverAssigned", this.handleDriverAssigned.bind(this));
    this.eventStore.on(
      "ShipmentPickedUp",
      this.handleShipmentPickedUp.bind(this),
    );
    this.eventStore.on(
      "ShipmentDelivered",
      this.handleShipmentDelivered.bind(this),
    );
    this.eventStore.on(
      "ShipmentCancelled",
      this.handleShipmentCancelled.bind(this),
    );
  }

  private async handleShipmentCreated(event: DomainEvent): Promise<void> {
    // Update read model (Prisma)
    await prisma.shipment.create({
      data: {
        id: event.aggregateId,
        trackingNumber: event.data.trackingNumber,
        origin: event.data.origin,
        destination: event.data.destination,
        weight: event.data.weight,
        customerId: event.data.customerId,
        status: "PENDING",
        tenantId: event.metadata.tenantId!,
      },
    });

    console.log(`✓ Shipment created: ${event.data.trackingNumber}`);
  }

  private async handleDriverAssigned(event: DomainEvent): Promise<void> {
    await prisma.shipment.update({
      where: { id: event.aggregateId },
      data: {
        driverId: event.data.driverId,
      },
    });

    console.log(
      `✓ Driver ${event.data.driverId} assigned to shipment ${event.aggregateId}`,
    );
  }

  private async handleShipmentPickedUp(event: DomainEvent): Promise<void> {
    await prisma.shipment.update({
      where: { id: event.aggregateId },
      data: {
        status: "IN_TRANSIT",
        pickupTime: event.data.pickupTime,
      },
    });

    console.log(`✓ Shipment ${event.aggregateId} picked up`);
  }

  private async handleShipmentDelivered(event: DomainEvent): Promise<void> {
    await prisma.shipment.update({
      where: { id: event.aggregateId },
      data: {
        status: "DELIVERED",
        deliveryTime: event.data.deliveryTime,
      },
    });

    console.log(`✓ Shipment ${event.aggregateId} delivered`);
  }

  private async handleShipmentCancelled(event: DomainEvent): Promise<void> {
    await prisma.shipment.update({
      where: { id: event.aggregateId },
      data: {
        status: "CANCELLED",
      },
    });

    console.log(
      `✓ Shipment ${event.aggregateId} cancelled: ${event.data.reason}`,
    );
  }
}

// Singleton instance
const eventStore = new EventStore();
const shipmentProjection = new ShipmentProjection(eventStore);

export { eventStore, shipmentProjection };

/**
 * Usage:
 *
 * // Create new shipment with event sourcing
 * const shipmentId = uuid();
 * const shipment = new ShipmentAggregate(eventStore, shipmentId);
 *
 * await shipment.create({
 *   trackingNumber: 'INF-2024-001',
 *   origin: 'New York, NY',
 *   destination: 'Los Angeles, CA',
 *   weight: 500,
 *   customerId: 'user-123',
 *   tenantId: 'tenant-456',
 * });
 *
 * // Assign driver
 * await shipment.assignDriver('driver-789', 'admin-id', 'tenant-456');
 *
 * // Mark as picked up
 * await shipment.markPickedUp('driver-789', 'tenant-456');
 *
 * // Mark as delivered
 * await shipment.markDelivered('driver-789', 'tenant-456', 'signature-data');
 *
 * // Rebuild state from events (time travel)
 * const historicalShipment = new ShipmentAggregate(eventStore, shipmentId);
 * await historicalShipment.rehydrate();
 * console.log(historicalShipment.getState());
 *
 * // Query events
 * const events = await eventStore.getEvents(shipmentId);
 * console.log('Shipment history:', events);
 *
 * Database schema:
 *
 * model Event {
 *   id            String   @id @default(uuid())
 *   aggregateId   String
 *   aggregateType String
 *   eventType     String
 *   data          Json
 *   metadata      Json
 *   version       Int
 *   timestamp     DateTime @default(now())
 *
 *   @@index([aggregateId, version])
 *   @@index([eventType])
 *   @@index([timestamp])
 * }
 *
 * Benefits:
 * - Complete audit trail
 * - Time travel (rebuild state at any point)
 * - Event replay for debugging
 * - Immutable history
 * - Easy to add new projections
 * - Support for CQRS
 * - Better compliance (audit requirements)
 */
