/**
 * CQRS (Command Query Responsibility Segregation)
 * Separate read and write operations for better performance
 * Commands modify state, Queries return data
 */

import { PrismaClient } from "@prisma/client";
import { EventStore, ShipmentAggregate } from "./eventSourcing";
import { v4 as uuid } from "uuid";

const prisma = new PrismaClient();
const eventStore = new EventStore();

/**
 * Base command interface
 */
export interface Command {
  type: string;
  aggregateId: string;
  data: Record<string, any>;
  metadata: {
    userId: string;
    tenantId: string;
    timestamp: Date;
  };
}

/**
 * Command result
 */
export interface CommandResult {
  success: boolean;
  aggregateId: string;
  version: number;
  error?: string;
}

/**
 * Base query interface
 */
export interface Query {
  type: string;
  filters?: Record<string, any>;
  pagination?: {
    page: number;
    limit: number;
  };
  sort?: {
    field: string;
    order: "asc" | "desc";
  };
}

/**
 * Query result
 */
export interface QueryResult<T> {
  data: T;
  pagination?: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

/**
 * Command handlers
 */
export class ShipmentCommandHandler {
  /**
   * Handle CreateShipment command
   */
  async handleCreateShipment(command: Command): Promise<CommandResult> {
    try {
      const shipmentId = command.aggregateId || uuid();
      const shipment = new ShipmentAggregate(eventStore, shipmentId);

      const trackingNumber = `INF-${Date.now()}`;

      await shipment.create({
        trackingNumber,
        origin: command.data.origin,
        destination: command.data.destination,
        weight: command.data.weight,
        customerId: command.metadata.userId,
        tenantId: command.metadata.tenantId,
      });

      return {
        success: true,
        aggregateId: shipmentId,
        version: 1,
      };
    } catch (error) {
      return {
        success: false,
        aggregateId: command.aggregateId,
        version: 0,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  /**
   * Handle AssignDriver command
   */
  async handleAssignDriver(command: Command): Promise<CommandResult> {
    try {
      const shipment = new ShipmentAggregate(eventStore, command.aggregateId);
      await shipment.rehydrate();

      await shipment.assignDriver(
        command.data.driverId,
        command.metadata.userId,
        command.metadata.tenantId,
      );

      return {
        success: true,
        aggregateId: command.aggregateId,
        version: shipment.getState().version,
      };
    } catch (error) {
      return {
        success: false,
        aggregateId: command.aggregateId,
        version: 0,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  /**
   * Handle MarkPickedUp command
   */
  async handleMarkPickedUp(command: Command): Promise<CommandResult> {
    try {
      const shipment = new ShipmentAggregate(eventStore, command.aggregateId);
      await shipment.rehydrate();

      await shipment.markPickedUp(
        command.metadata.userId,
        command.metadata.tenantId,
      );

      return {
        success: true,
        aggregateId: command.aggregateId,
        version: shipment.getState().version,
      };
    } catch (error) {
      return {
        success: false,
        aggregateId: command.aggregateId,
        version: 0,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  /**
   * Handle MarkDelivered command
   */
  async handleMarkDelivered(command: Command): Promise<CommandResult> {
    try {
      const shipment = new ShipmentAggregate(eventStore, command.aggregateId);
      await shipment.rehydrate();

      await shipment.markDelivered(
        command.metadata.userId,
        command.metadata.tenantId,
        command.data.signature,
      );

      return {
        success: true,
        aggregateId: command.aggregateId,
        version: shipment.getState().version,
      };
    } catch (error) {
      return {
        success: false,
        aggregateId: command.aggregateId,
        version: 0,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  /**
   * Handle CancelShipment command
   */
  async handleCancelShipment(command: Command): Promise<CommandResult> {
    try {
      const shipment = new ShipmentAggregate(eventStore, command.aggregateId);
      await shipment.rehydrate();

      await shipment.cancel(
        command.metadata.userId,
        command.metadata.tenantId,
        command.data.reason,
      );

      return {
        success: true,
        aggregateId: command.aggregateId,
        version: shipment.getState().version,
      };
    } catch (error) {
      return {
        success: false,
        aggregateId: command.aggregateId,
        version: 0,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }
}

/**
 * Query handlers (read-optimized)
 */
export class ShipmentQueryHandler {
  /**
   * Get shipment by ID
   */
  async getShipmentById(shipmentId: string): Promise<QueryResult<any>> {
    const shipment = await prisma.shipment.findUnique({
      where: { id: shipmentId },
      include: {
        customer: true,
        driver: {
          include: {
            user: true,
          },
        },
      },
    });

    return {
      data: shipment,
    };
  }

  /**
   * Get shipment by tracking number
   */
  async getShipmentByTrackingNumber(
    trackingNumber: string,
  ): Promise<QueryResult<any>> {
    const shipment = await prisma.shipment.findUnique({
      where: { trackingNumber },
      include: {
        customer: true,
        driver: {
          include: {
            user: true,
          },
        },
      },
    });

    return {
      data: shipment,
    };
  }

  /**
   * List shipments with filters and pagination
   */
  async listShipments(query: Query): Promise<QueryResult<any[]>> {
    const { filters = {}, pagination = { page: 1, limit: 20 }, sort } = query;

    const skip = (pagination.page - 1) * pagination.limit;

    const [shipments, total] = await Promise.all([
      prisma.shipment.findMany({
        where: filters,
        skip,
        take: pagination.limit,
        orderBy: sort ? { [sort.field]: sort.order } : { createdAt: "desc" },
        include: {
          customer: true,
          driver: {
            include: {
              user: true,
            },
          },
        },
      }),
      prisma.shipment.count({ where: filters }),
    ]);

    return {
      data: shipments,
      pagination: {
        page: pagination.page,
        limit: pagination.limit,
        total,
        pages: Math.ceil(total / pagination.limit),
      },
    };
  }

  /**
   * Get shipment statistics (denormalized for performance)
   */
  async getShipmentStats(
    tenantId: string,
    startDate: Date,
    endDate: Date,
  ): Promise<QueryResult<any>> {
    // Use materialized view or cached aggregate
    const [total, delivered, inTransit, cancelled, avgDeliveryTime] =
      await Promise.all([
        prisma.shipment.count({
          where: {
            tenantId,
            createdAt: {
              gte: startDate,
              lte: endDate,
            },
          },
        }),
        prisma.shipment.count({
          where: {
            tenantId,
            status: "DELIVERED",
            createdAt: {
              gte: startDate,
              lte: endDate,
            },
          },
        }),
        prisma.shipment.count({
          where: {
            tenantId,
            status: "IN_TRANSIT",
          },
        }),
        prisma.shipment.count({
          where: {
            tenantId,
            status: "CANCELLED",
            createdAt: {
              gte: startDate,
              lte: endDate,
            },
          },
        }),
        prisma.shipment.aggregate({
          where: {
            tenantId,
            status: "DELIVERED",
            createdAt: {
              gte: startDate,
              lte: endDate,
            },
          },
          _avg: {
            deliveryTime: true,
          },
        }),
      ]);

    return {
      data: {
        total,
        delivered,
        inTransit,
        cancelled,
        avgDeliveryTime: avgDeliveryTime._avg.deliveryTime || 0,
        deliveryRate: total > 0 ? (delivered / total) * 100 : 0,
      },
    };
  }

  /**
   * Search shipments (full-text search)
   */
  async searchShipments(
    searchTerm: string,
    tenantId: string,
  ): Promise<QueryResult<any[]>> {
    const shipments = await prisma.shipment.findMany({
      where: {
        tenantId,
        OR: [
          { trackingNumber: { contains: searchTerm, mode: "insensitive" } },
          { origin: { contains: searchTerm, mode: "insensitive" } },
          { destination: { contains: searchTerm, mode: "insensitive" } },
          { customer: { name: { contains: searchTerm, mode: "insensitive" } } },
        ],
      },
      include: {
        customer: true,
        driver: {
          include: {
            user: true,
          },
        },
      },
      take: 50,
    });

    return {
      data: shipments,
    };
  }
}

/**
 * Command bus for dispatching commands
 */
export class CommandBus {
  private handlers: Map<string, (command: Command) => Promise<CommandResult>> =
    new Map();

  register(
    commandType: string,
    handler: (command: Command) => Promise<CommandResult>,
  ): void {
    this.handlers.set(commandType, handler);
  }

  async execute(command: Command): Promise<CommandResult> {
    const handler = this.handlers.get(command.type);

    if (!handler) {
      return {
        success: false,
        aggregateId: command.aggregateId,
        version: 0,
        error: `No handler registered for command type: ${command.type}`,
      };
    }

    return handler(command);
  }
}

/**
 * Query bus for dispatching queries
 */
export class QueryBus {
  private handlers: Map<string, (query: Query) => Promise<QueryResult<any>>> =
    new Map();

  register(
    queryType: string,
    handler: (query: Query) => Promise<QueryResult<any>>,
  ): void {
    this.handlers.set(queryType, handler);
  }

  async execute<T>(query: Query): Promise<QueryResult<T>> {
    const handler = this.handlers.get(query.type);

    if (!handler) {
      throw new Error(`No handler registered for query type: ${query.type}`);
    }

    return handler(query);
  }
}

// Initialize buses
const commandBus = new CommandBus();
const queryBus = new QueryBus();

const commandHandler = new ShipmentCommandHandler();
const queryHandler = new ShipmentQueryHandler();

// Register command handlers
commandBus.register(
  "CreateShipment",
  commandHandler.handleCreateShipment.bind(commandHandler),
);
commandBus.register(
  "AssignDriver",
  commandHandler.handleAssignDriver.bind(commandHandler),
);
commandBus.register(
  "MarkPickedUp",
  commandHandler.handleMarkPickedUp.bind(commandHandler),
);
commandBus.register(
  "MarkDelivered",
  commandHandler.handleMarkDelivered.bind(commandHandler),
);
commandBus.register(
  "CancelShipment",
  commandHandler.handleCancelShipment.bind(commandHandler),
);

// Register query handlers
queryBus.register("GetShipmentById", (q) =>
  queryHandler.getShipmentById(q.filters!.id),
);
queryBus.register("GetShipmentByTrackingNumber", (q) =>
  queryHandler.getShipmentByTrackingNumber(q.filters!.trackingNumber),
);
queryBus.register("ListShipments", (q) => queryHandler.listShipments(q));
queryBus.register("GetShipmentStats", (q) =>
  queryHandler.getShipmentStats(
    q.filters!.tenantId,
    q.filters!.startDate,
    q.filters!.endDate,
  ),
);
queryBus.register("SearchShipments", (q) =>
  queryHandler.searchShipments(q.filters!.searchTerm, q.filters!.tenantId),
);

export { commandBus, queryBus };

/**
 * Usage:
 *
 * // Execute command (write)
 * const result = await commandBus.execute({
 *   type: 'CreateShipment',
 *   aggregateId: uuid(),
 *   data: {
 *     origin: 'New York, NY',
 *     destination: 'Los Angeles, CA',
 *     weight: 500,
 *   },
 *   metadata: {
 *     userId: 'user-123',
 *     tenantId: 'tenant-456',
 *     timestamp: new Date(),
 *   },
 * });
 *
 * // Execute query (read)
 * const shipment = await queryBus.execute({
 *   type: 'GetShipmentById',
 *   filters: { id: 'shipment-123' },
 * });
 *
 * // List with pagination
 * const shipments = await queryBus.execute({
 *   type: 'ListShipments',
 *   filters: { status: 'IN_TRANSIT', tenantId: 'tenant-456' },
 *   pagination: { page: 1, limit: 20 },
 *   sort: { field: 'createdAt', order: 'desc' },
 * });
 *
 * // Get statistics
 * const stats = await queryBus.execute({
 *   type: 'GetShipmentStats',
 *   filters: {
 *     tenantId: 'tenant-456',
 *     startDate: new Date('2024-01-01'),
 *     endDate: new Date('2024-12-31'),
 *   },
 * });
 *
 * Benefits:
 * - Separate read/write paths
 * - Optimized queries (no joins needed)
 * - Better scalability (separate databases for read/write)
 * - Easier to add caching
 * - Clear separation of concerns
 * - Better performance for complex queries
 */
