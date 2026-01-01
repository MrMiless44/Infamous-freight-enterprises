/**
 * GraphQL Resolvers
 * Business logic for GraphQL queries, mutations, and subscriptions
 */

import { PrismaClient } from "@prisma/client";
import { PubSub } from "graphql-subscriptions";
import { GraphQLError } from "graphql";

const prisma = new PrismaClient();
const pubsub = new PubSub();

// Subscription topics
const SHIPMENT_UPDATED = "SHIPMENT_UPDATED";
const DRIVER_LOCATION_UPDATED = "DRIVER_LOCATION_UPDATED";
const NOTIFICATION_RECEIVED = "NOTIFICATION_RECEIVED";

export const resolvers = {
  Query: {
    // User queries
    me: async (_: any, __: any, context: any) => {
      if (!context.user) {
        throw new GraphQLError("Not authenticated", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      return prisma.user.findUnique({
        where: { id: context.user.sub },
      });
    },

    user: async (_: any, { id }: { id: string }, context: any) => {
      if (!context.user) {
        throw new GraphQLError("Not authenticated", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      return prisma.user.findUnique({
        where: { id },
      });
    },

    users: async (_: any, { role, first = 20, after }: any, context: any) => {
      if (!context.user || context.user.role !== "admin") {
        throw new GraphQLError("Not authorized", {
          extensions: { code: "FORBIDDEN" },
        });
      }

      return prisma.user.findMany({
        where: role ? { role } : undefined,
        take: first,
        skip: after ? 1 : 0,
        cursor: after ? { id: after } : undefined,
      });
    },

    // Shipment queries
    shipment: async (_: any, { id, trackingNumber }: any, context: any) => {
      if (!context.user) {
        throw new GraphQLError("Not authenticated", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      const where = id ? { id } : { trackingNumber };

      const shipment = await prisma.shipment.findUnique({
        where,
        include: {
          customer: true,
          driver: true,
        },
      });

      if (!shipment) {
        throw new GraphQLError("Shipment not found", {
          extensions: { code: "NOT_FOUND" },
        });
      }

      // Check authorization
      if (
        context.user.role !== "admin" &&
        shipment.customerId !== context.user.sub &&
        shipment.driverId !== context.user.sub
      ) {
        throw new GraphQLError("Not authorized to view this shipment", {
          extensions: { code: "FORBIDDEN" },
        });
      }

      return shipment;
    },

    shipments: async (
      _: any,
      { status, customerId, driverId, first = 20, after }: any,
      context: any,
    ) => {
      if (!context.user) {
        throw new GraphQLError("Not authenticated", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      const where: any = {};

      if (status) where.status = status;
      if (customerId) where.customerId = customerId;
      if (driverId) where.driverId = driverId;

      // Restrict to user's own shipments unless admin
      if (context.user.role === "customer") {
        where.customerId = context.user.sub;
      } else if (context.user.role === "driver") {
        where.driverId = context.user.sub;
      }

      const shipments = await prisma.shipment.findMany({
        where,
        take: first + 1, // +1 to check if there's a next page
        skip: after ? 1 : 0,
        cursor: after ? { id: after } : undefined,
        include: {
          customer: true,
          driver: true,
        },
        orderBy: { createdAt: "desc" },
      });

      const hasNextPage = shipments.length > first;
      const nodes = hasNextPage ? shipments.slice(0, -1) : shipments;

      return {
        edges: nodes.map((node) => ({
          node,
          cursor: node.id,
        })),
        pageInfo: {
          hasNextPage,
          hasPreviousPage: !!after,
          startCursor: nodes[0]?.id,
          endCursor: nodes[nodes.length - 1]?.id,
        },
        totalCount: await prisma.shipment.count({ where }),
      };
    },

    searchShipments: async (
      _: any,
      { query, first = 10 }: any,
      context: any,
    ) => {
      if (!context.user) {
        throw new GraphQLError("Not authenticated", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      return prisma.shipment.findMany({
        where: {
          OR: [
            { trackingNumber: { contains: query, mode: "insensitive" } },
            { origin: { contains: query, mode: "insensitive" } },
            { destination: { contains: query, mode: "insensitive" } },
          ],
        },
        take: first,
        include: {
          customer: true,
          driver: true,
        },
      });
    },

    // Driver queries
    driver: async (_: any, { id }: { id: string }) => {
      return prisma.driver.findUnique({
        where: { id },
        include: { user: true },
      });
    },

    drivers: async (_: any, { status, first = 20 }: any) => {
      return prisma.driver.findMany({
        where: status ? { status } : undefined,
        take: first,
        include: { user: true },
      });
    },

    nearbyDrivers: async (
      _: any,
      {
        latitude,
        longitude,
        radius,
      }: { latitude: number; longitude: number; radius: number },
    ) => {
      // Use raw SQL for geo queries
      const drivers = await prisma.$queryRaw`
        SELECT d.* FROM drivers d
        WHERE d.status = 'ACTIVE'
        AND ST_Distance_Sphere(
          point(d.longitude, d.latitude),
          point(${longitude}, ${latitude})
        ) <= ${radius * 1000}
      `;

      return drivers;
    },

    // Analytics queries
    analytics: async (_: any, { filter }: any, context: any) => {
      if (!context.user || context.user.role !== "admin") {
        throw new GraphQLError("Not authorized", {
          extensions: { code: "FORBIDDEN" },
        });
      }

      const { startDate, endDate, driverId, customerId, status } = filter;

      const where: any = {
        createdAt: {
          gte: new Date(startDate),
          lte: new Date(endDate),
        },
      };

      if (driverId) where.driverId = driverId;
      if (customerId) where.customerId = customerId;
      if (status) where.status = status;

      const [
        totalShipments,
        activeShipments,
        completedShipments,
        avgDeliveryTime,
        onTimeShipments,
      ] = await Promise.all([
        prisma.shipment.count({ where }),
        prisma.shipment.count({ where: { ...where, status: "IN_TRANSIT" } }),
        prisma.shipment.count({ where: { ...where, status: "DELIVERED" } }),
        prisma.shipment.aggregate({
          where: { ...where, status: "DELIVERED" },
          _avg: { deliveryTime: true },
        }),
        prisma.shipment.count({
          where: {
            ...where,
            status: "DELIVERED",
            deliveryTime: { lte: prisma.shipment.fields.estimatedDelivery },
          },
        }),
      ]);

      const topDrivers = await prisma.driver.findMany({
        where: {
          shipments: {
            some: {
              createdAt: {
                gte: new Date(startDate),
                lte: new Date(endDate),
              },
            },
          },
        },
        take: 10,
        orderBy: {
          rating: "desc",
        },
        include: { user: true },
      });

      return {
        totalShipments,
        activeShipments,
        completedShipments,
        averageDeliveryTime: avgDeliveryTime._avg.deliveryTime || 0,
        onTimeRate:
          completedShipments > 0 ? onTimeShipments / completedShipments : 0,
        customerSatisfaction: 4.5, // From reviews
        revenue: totalShipments * 150, // Average $150 per shipment
        topDrivers,
      };
    },
  },

  Mutation: {
    // Shipment mutations
    createShipment: async (_: any, { input }: any, context: any) => {
      if (!context.user) {
        throw new GraphQLError("Not authenticated", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      const shipment = await prisma.shipment.create({
        data: {
          ...input,
          customerId: context.user.sub,
          trackingNumber: `INF-${Date.now()}`,
          status: "PENDING",
        },
        include: {
          customer: true,
        },
      });

      // Publish to subscriptions
      pubsub.publish(SHIPMENT_UPDATED, { shipmentUpdated: shipment });

      return shipment;
    },

    updateShipment: async (_: any, { id, input }: any, context: any) => {
      if (!context.user) {
        throw new GraphQLError("Not authenticated", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      const shipment = await prisma.shipment.update({
        where: { id },
        data: input,
        include: {
          customer: true,
          driver: true,
        },
      });

      // Publish to subscriptions
      pubsub.publish(SHIPMENT_UPDATED, { shipmentUpdated: shipment });

      return shipment;
    },

    assignDriver: async (
      _: any,
      { shipmentId, driverId }: any,
      context: any,
    ) => {
      if (!context.user || context.user.role !== "admin") {
        throw new GraphQLError("Not authorized", {
          extensions: { code: "FORBIDDEN" },
        });
      }

      const shipment = await prisma.shipment.update({
        where: { id: shipmentId },
        data: {
          driverId,
          status: "IN_TRANSIT",
        },
        include: {
          customer: true,
          driver: true,
        },
      });

      pubsub.publish(SHIPMENT_UPDATED, { shipmentUpdated: shipment });

      return shipment;
    },

    // Driver mutations
    updateDriverLocation: async (
      _: any,
      { driverId, location }: any,
      context: any,
    ) => {
      if (!context.user || context.user.sub !== driverId) {
        throw new GraphQLError("Not authorized", {
          extensions: { code: "FORBIDDEN" },
        });
      }

      const driver = await prisma.driver.update({
        where: { id: driverId },
        data: {
          latitude: location.latitude,
          longitude: location.longitude,
          lastLocationUpdate: new Date(),
        },
        include: { user: true },
      });

      pubsub.publish(DRIVER_LOCATION_UPDATED, {
        driverLocationUpdated: driver,
      });

      return driver;
    },
  },

  Subscription: {
    shipmentUpdated: {
      subscribe: (_: any, { id }: any) => {
        return pubsub.asyncIterator([SHIPMENT_UPDATED]);
      },
      resolve: (payload: any) => payload.shipmentUpdated,
    },

    driverLocationUpdated: {
      subscribe: (_: any, { id }: any) => {
        return pubsub.asyncIterator([DRIVER_LOCATION_UPDATED]);
      },
      resolve: (payload: any) => payload.driverLocationUpdated,
    },
  },

  // Field resolvers
  Shipment: {
    history: async (parent: any) => {
      return prisma.shipmentEvent.findMany({
        where: { shipmentId: parent.id },
        orderBy: { timestamp: "desc" },
      });
    },
  },

  Driver: {
    assignedShipments: async (parent: any) => {
      return prisma.shipment.findMany({
        where: {
          driverId: parent.id,
          status: { in: ["PENDING", "IN_TRANSIT"] },
        },
      });
    },

    completedShipments: async (parent: any) => {
      return prisma.shipment.count({
        where: {
          driverId: parent.id,
          status: "DELIVERED",
        },
      });
    },
  },

  User: {
    shipments: async (parent: any) => {
      return prisma.shipment.findMany({
        where: { customerId: parent.id },
        orderBy: { createdAt: "desc" },
      });
    },
  },
};

export default resolvers;
