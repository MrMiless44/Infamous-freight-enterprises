/**
 * WebSocket Event Handlers
 * Real-time event handlers for shipment tracking, notifications, and collaboration
 */

import { Socket } from "socket.io";
import { prisma } from "../lib/prisma";
import { NotificationService } from "./notification.service";

export class WebSocketEventHandler {
  /**
   * Register all WebSocket event handlers
   */
  static registerHandlers(socket: Socket) {
    // Shipment tracking events
    socket.on("shipment:subscribe", (shipmentId: string) =>
      this.handleShipmentSubscribe(socket, shipmentId),
    );
    socket.on("shipment:unsubscribe", (shipmentId: string) =>
      this.handleShipmentUnsubscribe(socket, shipmentId),
    );
    socket.on("shipment:update", (data) =>
      this.handleShipmentUpdate(socket, data),
    );

    // Driver location tracking
    socket.on("driver:location", (data) =>
      this.handleDriverLocation(socket, data),
    );
    socket.on("driver:status", (data) => this.handleDriverStatus(socket, data));

    // Real-time collaboration
    socket.on("notification:read", (notificationId: string) =>
      this.handleNotificationRead(socket, notificationId),
    );
    socket.on("message:send", (data) => this.handleMessage(socket, data));

    // Connection lifecycle
    socket.on("disconnect", () => this.handleDisconnect(socket));
  }

  /**
   * Subscribe to shipment updates
   */
  private static async handleShipmentSubscribe(
    socket: Socket,
    shipmentId: string,
  ) {
    try {
      const shipment = await prisma.shipment.findUnique({
        where: { id: shipmentId },
      });

      if (!shipment) {
        socket.emit("error", { message: "Shipment not found" });
        return;
      }

      // Join shipment-specific room
      socket.join(`shipment:${shipmentId}`);
      console.log(`Client subscribed to shipment ${shipmentId}`);
    } catch (error) {
      console.error("Failed to subscribe to shipment:", error);
      socket.emit("error", { message: "Subscription failed" });
    }
  }

  /**
   * Unsubscribe from shipment updates
   */
  private static handleShipmentUnsubscribe(socket: Socket, shipmentId: string) {
    socket.leave(`shipment:${shipmentId}`);
    console.log(`Client unsubscribed from shipment ${shipmentId}`);
  }

  /**
   * Handle shipment status updates (broadcast to all subscribers)
   */
  private static async handleShipmentUpdate(
    socket: Socket,
    data: {
      shipmentId: string;
      status: string;
      location?: { lat: number; lng: number };
      notes?: string;
    },
  ) {
    try {
      const shipment = await prisma.shipment.update({
        where: { id: data.shipmentId },
        data: {
          status: data.status,
          updatedAt: new Date(),
        },
      });

      // Broadcast to all subscribers of this shipment
      socket.io.to(`shipment:${data.shipmentId}`).emit("shipment:updated", {
        id: shipment.id,
        status: shipment.status,
        location: data.location,
        timestamp: new Date().toISOString(),
      });

      // Notify relevant parties
      await NotificationService.notifyShipmentUpdate(shipment);
    } catch (error) {
      console.error("Failed to update shipment:", error);
      socket.emit("error", { message: "Update failed" });
    }
  }

  /**
   * Handle driver location updates (real-time tracking)
   */
  private static async handleDriverLocation(
    socket: Socket,
    data: {
      driverId: string;
      lat: number;
      lng: number;
    },
  ) {
    try {
      // Update driver location in cache for fast access
      const cacheKey = `driver:location:${data.driverId}`;
      // Cache location update (implementation depends on CacheService)

      // Broadcast to all shipments assigned to this driver
      socket.io.emit(`driver:location:${data.driverId}`, {
        driverId: data.driverId,
        lat: data.lat,
        lng: data.lng,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("Failed to update driver location:", error);
    }
  }

  /**
   * Handle driver status changes (online, offline, on break, etc.)
   */
  private static async handleDriverStatus(
    socket: Socket,
    data: {
      driverId: string;
      status: "online" | "offline" | "on_break" | "unavailable";
    },
  ) {
    try {
      const driver = await prisma.driverProfile.update({
        where: { id: data.driverId },
        data: { status: data.status },
      });

      // Notify dispatch and admins
      socket.io.to("dispatch").emit("driver:status:changed", {
        driverId: driver.id,
        status: driver.status,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("Failed to update driver status:", error);
    }
  }

  /**
   * Handle notification read receipts
   */
  private static async handleNotificationRead(
    socket: Socket,
    notificationId: string,
  ) {
    try {
      await prisma.notification.update({
        where: { id: notificationId },
        data: { readAt: new Date() },
      });

      socket.emit("notification:ack", { notificationId });
    } catch (error) {
      console.error("Failed to mark notification as read:", error);
    }
  }

  /**
   * Handle real-time messaging
   */
  private static async handleMessage(
    socket: Socket,
    data: {
      conversationId: string;
      content: string;
      senderId: string;
    },
  ) {
    try {
      const message = await prisma.message.create({
        data: {
          content: data.content,
          conversationId: data.conversationId,
          senderId: data.senderId,
        },
      });

      // Broadcast message to all participants in conversation
      socket.io.to(`conversation:${data.conversationId}`).emit("message:new", {
        id: message.id,
        content: message.content,
        senderId: message.senderId,
        timestamp: message.createdAt.toISOString(),
      });
    } catch (error) {
      console.error("Failed to send message:", error);
      socket.emit("error", { message: "Message send failed" });
    }
  }

  /**
   * Handle client disconnect (cleanup)
   */
  private static handleDisconnect(socket: Socket) {
    console.log(`Client disconnected: ${socket.id}`);
    // Cleanup any subscriptions or temporary data
  }
}
