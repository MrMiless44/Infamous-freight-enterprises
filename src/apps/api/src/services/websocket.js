/**
 * WebSocket Service for Real-Time Tracking
 *
 * Provides real-time updates for:
 * - Shipment location tracking
 * - Driver status changes
 * - Delivery notifications
 * - System events
 */

const WebSocket = require("ws");
const { EventEmitter } = require("events");

class WebSocketService extends EventEmitter {
  constructor() {
    super();
    this.wss = null;
    this.clients = new Map(); // Map<clientId, WebSocket>
    this.subscriptions = new Map(); // Map<clientId, Set<subscriptionKey>>
  }

  /**
   * Initialize WebSocket server
   */
  initialize(server) {
    this.wss = new WebSocket.Server({
      server,
      path: "/ws",
      verifyClient: (info, callback) => {
        // Verify client authentication
        const token = new URL(
          info.req.url,
          "http://localhost",
        ).searchParams.get("token");

        if (!token) {
          callback(false, 401, "Unauthorized");
          return;
        }

        // In production, verify JWT token
        // const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // info.req.user = decoded;

        callback(true);
      },
    });

    this.wss.on("connection", (ws, req) => {
      this.handleConnection(ws, req);
    });

    console.log("[WebSocket] Server initialized");
  }

  /**
   * Handle new WebSocket connection
   */
  handleConnection(ws, req) {
    const clientId = this.generateClientId();
    const url = new URL(req.url, "http://localhost");
    const userId = url.searchParams.get("userId"); // In production, get from JWT

    this.clients.set(clientId, { ws, userId, connectedAt: new Date() });
    this.subscriptions.set(clientId, new Set());

    console.log(`[WebSocket] Client connected: ${clientId} (user: ${userId})`);

    // Send welcome message
    this.sendToClient(clientId, {
      type: "connection",
      status: "connected",
      clientId,
      timestamp: new Date().toISOString(),
    });

    // Handle incoming messages
    ws.on("message", (data) => {
      this.handleMessage(clientId, data);
    });

    // Handle client disconnect
    ws.on("close", () => {
      this.handleDisconnect(clientId);
    });

    // Handle errors
    ws.on("error", (error) => {
      console.error(`[WebSocket] Client error ${clientId}:`, error);
    });

    // Send periodic heartbeat
    const heartbeat = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.ping();
      } else {
        clearInterval(heartbeat);
      }
    }, 30000); // Every 30 seconds
  }

  /**
   * Handle incoming message from client
   */
  handleMessage(clientId, data) {
    try {
      const message = JSON.parse(data.toString());

      switch (message.type) {
        case "subscribe":
          this.subscribe(clientId, message.channel, message.resourceId);
          break;
        case "unsubscribe":
          this.unsubscribe(clientId, message.channel, message.resourceId);
          break;
        case "ping":
          this.sendToClient(clientId, {
            type: "pong",
            timestamp: new Date().toISOString(),
          });
          break;
        default:
          console.warn(`[WebSocket] Unknown message type: ${message.type}`);
      }
    } catch (error) {
      console.error("[WebSocket] Message parse error:", error);
    }
  }

  /**
   * Subscribe client to a channel
   */
  subscribe(clientId, channel, resourceId) {
    const subscriptionKey = `${channel}:${resourceId || "*"}`;
    const clientSubs = this.subscriptions.get(clientId);

    if (clientSubs) {
      clientSubs.add(subscriptionKey);
      console.log(
        `[WebSocket] Client ${clientId} subscribed to ${subscriptionKey}`,
      );

      this.sendToClient(clientId, {
        type: "subscribed",
        channel,
        resourceId,
        timestamp: new Date().toISOString(),
      });
    }
  }

  /**
   * Unsubscribe client from a channel
   */
  unsubscribe(clientId, channel, resourceId) {
    const subscriptionKey = `${channel}:${resourceId || "*"}`;
    const clientSubs = this.subscriptions.get(clientId);

    if (clientSubs) {
      clientSubs.delete(subscriptionKey);
      console.log(
        `[WebSocket] Client ${clientId} unsubscribed from ${subscriptionKey}`,
      );

      this.sendToClient(clientId, {
        type: "unsubscribed",
        channel,
        resourceId,
        timestamp: new Date().toISOString(),
      });
    }
  }

  /**
   * Handle client disconnect
   */
  handleDisconnect(clientId) {
    this.clients.delete(clientId);
    this.subscriptions.delete(clientId);
    console.log(`[WebSocket] Client disconnected: ${clientId}`);
  }

  /**
   * Send message to specific client
   */
  sendToClient(clientId, message) {
    const client = this.clients.get(clientId);
    if (client && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify(message));
    }
  }

  /**
   * Broadcast to all clients subscribed to a channel
   */
  broadcast(channel, resourceId, data) {
    const subscriptionKey = `${channel}:${resourceId}`;
    const wildcardKey = `${channel}:*`;

    this.subscriptions.forEach((subs, clientId) => {
      if (subs.has(subscriptionKey) || subs.has(wildcardKey)) {
        this.sendToClient(clientId, {
          type: "update",
          channel,
          resourceId,
          data,
          timestamp: new Date().toISOString(),
        });
      }
    });
  }

  /**
   * Broadcast shipment location update
   */
  broadcastShipmentLocation(shipmentId, location) {
    this.broadcast("shipment-location", shipmentId, {
      lat: location.lat,
      lng: location.lng,
      address: location.address,
      speed: location.speed,
      heading: location.heading,
    });
  }

  /**
   * Broadcast shipment status update
   */
  broadcastShipmentStatus(shipmentId, status, metadata) {
    this.broadcast("shipment-status", shipmentId, {
      status,
      ...metadata,
    });
  }

  /**
   * Broadcast driver status update
   */
  broadcastDriverStatus(driverId, status, metadata) {
    this.broadcast("driver-status", driverId, {
      status,
      ...metadata,
    });
  }

  /**
   * Broadcast system event
   */
  broadcastSystemEvent(event, data) {
    this.broadcast("system-events", "*", {
      event,
      ...data,
    });
  }

  /**
   * Generate unique client ID
   */
  generateClientId() {
    return `client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get connected client count
   */
  getClientCount() {
    return this.clients.size;
  }

  /**
   * Get all subscriptions for debugging
   */
  getSubscriptions() {
    const subs = {};
    this.subscriptions.forEach((clientSubs, clientId) => {
      subs[clientId] = Array.from(clientSubs);
    });
    return subs;
  }

  /**
   * Close WebSocket server
   */
  close() {
    if (this.wss) {
      this.wss.close();
      console.log("[WebSocket] Server closed");
    }
  }
}

// Singleton instance
const websocketService = new WebSocketService();

module.exports = websocketService;
