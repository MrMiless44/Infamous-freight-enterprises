const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");
const { logger } = require("../middleware/logger");

let io = null;

/**
 * Initialize Socket.IO server
 * @param {object} httpServer - HTTP server instance
 * @returns {Server} Socket.IO server
 */
function initializeWebSocket(httpServer) {
  const allowedOrigins = (
    process.env.CORS_ORIGINS || "http://localhost:3000"
  )
    .split(",")
    .map((origin) => origin.trim());

  io = new Server(httpServer, {
    cors: {
      origin: allowedOrigins,
      methods: ["GET", "POST"],
      credentials: true,
    },
    path: "/socket.io/",
    transports: ["websocket", "polling"],
  });

  // Authentication middleware
  io.use((socket, next) => {
    const token = socket.handshake.auth.token || socket.handshake.query.token;

    if (!token && process.env.JWT_SECRET) {
      logger.warn("Socket connection rejected: No token provided");
      return next(new Error("Authentication required"));
    }

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "test-secret");
        socket.user = decoded;
        logger.info("Socket authenticated", {
          userId: decoded.sub || decoded.id,
          socketId: socket.id,
        });
        next();
      } catch (err) {
        logger.warn("Socket authentication failed", {
          error: err.message,
          socketId: socket.id,
        });
        return next(new Error("Invalid token"));
      }
    } else {
      // Dev mode: allow unauthenticated connections
      logger.info("Socket connected (dev mode)", { socketId: socket.id });
      next();
    }
  });

  // Connection handler
  io.on("connection", (socket) => {
    const userId = socket.user?.sub || socket.user?.id || "anonymous";
    logger.info("Client connected to WebSocket", {
      socketId: socket.id,
      userId,
    });

    // Subscribe to shipment updates
    socket.on("subscribe:shipment", (shipmentId) => {
      socket.join(`shipment:${shipmentId}`);
      logger.info("Client subscribed to shipment", {
        socketId: socket.id,
        shipmentId,
        userId,
      });
    });

    // Unsubscribe from shipment updates
    socket.on("unsubscribe:shipment", (shipmentId) => {
      socket.leave(`shipment:${shipmentId}`);
      logger.info("Client unsubscribed from shipment", {
        socketId: socket.id,
        shipmentId,
        userId,
      });
    });

    // Subscribe to driver updates
    socket.on("subscribe:driver", (driverId) => {
      socket.join(`driver:${driverId}`);
      logger.info("Client subscribed to driver", {
        socketId: socket.id,
        driverId,
        userId,
      });
    });

    // Unsubscribe from driver updates
    socket.on("unsubscribe:driver", (driverId) => {
      socket.leave(`driver:${driverId}`);
      logger.info("Client unsubscribed from driver", {
        socketId: socket.id,
        driverId,
        userId,
      });
    });

    // Subscribe to all shipments (admin/dispatcher only)
    socket.on("subscribe:shipments:all", () => {
      if (socket.user?.role === "admin" || socket.user?.role === "dispatcher") {
        socket.join("shipments:all");
        logger.info("Client subscribed to all shipments", {
          socketId: socket.id,
          userId,
        });
      } else {
        socket.emit("error", {
          message: "Insufficient permissions",
        });
      }
    });

    // Handle location updates (from mobile drivers)
    socket.on("driver:location", (data) => {
      const { driverId, latitude, longitude, timestamp } = data;
      
      if (!driverId || !latitude || !longitude) {
        return socket.emit("error", {
          message: "Invalid location data",
        });
      }

      // Broadcast location to subscribers
      io.to(`driver:${driverId}`).emit("driver:location:update", {
        driverId,
        latitude,
        longitude,
        timestamp: timestamp || Date.now(),
      });

      logger.debug("Driver location updated", {
        driverId,
        socketId: socket.id,
      });
    });

    // Ping/pong for connection health
    socket.on("ping", () => {
      socket.emit("pong", { timestamp: Date.now() });
    });

    // Disconnection handler
    socket.on("disconnect", (reason) => {
      logger.info("Client disconnected from WebSocket", {
        socketId: socket.id,
        userId,
        reason,
      });
    });

    // Error handler
    socket.on("error", (error) => {
      logger.error("Socket error", {
        socketId: socket.id,
        userId,
        error: error.message,
      });
    });
  });

  logger.info("WebSocket server initialized");
  return io;
}

/**
 * Emit shipment status update to subscribers
 * @param {string} shipmentId - Shipment ID
 * @param {object} update - Update data
 */
function emitShipmentUpdate(shipmentId, update) {
  if (!io) return;

  io.to(`shipment:${shipmentId}`).emit("shipment:update", {
    shipmentId,
    ...update,
    timestamp: Date.now(),
  });

  // Also emit to all subscribers (admin/dispatcher)
  io.to("shipments:all").emit("shipment:update", {
    shipmentId,
    ...update,
    timestamp: Date.now(),
  });

  logger.debug("Shipment update emitted", { shipmentId });
}

/**
 * Emit driver status update to subscribers
 * @param {string} driverId - Driver ID
 * @param {object} update - Update data
 */
function emitDriverUpdate(driverId, update) {
  if (!io) return;

  io.to(`driver:${driverId}`).emit("driver:update", {
    driverId,
    ...update,
    timestamp: Date.now(),
  });

  logger.debug("Driver update emitted", { driverId });
}

/**
 * Emit notification to specific user
 * @param {string} userId - User ID
 * @param {object} notification - Notification data
 */
function emitUserNotification(userId, notification) {
  if (!io) return;

  // Find sockets for this user
  const sockets = Array.from(io.sockets.sockets.values()).filter(
    (socket) => socket.user?.sub === userId || socket.user?.id === userId,
  );

  sockets.forEach((socket) => {
    socket.emit("notification", {
      ...notification,
      timestamp: Date.now(),
    });
  });

  logger.debug("User notification emitted", { userId });
}

/**
 * Get connected clients count
 * @returns {number} Number of connected clients
 */
function getConnectedClientsCount() {
  if (!io) return 0;
  return io.sockets.sockets.size;
}

/**
 * Get Socket.IO instance
 * @returns {Server|null} Socket.IO server instance
 */
function getIO() {
  return io;
}

module.exports = {
  initializeWebSocket,
  emitShipmentUpdate,
  emitDriverUpdate,
  emitUserNotification,
  getConnectedClientsCount,
  getIO,
};
