import { Server } from 'socket.io';
import * as jwt from 'jsonwebtoken';
import { logger } from '../middleware/logger';

let io: Server | null = null;

/**
 * Initialize Socket.IO server for real-time updates
 */
export function initializeWebSocket(httpServer: any): Server | null {
  const allowedOrigins = (
    process.env.CORS_ORIGINS || 'http://localhost:3000'
  )
    .split(',')
    .map((origin) => origin.trim());

  try {
    io = new Server(httpServer, {
      cors: {
        origin: allowedOrigins,
        methods: ['GET', 'POST'],
        credentials: true,
      },
      path: '/socket.io/',
      transports: ['websocket', 'polling'],
    });

    // Authentication middleware
    io.use((socket, next) => {
      const token = (socket.handshake.auth as any).token || (socket.handshake.query as any).token;

      if (!token && process.env.JWT_SECRET) {
        logger.warn('Socket connection rejected: No token provided');
        return next(new Error('Authentication required'));
      }

      if (token) {
        try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET || 'test-secret');
          (socket as any).user = decoded;
          logger.info('Socket authenticated', {
            userId: (decoded as any).sub || (decoded as any).id,
            socketId: socket.id,
          });
          next();
        } catch (err: any) {
          logger.warn('Socket authentication failed', {
            error: err.message,
            socketId: socket.id,
          });
          return next(new Error('Invalid token'));
        }
      } else {
        logger.info('Socket connected (dev mode)', { socketId: socket.id });
        next();
      }
    });

    // Connection handler
    io.on('connection', (socket) => {
      const userId = (socket as any).user?.sub || (socket as any).user?.id || 'anonymous';
      logger.info('Client connected to WebSocket', { socketId: socket.id, userId });

      // Subscribe to shipment updates
      socket.on('subscribe:shipment', (shipmentId: string) => {
        socket.join(`shipment:${shipmentId}`);
        logger.info('Client subscribed to shipment', {
          socketId: socket.id,
          shipmentId,
          userId,
        });
      });

      // Subscribe to driver updates
      socket.on('subscribe:driver', (driverId: string) => {
        socket.join(`driver:${driverId}`);
        logger.info('Client subscribed to driver', {
          socketId: socket.id,
          driverId,
          userId,
        });
      });

      // Handle location updates
      socket.on('driver:location', (data: any) => {
        const { driverId, latitude, longitude, timestamp } = data;
        
        if (!driverId || !latitude || !longitude) {
          return socket.emit('error', { message: 'Invalid location data' });
        }

        io?.to(`driver:${driverId}`).emit('driver:location:update', {
          driverId,
          latitude,
          longitude,
          timestamp: timestamp || Date.now(),
        });
      });

      // Ping/pong
      socket.on('ping', () => {
        socket.emit('pong', { timestamp: Date.now() });
      });

      // Disconnect
      socket.on('disconnect', (reason: string) => {
        logger.info('Client disconnected from WebSocket', {
          socketId: socket.id,
          userId,
          reason,
        });
      });
    });

    logger.info('WebSocket server initialized');
    return io;
  } catch (error: any) {
    logger.error('WebSocket initialization failed', { error: error.message });
    return null;
  }
}

/**
 * Emit shipment update to subscribers
 */
export function emitShipmentUpdate(shipmentId: string, update: any): void {
  if (!io) return;
  io.to(`shipment:${shipmentId}`).emit('shipment:update', {
    shipmentId,
    ...update,
    timestamp: Date.now(),
  });
}

/**
 * Emit driver update to subscribers
 */
export function emitDriverUpdate(driverId: string, update: any): void {
  if (!io) return;
  io.to(`driver:${driverId}`).emit('driver:update', {
    driverId,
    ...update,
    timestamp: Date.now(),
  });
}

/**
 * Get Socket.IO instance
 */
export function getIO(): Server | null {
  return io;
}

export const websocketService = {
  initializeWebSocket,
  emitShipmentUpdate,
  emitDriverUpdate,
  getIO,
};
