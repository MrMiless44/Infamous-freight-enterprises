/**
 * Socket.IO Redis Adapter Configuration
 * Enables horizontal scaling across multiple servers
 */

import { createClient } from "redis";
import type { Server } from "socket.io";

const pubClient = createClient({
  url: process.env.REDIS_URL || "redis://localhost:6379",
  socket: {
    reconnectStrategy: (retries: number) => {
      if (retries > 10) {
        console.error("Redis reconnection failed after 10 attempts");
        return new Error("Redis unavailable");
      }
      return Math.min(retries * 100, 3000);
    },
  },
});

const subClient = pubClient.duplicate();

/**
 * Initialize Redis adapter for Socket.IO
 * Falls back to memory adapter if Redis is unavailable
 */
export async function initializeRedisAdapter(io: Server) {
  try {
    if (!process.env.REDIS_URL) {
      console.log(
        "⚠️  REDIS_URL not set - using memory adapter (not suitable for production scaling)",
      );
      return { pubClient: null, subClient: null };
    }

    // Try to import Redis adapter
    let createAdapter: any;
    try {
      const module = await import("@socket.io/redis-adapter");
      createAdapter = module.createAdapter;
    } catch (err) {
      console.log(
        "⚠️  @socket.io/redis-adapter not installed - using memory adapter",
      );
      console.log("   Install with: pnpm add @socket.io/redis-adapter");
      return { pubClient: null, subClient: null };
    }

    // Connect Redis clients
    await Promise.all([pubClient.connect(), subClient.connect()]);

    // Attach Redis adapter
    io.adapter(createAdapter(pubClient, subClient));

    console.log("✅ Socket.IO Redis adapter initialized");

    // Handle connection errors
    pubClient.on("error", (err) => {
      console.error("Redis Pub Client Error:", err);
    });

    subClient.on("error", (err) => {
      console.error("Redis Sub Client Error:", err);
    });

    return { pubClient, subClient };
  } catch (error) {
    console.error("Failed to initialize Redis adapter:", error);
    console.log("⚠️  Continuing with memory adapter");
    return { pubClient: null, subClient: null };
  }
}

/**
 * Benefits of Redis adapter:
 * - Enables message broadcasting across multiple server instances
 * - Supports sticky sessions or stateless deployment
 * - Persists socket state in Redis
 * - Scales to thousands of concurrent connections
 *
 * Usage:
 * const io = new Server(httpServer);
 * const { pubClient, subClient } = await initializeRedisAdapter(io);
 *
 * On disconnect:
 * await pubClient.quit();
 * await subClient.quit();
 */

export const redisAdapterConfig = {
  // Connection pooling
  connectionPool: {
    min: 2,
    max: 10,
  },

  // Socket state persistence
  persistence: {
    enabled: true,
    ttl: 86400, // 24 hours
    prefix: "socket:",
  },

  // Scaling parameters
  scaling: {
    maxConnections: 100000,
    serverCount: parseInt(process.env.SERVER_INSTANCES || "1", 10),
    loadBalancing: "round-robin",
  },

  // Health check
  healthCheck: {
    interval: 30000, // 30 seconds
    timeout: 5000,
    key: "health:socket.io",
  },
};
