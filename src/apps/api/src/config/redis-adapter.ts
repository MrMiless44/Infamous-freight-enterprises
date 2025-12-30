/**
 * Socket.IO Redis Adapter Configuration
 * Enables horizontal scaling across multiple servers
 */

import { createAdapter } from '@socket.io/redis-adapter';
import { createClient } from 'redis';

const pubClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
});

const subClient = pubClient.duplicate();

export async function initializeRedisAdapter(io: any) {
  // Connect both clients
  await Promise.all([pubClient.connect(), subClient.connect()]);

  // Attach Redis adapter
  io.adapter(createAdapter(pubClient, subClient));

  console.log('✅ Socket.IO Redis adapter initialized');

  // Handle connection errors
  pubClient.on('error', (err) => {
    console.error('Redis Pub Client Error:', err);
  });

  subClient.on('error', (err) => {
    console.error('Redis Sub Client Error:', err);
  });

  return { pubClient, subClient };
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
    prefix: 'socket:',
  },

  // Scaling parameters
  scaling: {
    maxConnections: 100000,
    serverCount: parseInt(process.env.SERVER_INSTANCES || '1', 10),
    loadBalancing: 'round-robin',
  },

  // Health check
  healthCheck: {
    interval: 30000, // 30 seconds
    timeout: 5000,
    key: 'health:socket.io',
  },
};
