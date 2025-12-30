import { logger } from '../middleware/logger';

/**
 * Cache service with Redis support (or in-memory fallback)
 */

let redisClient: any = null;
const memoryCache = new Map<string, { value: any; expiresAt: number }>();

/**
 * Initialize Redis client if available
 */
export async function initializeRedis(): Promise<boolean> {
  if (process.env.REDIS_URL) {
    try {
      const redis = await import('redis');
      redisClient = redis.createClient({
        url: process.env.REDIS_URL,
        socket: {
          reconnectStrategy: (retries: number) => {
            if (retries > 10) {
              logger.error('Redis reconnection failed after 10 attempts');
              return new Error('Redis unavailable');
            }
            return Math.min(retries * 100, 3000);
          },
        },
      });

      redisClient.on('error', (err: Error) => {
        logger.error('Redis client error', { error: err.message });
      });

      redisClient.on('connect', () => {
        logger.info('Redis client connected');
      });

      await redisClient.connect();
      logger.info('Redis cache initialized successfully');
      return true;
    } catch (error: any) {
      logger.warn('Failed to initialize Redis, using memory cache', {
        error: error.message,
      });
      redisClient = null;
      return false;
    }
  } else {
    logger.info('No REDIS_URL provided, using in-memory cache');
    return false;
  }
}

/**
 * Get value from cache
 */
export async function get(key: string): Promise<any | null> {
  try {
    if (redisClient && redisClient.isOpen) {
      const value = await redisClient.get(key);
      return value ? JSON.parse(value) : null;
    } else {
      const cached = memoryCache.get(key);
      if (cached && cached.expiresAt > Date.now()) {
        return cached.value;
      } else if (cached) {
        memoryCache.delete(key);
      }
      return null;
    }
  } catch (error: any) {
    logger.error('Cache get error', { key, error: error.message });
    return null;
  }
}

/**
 * Set value in cache
 */
export async function set(
  key: string,
  value: any,
  ttl: number = 300,
): Promise<boolean> {
  try {
    if (redisClient && redisClient.isOpen) {
      await redisClient.setEx(key, ttl, JSON.stringify(value));
      return true;
    } else {
      memoryCache.set(key, {
        value,
        expiresAt: Date.now() + ttl * 1000,
      });
      return true;
    }
  } catch (error: any) {
    logger.error('Cache set error', { key, error: error.message });
    return false;
  }
}

/**
 * Delete value from cache
 */
export async function del(key: string): Promise<boolean> {
  try {
    if (redisClient && redisClient.isOpen) {
      await redisClient.del(key);
      return true;
    } else {
      memoryCache.delete(key);
      return true;
    }
  } catch (error: any) {
    logger.error('Cache delete error', { key, error: error.message });
    return false;
  }
}

/**
 * Get or set cached value
 */
export async function getOrSet(
  key: string,
  fn: () => Promise<any>,
  ttl: number = 300,
): Promise<any> {
  const cached = await get(key);
  if (cached !== null) {
    return cached;
  }

  const value = await fn();
  await set(key, value, ttl);
  return value;
}

export const cacheService = {
  initializeRedis,
  get,
  set,
  del,
  getOrSet,
};
