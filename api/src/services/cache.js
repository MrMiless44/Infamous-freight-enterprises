const { logger } = require("../middleware/logger");

/**
 * Cache service with Redis support (or in-memory fallback)
 * Provides caching capabilities for frequently accessed data
 */

let redisClient = null;
const memoryCache = new Map();

// Try to initialize Redis if available
async function initializeRedis() {
  if (process.env.REDIS_URL) {
    try {
      const redis = require("redis");
      redisClient = redis.createClient({
        url: process.env.REDIS_URL,
        socket: {
          reconnectStrategy: (retries) => {
            if (retries > 10) {
              logger.error("Redis reconnection failed after 10 attempts");
              return new Error("Redis unavailable");
            }
            return Math.min(retries * 100, 3000);
          },
        },
      });

      redisClient.on("error", (err) => {
        logger.error("Redis client error", { error: err.message });
      });

      redisClient.on("connect", () => {
        logger.info("Redis client connected");
      });

      await redisClient.connect();
      logger.info("Redis cache initialized successfully");
      return true;
    } catch (error) {
      logger.warn("Failed to initialize Redis, using memory cache", {
        error: error.message,
      });
      redisClient = null;
      return false;
    }
  } else {
    logger.info("No REDIS_URL provided, using in-memory cache");
    return false;
  }
}

/**
 * Get value from cache
 * @param {string} key - Cache key
 * @returns {Promise<any|null>} Cached value or null
 */
async function get(key) {
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
  } catch (error) {
    logger.error("Cache get error", { key, error: error.message });
    return null;
  }
}

/**
 * Set value in cache
 * @param {string} key - Cache key
 * @param {any} value - Value to cache
 * @param {number} ttl - Time to live in seconds (default: 300)
 * @returns {Promise<boolean>} Success status
 */
async function set(key, value, ttl = 300) {
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
  } catch (error) {
    logger.error("Cache set error", { key, error: error.message });
    return false;
  }
}

/**
 * Delete value from cache
 * @param {string} key - Cache key
 * @returns {Promise<boolean>} Success status
 */
async function del(key) {
  try {
    if (redisClient && redisClient.isOpen) {
      await redisClient.del(key);
      return true;
    } else {
      memoryCache.delete(key);
      return true;
    }
  } catch (error) {
    logger.error("Cache delete error", { key, error: error.message });
    return false;
  }
}

/**
 * Delete multiple keys matching a pattern
 * @param {string} pattern - Pattern to match (e.g., "shipments:*")
 * @returns {Promise<number>} Number of keys deleted
 */
async function delPattern(pattern) {
  try {
    if (redisClient && redisClient.isOpen) {
      const keys = await redisClient.keys(pattern);
      if (keys.length > 0) {
        await redisClient.del(keys);
        return keys.length;
      }
      return 0;
    } else {
      let count = 0;
      for (const key of memoryCache.keys()) {
        if (key.startsWith(pattern.replace("*", ""))) {
          memoryCache.delete(key);
          count++;
        }
      }
      return count;
    }
  } catch (error) {
    logger.error("Cache delete pattern error", {
      pattern,
      error: error.message,
    });
    return 0;
  }
}

/**
 * Get or set cached value
 * @param {string} key - Cache key
 * @param {Function} fn - Function to generate value if not cached
 * @param {number} ttl - Time to live in seconds
 * @returns {Promise<any>} Cached or generated value
 */
async function getOrSet(key, fn, ttl = 300) {
  const cached = await get(key);
  if (cached !== null) {
    return cached;
  }

  const value = await fn();
  await set(key, value, ttl);
  return value;
}

/**
 * Clear all cache entries
 * @returns {Promise<boolean>} Success status
 */
async function clear() {
  try {
    if (redisClient && redisClient.isOpen) {
      await redisClient.flushAll();
      return true;
    } else {
      memoryCache.clear();
      return true;
    }
  } catch (error) {
    logger.error("Cache clear error", { error: error.message });
    return false;
  }
}

/**
 * Get cache statistics
 * @returns {Promise<object>} Cache stats
 */
async function getStats() {
  try {
    if (redisClient && redisClient.isOpen) {
      const info = await redisClient.info("stats");
      return {
        type: "redis",
        connected: true,
        info,
      };
    } else {
      return {
        type: "memory",
        size: memoryCache.size,
        keys: Array.from(memoryCache.keys()),
      };
    }
  } catch (error) {
    logger.error("Cache stats error", { error: error.message });
    return { type: "unknown", error: error.message };
  }
}

module.exports = {
  initializeRedis,
  get,
  set,
  del,
  delPattern,
  getOrSet,
  clear,
  getStats,
};
