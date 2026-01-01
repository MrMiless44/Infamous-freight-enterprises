/**
 * Redis Caching Middleware
 * Implements intelligent caching with automatic invalidation
 * Expected impact: 10x faster response times (500ms → 50ms)
 */

import { createClient, RedisClientType } from "redis";
import type { Request, Response, NextFunction } from "express";

let redisClient: RedisClientType | null = null;

/**
 * Initialize Redis client
 */
export async function initializeRedis(): Promise<void> {
  if (redisClient) return;

  const redisUrl = process.env.REDIS_URL || "redis://localhost:6379";

  redisClient = createClient({
    url: redisUrl,
    socket: {
      reconnectStrategy: (retries) => {
        if (retries > 10) {
          console.error("Redis: Too many reconnection attempts");
          return new Error("Redis unavailable");
        }
        return Math.min(retries * 50, 1000);
      },
    },
  });

  redisClient.on("error", (err) => {
    console.error("Redis Client Error:", err);
  });

  redisClient.on("connect", () => {
    console.log("✅ Redis connected successfully");
  });

  try {
    await redisClient.connect();
  } catch (error) {
    console.error("Failed to connect to Redis:", error);
    redisClient = null;
  }
}

interface CacheOptions {
  ttl?: number; // Time to live in seconds
  keyPrefix?: string;
  includeQuery?: boolean;
  includeUser?: boolean;
  skipCache?: (req: Request) => boolean;
}

/**
 * Generate cache key from request
 */
function generateCacheKey(req: Request, options: CacheOptions): string {
  const parts: string[] = [options.keyPrefix || "cache"];

  // Add path
  parts.push(req.path.replace(/\//g, ":"));

  // Add user ID if authenticated
  if (options.includeUser && req.user?.sub) {
    parts.push(`user:${req.user.sub}`);
  }

  // Add query params hash
  if (options.includeQuery && Object.keys(req.query).length > 0) {
    const queryStr = JSON.stringify(req.query);
    const crypto = require("crypto");
    const hash = crypto
      .createHash("sha256")
      .update(queryStr)
      .digest("hex")
      .slice(0, 8);
    parts.push(`q:${hash}`);
  }

  return parts.join(":");
}

/**
 * Cache middleware for GET requests
 */
export function cacheMiddleware(options: CacheOptions = {}) {
  const defaultOptions: CacheOptions = {
    ttl: 300, // 5 minutes default
    keyPrefix: "api",
    includeQuery: true,
    includeUser: false,
    ...options,
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    // Only cache GET requests
    if (req.method !== "GET") {
      return next();
    }

    // Skip if Redis not available
    if (!redisClient || !redisClient.isOpen) {
      return next();
    }

    // Skip if custom condition
    if (defaultOptions.skipCache && defaultOptions.skipCache(req)) {
      return next();
    }

    const cacheKey = generateCacheKey(req, defaultOptions);

    try {
      // Try to get from cache
      const cached = await redisClient.get(cacheKey);

      if (cached) {
        // Cache hit
        const data = JSON.parse(cached);
        res.setHeader("X-Cache-Hit", "true");
        return res.json(data);
      }

      // Cache miss - intercept response
      const originalJson = res.json.bind(res);
      res.json = function (body: any) {
        // Cache the response
        if (res.statusCode === 200) {
          redisClient!
            .setEx(cacheKey, defaultOptions.ttl!, JSON.stringify(body))
            .catch((err) => console.error("Cache write error:", err));
        }

        res.setHeader("X-Cache-Hit", "false");
        return originalJson(body);
      };

      next();
    } catch (error) {
      console.error("Cache middleware error:", error);
      next();
    }
  };
}

/**
 * Invalidate cache by pattern
 */
export async function invalidateCache(pattern: string): Promise<void> {
  if (!redisClient || !redisClient.isOpen) {
    return;
  }

  try {
    const keys = await redisClient.keys(pattern);
    if (keys.length > 0) {
      await redisClient.del(keys);
      console.log(
        `🗑️  Invalidated ${keys.length} cache keys matching: ${pattern}`,
      );
    }
  } catch (error) {
    console.error("Cache invalidation error:", error);
  }
}

/**
 * Invalidate cache for specific resource
 */
export function invalidateCacheMiddleware(
  pattern: string | ((req: Request) => string),
) {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Store original send
    const originalSend = res.send.bind(res);

    res.send = function (body: any) {
      // Invalidate after successful mutation
      if (res.statusCode >= 200 && res.statusCode < 300) {
        const invalidationPattern =
          typeof pattern === "function" ? pattern(req) : pattern;
        invalidateCache(invalidationPattern).catch((err) =>
          console.error("Post-mutation cache invalidation error:", err),
        );
      }
      return originalSend(body);
    };

    next();
  };
}

/**
 * Get cache statistics
 */
export async function getCacheStats(): Promise<{
  connected: boolean;
  keyCount: number;
  memoryUsage?: string;
}> {
  if (!redisClient || !redisClient.isOpen) {
    return { connected: false, keyCount: 0 };
  }

  try {
    const keys = await redisClient.keys("*");
    const info = await redisClient.info("memory");

    return {
      connected: true,
      keyCount: keys.length,
      memoryUsage: info,
    };
  } catch (error) {
    console.error("Failed to get cache stats:", error);
    return { connected: false, keyCount: 0 };
  }
}

export { redisClient };
