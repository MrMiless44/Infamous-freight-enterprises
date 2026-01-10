/**
 * Phase 2 Performance Optimization - API Response Caching Middleware
 *
 * Caches GET endpoint responses with intelligent invalidation
 * Expected improvements:
 *   - Cache hit rate: 40% → >70% (+30 pts)
 *   - API response time: 2.0s → 1.2s (40% faster)
 *   - Server load: Reduced by 50-60%
 */

import type { Request, Response, NextFunction } from "express";

interface CacheConfig {
  ttl: number; // Time to live in seconds
  keyPrefix: string; // Redis key prefix
  includeQuery: boolean; // Include query params in cache key
  includeUser: boolean; // Include user ID in cache key
}

const DEFAULT_TTL = 300; // 5 minutes

/**
 * Generate cache key from request
 */
function generateCacheKey(req: Request, config: CacheConfig): string {
  let key = config.keyPrefix;

  if (config.includeUser && req.user?.sub) {
    key += `:user:${req.user.sub}`;
  }

  if (config.includeQuery && Object.keys(req.query).length > 0) {
    const queryStr = JSON.stringify(req.query);
    const hash = require("crypto")
      .createHash("sha256")
      .update(queryStr)
      .digest("hex")
      .slice(0, 8);
    key += `:query:${hash}`;
  }

  return key;
}

/**
 * Cache middleware for GET requests
 */
export function cacheMiddleware(config: Partial<CacheConfig> = {}) {
  const cacheConfig: CacheConfig = {
    ttl: DEFAULT_TTL,
    keyPrefix: "api",
    includeQuery: true,
    includeUser: false,
    ...config,
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    // Only cache GET requests
    if (req.method !== "GET") {
      return next();
    }

    try {
      const redis = req.app.locals.redis;
      if (!redis) {
        return next(); // Redis not available, skip caching
      }

      const cacheKey = generateCacheKey(req, cacheConfig);

      // Try to get from cache
      const cachedData = await redis.get(cacheKey);
      if (cachedData) {
        res.set("X-Cache", "HIT");
        res.set("X-Cache-Key", cacheKey);
        return res.json(JSON.parse(cachedData));
      }

      // Store original json method
      const originalJson = res.json.bind(res);

      // Override json method to cache response
      res.json = function (data: any) {
        // Add cache headers
        res.set("Cache-Control", `public, max-age=${cacheConfig.ttl}`);
        res.set("X-Cache", "MISS");
        res.set("X-Cache-Key", cacheKey);

        // Cache the response
        if (res.statusCode === 200) {
          redis
            .setex(cacheKey, cacheConfig.ttl, JSON.stringify(data))
            .catch((err: Error) => {
              console.error("Cache set error:", err.message);
              // Fail silently - caching error shouldn't break response
            });
        }

        return originalJson(data);
      };

      next();
    } catch (error) {
      console.error("Cache middleware error:", error);
      next(); // Continue on error
    }
  };
}

/**
 * Clear cache for specific patterns
 */
export async function clearCache(redis: any, pattern: string): Promise<number> {
  const keys = await redis.keys(pattern);
  if (keys.length === 0) return 0;
  return redis.del(...keys);
}

/**
 * Cache invalidation middleware
 * Clears cache on POST/PUT/DELETE operations
 */
export function invalidateCacheMiddleware(pattern: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Store original json
    const originalJson = res.json.bind(res);

    res.json = function (data: any) {
      // Invalidate cache after successful mutation
      if ([201, 200].includes(res.statusCode)) {
        const redis = req.app.locals.redis;
        if (redis) {
          clearCache(redis, pattern).catch((err: Error) => {
            console.error("Cache invalidation error:", err.message);
          });
        }
      }

      return originalJson(data);
    };

    next();
  };
}

/**
 * Warm cache with pre-computed data
 */
export async function warmCache(
  redis: any,
  endpoints: Array<{ key: string; data: any; ttl?: number }>,
): Promise<void> {
  for (const { key, data, ttl = DEFAULT_TTL } of endpoints) {
    await redis.setex(key, ttl, JSON.stringify(data));
  }
}

// Phase 2 Caching Configuration - Applied to routes

export const CACHE_CONFIGS = {
  // 5-minute cache for read-heavy endpoints
  shipments: {
    ttl: 300,
    keyPrefix: "cache:shipments",
    includeQuery: true,
    includeUser: false,
  } as CacheConfig,

  drivers: {
    ttl: 300,
    keyPrefix: "cache:drivers",
    includeQuery: true,
    includeUser: false,
  } as CacheConfig,

  routes: {
    ttl: 300,
    keyPrefix: "cache:routes",
    includeQuery: true,
    includeUser: false,
  } as CacheConfig,

  // User-specific caching
  notifications: {
    ttl: 60,
    keyPrefix: "cache:notifications",
    includeQuery: false,
    includeUser: true,
  } as CacheConfig,

  profile: {
    ttl: 300,
    keyPrefix: "cache:profile",
    includeQuery: false,
    includeUser: true,
  } as CacheConfig,

  // Dashboard/analytics caching
  analytics: {
    ttl: 600, // 10 minutes for aggregated data
    keyPrefix: "cache:analytics",
    includeQuery: true,
    includeUser: true,
  } as CacheConfig,
};

// Invalidation patterns for mutations
export const INVALIDATION_PATTERNS = {
  shipmentCreate: "cache:shipments*",
  shipmentUpdate: "cache:shipments*",
  driverUpdate: "cache:drivers*",
  analyticsUpdate: "cache:analytics*",
};
