/**
 * Tiered Rate Limiting Based on User Subscription Level
 * Provides different rate limits for free, pro, and enterprise users
 */

import rateLimit from "express-rate-limit";
import RedisStore from "rate-limit-redis";
import { Request, Response, NextFunction } from "express";
import { redis } from "./redisCache";

/**
 * Subscription tier definitions with rate limits
 */
export interface RateLimitTier {
  name: "free" | "pro" | "enterprise";
  requests: number; // Max requests
  windowMs: number; // Time window in milliseconds
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

const RATE_LIMIT_TIERS: Record<string, RateLimitTier> = {
  free: {
    name: "free",
    requests: 100, // 100 requests
    windowMs: 60 * 60 * 1000, // per hour
  },
  pro: {
    name: "pro",
    requests: 10000, // 10,000 requests
    windowMs: 60 * 60 * 1000, // per hour
  },
  enterprise: {
    name: "enterprise",
    requests: 1000000, // 1,000,000 requests (essentially unlimited)
    windowMs: 60 * 60 * 1000, // per hour
  },
};

/**
 * Get the appropriate rate limiter for a user's tier
 */
function createTieredLimiter(tier: RateLimitTier) {
  return rateLimit({
    store: new RedisStore({
      client: redis,
      prefix: `rate-limit:${tier.name}:`,
      expiry: Math.ceil(tier.windowMs / 1000), // Convert to seconds
    }),
    windowMs: tier.windowMs,
    max: tier.requests,
    message: {
      error: `Rate limit exceeded for ${tier.name} tier`,
      retryAfter: tier.windowMs / 1000,
    },
    statusCode: 429,
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === "/api/health";
    },
    keyGenerator: (req) => {
      // Use user ID if authenticated, otherwise use IP
      return req.user?.sub || req.ip;
    },
    handler: (req, res) => {
      res.status(429).json({
        error: "Too many requests",
        tier: tier.name,
        retryAfter: Math.ceil(tier.windowMs / 1000),
        limits: {
          requests: tier.requests,
          windowMs: tier.windowMs,
        },
      });
    },
  });
}

/**
 * Middleware factory: Apply appropriate rate limit based on user tier
 */
export function tieredRateLimit(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  // Get user subscription tier (from JWT token)
  const userTier = (req.user?.subscriptionTier as string) || "free";
  const tier = RATE_LIMIT_TIERS[userTier] || RATE_LIMIT_TIERS.free;

  // Get or create limiter for this tier
  const limiter = createTieredLimiter(tier);

  // Apply limiter
  limiter(req, res, next);
}

/**
 * API endpoint-specific rate limiters
 */
export const endpointLimiters = {
  // Expensive operations (higher limits)
  analytics: rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: (req) => {
      const tier = req.user?.subscriptionTier || "free";
      return tier === "enterprise" ? 1000 : tier === "pro" ? 100 : 10;
    },
    message: "Too many analytics requests",
  }),

  // Very expensive operations (strict limits)
  export: rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 1 day
    max: (req) => {
      const tier = req.user?.subscriptionTier || "free";
      return tier === "enterprise" ? 50 : tier === "pro" ? 10 : 2;
    },
    message: "Daily export limit exceeded",
  }),

  // AI operations (moderate limits)
  aiInference: rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: (req) => {
      const tier = req.user?.subscriptionTier || "free";
      return tier === "enterprise" ? 1000 : tier === "pro" ? 100 : 10;
    },
    message: "AI request limit exceeded",
  }),

  // Webhooks (very generous for enterprise)
  webhooks: rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: (req) => {
      const tier = req.user?.subscriptionTier || "free";
      return tier === "enterprise" ? 10000 : tier === "pro" ? 1000 : 100;
    },
  }),
};

/**
 * Track rate limit usage for analytics
 */
export async function trackRateLimitUsage(
  userId: string,
  tier: string,
  endpoint: string,
): Promise<void> {
  const key = `rate-limit-usage:${userId}:${endpoint}`;
  const now = new Date();
  const hour = `${now.getHours()}:00`;

  await redis.hincrby(key, hour, 1);
  await redis.expire(key, 24 * 60 * 60); // Expire after 24 hours
}

/**
 * Get rate limit status for a user
 */
export async function getRateLimitStatus(
  userId: string,
  tier: string,
): Promise<{
  tier: string;
  limit: number;
  remaining: number;
  resetTime: number;
  percentageUsed: number;
}> {
  const tierConfig = RATE_LIMIT_TIERS[tier] || RATE_LIMIT_TIERS.free;
  const key = `rate-limit:${tier}:${userId}`;

  const count = await redis.get(key);
  const ttl = await redis.ttl(key);

  const currentCount = parseInt(count || "0", 10);
  const remaining = Math.max(0, tierConfig.requests - currentCount);
  const percentageUsed = (currentCount / tierConfig.requests) * 100;

  return {
    tier: tierConfig.name,
    limit: tierConfig.requests,
    remaining,
    resetTime: ttl > 0 ? Date.now() + ttl * 1000 : Date.now(),
    percentageUsed,
  };
}

/**
 * Endpoint to check rate limit status
 */
export async function handleRateLimitStatus(req: Request, res: Response) {
  const userId = req.user?.sub;
  const tier = req.user?.subscriptionTier || "free";

  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const status = await getRateLimitStatus(userId, tier);

  res.json({
    success: true,
    data: status,
    warning: status.percentageUsed > 80 ? "Approaching rate limit" : null,
  });
}

/**
 * Middleware to warn when approaching rate limit
 */
export function rateLimitWarning(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const userId = req.user?.sub;
  const tier = req.user?.subscriptionTier || "free";

  if (!userId) {
    return next();
  }

  getRateLimitStatus(userId, tier).then((status) => {
    if (status.percentageUsed > 80) {
      res.setHeader("X-RateLimit-Warning", "Approaching limit");
      res.setHeader("X-RateLimit-Remaining", status.remaining.toString());
      res.setHeader("X-RateLimit-Reset", status.resetTime.toString());
    }

    next();
  });
}

/**
 * Usage in Express app:
 *
 * // Global tiered rate limiting
 * app.use(tieredRateLimit);
 *
 * // Endpoint-specific limits
 * app.get('/api/analytics', endpointLimiters.analytics, getAnalytics);
 * app.post('/api/export', endpointLimiters.export, exportData);
 * app.post('/api/ai/infer', endpointLimiters.aiInference, inferAI);
 *
 * // Rate limit status endpoint
 * app.get('/api/rate-limit/status', handleRateLimitStatus);
 *
 * Example JWT with subscription tier:
 * {
 *   "sub": "user123",
 *   "email": "user@example.com",
 *   "subscriptionTier": "pro"  // free | pro | enterprise
 * }
 */
