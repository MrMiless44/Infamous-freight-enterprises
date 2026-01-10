/**
 * Rate Limiting by IP Address
 * Prevents abuse from specific IP addresses
 */

// @ts-nocheck
import rateLimit from "express-rate-limit";
import RedisStore from "rate-limit-redis";
import { createClient } from "redis";
import { Request, Response } from "express";
import { logger } from "./logger";

// Initialize Redis client for distributed rate limiting
const redisClient = createClient({
  url: process.env.REDIS_URL || "redis://localhost:6379",
});

redisClient.connect().catch((err) => {
  logger.error("Redis connection error for rate limiting", {
    error: err.message,
  });
});

/**
 * IP-based rate limiters
 */
export const ipBasedLimiters = {
  // Strict limit for authentication endpoints
  authByIp: rateLimit({
    store: new RedisStore({
      client: redisClient,
      prefix: "rl:auth:ip:",
    }),
    keyGenerator: (req: Request) =>
      req.ip || req.socket.remoteAddress || "unknown",
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per 15 minutes per IP
    skip: (req: Request) => {
      // Skip for trusted IPs
      const trustedIps = (process.env.TRUSTED_IPS || "").split(",");
      return trustedIps.includes(req.ip || "");
    },
    handler: (req: Request, res: Response) => {
      logger.warn("Auth rate limit exceeded by IP", {
        ip: req.ip,
        endpoint: req.path,
      });
      res.status(429).json({
        error: "Too many authentication attempts from this IP",
        retryAfter: 900,
      });
    },
  }),

  // Medium limit for API endpoints
  apiByIp: rateLimit({
    store: new RedisStore({
      client: redisClient,
      prefix: "rl:api:ip:",
    }),
    keyGenerator: (req: Request) =>
      req.ip || req.socket.remoteAddress || "unknown",
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per 15 minutes per IP
    handler: (req: Request, res: Response) => {
      logger.warn("API rate limit exceeded by IP", {
        ip: req.ip,
        endpoint: req.path,
      });
      res.status(429).json({
        error: "Too many requests from this IP",
        retryAfter: 900,
      });
    },
  }),

  // Strict limit for billing endpoints
  billingByIp: rateLimit({
    store: new RedisStore({
      client: redisClient,
      prefix: "rl:billing:ip:",
    }),
    keyGenerator: (req: Request) =>
      req.ip || req.socket.remoteAddress || "unknown",
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // 10 requests per hour per IP
    handler: (req: Request, res: Response) => {
      logger.warn("Billing rate limit exceeded by IP", {
        ip: req.ip,
        endpoint: req.path,
      });
      res.status(429).json({
        error: "Too many billing requests from this IP",
        retryAfter: 3600,
      });
    },
  }),

  // Moderate limit for AI endpoints
  aiByIp: rateLimit({
    store: new RedisStore({
      client: redisClient,
      prefix: "rl:ai:ip:",
    }),
    keyGenerator: (req: Request) =>
      req.ip || req.socket.remoteAddress || "unknown",
    windowMs: 60 * 1000, // 1 minute
    max: 10, // 10 requests per minute per IP
    handler: (req: Request, res: Response) => {
      logger.warn("AI rate limit exceeded by IP", {
        ip: req.ip,
        endpoint: req.path,
      });
      res.status(429).json({
        error: "Too many AI requests from this IP",
        retryAfter: 60,
      });
    },
  }),
};

/**
 * User-based rate limiters (if authenticated)
 */
export const userBasedLimiters = {
  // Limit per authenticated user
  apiByUser: rateLimit({
    store: new RedisStore({
      client: redisClient,
      prefix: "rl:api:user:",
    }),
    keyGenerator: (req: Request) => {
      // Use user ID if authenticated, fall back to IP
      return (req.user as any)?.sub || req.ip || "anonymous";
    },
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500, // 500 requests per user per 15 minutes
    skip: (req: Request) => !req.user, // Only rate limit authenticated users
  }),
};

/**
 * Block list for abusive IPs
 */
const blockList = new Set<string>();

/**
 * Middleware to check block list
 */
export const blockListMiddleware = (req: any, res: any, next: any) => {
  const ip = req.ip || req.socket.remoteAddress;

  if (blockList.has(ip)) {
    logger.warn("Blocked IP attempted access", { ip, endpoint: req.path });
    return res.status(403).json({
      error: "Your IP address has been blocked",
      code: "IP_BLOCKED",
    });
  }

  next();
};

/**
 * Add IP to block list
 */
export function blockIp(
  ip: string,
  reason: string,
  duration: number = 24 * 60 * 60 * 1000,
) {
  blockList.add(ip);
  logger.info("IP blocked", { ip, reason, duration });

  // Auto-unblock after duration
  setTimeout(() => {
    blockList.delete(ip);
    logger.info("IP unblocked", { ip });
  }, duration);
}

/**
 * Remove IP from block list
 */
export function unblockIp(ip: string) {
  blockList.delete(ip);
  logger.info("IP manually unblocked", { ip });
}

/**
 * Get blocked IPs
 */
export function getBlockedIps(): string[] {
  return Array.from(blockList);
}

export default ipBasedLimiters;
