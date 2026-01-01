/**
 * Rate Limit Metrics Endpoint
 * Provides visibility into rate limit hits and user patterns
 */

import type { Request, Response, NextFunction } from "express";
import { requireScope } from "./auth";

interface RateLimitStats {
  endpoint: string;
  hits: number;
  blocked: number;
  lastReset: Date;
}

// In-memory stats (in production, use Redis)
const stats = new Map<string, RateLimitStats>();

/**
 * Middleware to track rate limit metrics
 */
export function trackRateLimitMetrics(limitName: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${limitName}:${req.path}`;

    if (!stats.has(key)) {
      stats.set(key, {
        endpoint: req.path,
        hits: 0,
        blocked: 0,
        lastReset: new Date(),
      });
    }

    const stat = stats.get(key)!;
    stat.hits++;

    // Track if this request was rate limited
    const originalSend = res.send.bind(res);
    res.send = function (body: any) {
      if (res.statusCode === 429) {
        stat.blocked++;
      }
      return originalSend(body);
    };

    next();
  };
}

/**
 * GET /api/metrics/rate-limits
 * Returns rate limit statistics
 */
export async function getRateLimitMetrics(req: Request, res: Response) {
  const metrics = {
    summary: {
      totalHits: 0,
      totalBlocked: 0,
      blockRate: 0,
    },
    byEndpoint: [] as any[],
    topUsers: [] as any[],
    recommendations: [] as string[],
  };

  // Aggregate stats
  stats.forEach((stat, key) => {
    metrics.summary.totalHits += stat.hits;
    metrics.summary.totalBlocked += stat.blocked;

    metrics.byEndpoint.push({
      endpoint: stat.endpoint,
      hits: stat.hits,
      blocked: stat.blocked,
      blockRate:
        stat.hits > 0
          ? ((stat.blocked / stat.hits) * 100).toFixed(2) + "%"
          : "0%",
      lastReset: stat.lastReset,
    });
  });

  metrics.summary.blockRate =
    metrics.summary.totalHits > 0
      ? (metrics.summary.totalBlocked / metrics.summary.totalHits) * 100
      : 0;

  // Sort by blocked count
  metrics.byEndpoint.sort((a, b) => b.blocked - a.blocked);

  // Recommendations
  if (metrics.summary.blockRate > 5) {
    metrics.recommendations.push(
      "High block rate detected. Consider increasing rate limits or educating users.",
    );
  }

  metrics.byEndpoint.forEach((endpoint) => {
    const blockRateNum = parseFloat(endpoint.blockRate);
    if (blockRateNum > 10) {
      metrics.recommendations.push(
        `Endpoint ${endpoint.endpoint} has ${endpoint.blockRate} block rate. Investigate usage patterns.`,
      );
    }
  });

  res.json({
    success: true,
    data: metrics,
    timestamp: new Date(),
  });
}

/**
 * POST /api/metrics/rate-limits/reset
 * Reset rate limit statistics
 */
export async function resetRateLimitMetrics(req: Request, res: Response) {
  stats.clear();

  res.json({
    success: true,
    message: "Rate limit metrics reset successfully",
    timestamp: new Date(),
  });
}

/**
 * Get rate limit status for specific user
 */
export async function getUserRateLimitStatus(req: Request, res: Response) {
  const userId = req.params.userId || req.user?.sub;

  if (!userId) {
    return res.status(400).json({
      success: false,
      error: "User ID required",
    });
  }

  // In production, query Redis for user-specific limits
  const userStats = {
    userId,
    limits: {
      general: {
        remaining: 95,
        total: 100,
        resetAt: new Date(Date.now() + 900000),
      },
      ai: { remaining: 18, total: 20, resetAt: new Date(Date.now() + 60000) },
      billing: {
        remaining: 28,
        total: 30,
        resetAt: new Date(Date.now() + 900000),
      },
    },
    blocked: {
      count: 0,
      endpoints: [],
    },
  };

  res.json({
    success: true,
    data: userStats,
  });
}

export default {
  trackRateLimitMetrics,
  getRateLimitMetrics,
  resetRateLimitMetrics,
  getUserRateLimitStatus,
};
