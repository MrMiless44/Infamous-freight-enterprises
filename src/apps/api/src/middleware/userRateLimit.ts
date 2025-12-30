import { RateLimiterMemory } from 'rate-limiter-flexible';
import { logger } from './logger';

// User-specific rate limiters (in addition to global rate limiting)
const userLimiters = {
  // Per user: 100 requests per 15 minutes
  general: new RateLimiterMemory({
    keyPrefix: 'user_general',
    points: 100,
    duration: 15 * 60,
    blockDuration: 15 * 60,
  }),

  // Per user AI commands: 30 requests per minute
  ai: new RateLimiterMemory({
    keyPrefix: 'user_ai',
    points: 30,
    duration: 60,
    blockDuration: 60,
  }),

  // Per user billing: 20 requests per 15 minutes
  billing: new RateLimiterMemory({
    keyPrefix: 'user_billing',
    points: 20,
    duration: 15 * 60,
    blockDuration: 15 * 60,
  }),
};

/**
 * User-level rate limiting middleware
 */
export async function userRateLimit(
  limiterType: 'general' | 'ai' | 'billing' = 'general',
) {
  return async (req: any, res: any, next: any) => {
    // Skip if user is not authenticated
    if (!req.user || !req.user.id) {
      return next();
    }

    const limiter = userLimiters[limiterType];
    const userId = req.user.id;

    try {
      const rateLimitRes = await limiter.consume(userId, 1);

      // Add rate limit headers
      res.setHeader('X-RateLimit-User-Limit', limiter.points);
      res.setHeader('X-RateLimit-User-Remaining', rateLimitRes.remainingPoints);
      res.setHeader(
        'X-RateLimit-User-Reset',
        new Date(Date.now() + rateLimitRes.msBeforeNext).toISOString(),
      );

      next();
    } catch (rejRes: any) {
      const retryAfter = Math.ceil(rejRes.msBeforeNext / 1000);

      logger.warn('User rate limit exceeded', {
        userId,
        limiterType,
        retryAfter,
      });

      res.setHeader('Retry-After', retryAfter);
      res.setHeader('X-RateLimit-User-Limit', limiter.points);
      res.setHeader('X-RateLimit-User-Remaining', 0);
      res.setHeader(
        'X-RateLimit-User-Reset',
        new Date(Date.now() + rejRes.msBeforeNext).toISOString(),
      );

      return res.status(429).json({
        success: false,
        error: 'Too many requests from this user',
        message: `User rate limit exceeded. Try again in ${retryAfter} seconds.`,
        retryAfter,
      });
    }
  };
}

export { userLimiters };
