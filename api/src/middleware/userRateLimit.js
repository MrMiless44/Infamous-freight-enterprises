const { RateLimiterMemory } = require("rate-limiter-flexible");
const { logger } = require("./logger");

// User-specific rate limiters (in addition to global rate limiting)
const userLimiters = {
  // Per user: 100 requests per 15 minutes
  general: new RateLimiterMemory({
    keyPrefix: "user_general",
    points: 100,
    duration: 15 * 60,
    blockDuration: 15 * 60,
  }),

  // Per user AI commands: 30 requests per minute (more generous than global)
  ai: new RateLimiterMemory({
    keyPrefix: "user_ai",
    points: 30,
    duration: 60,
    blockDuration: 60,
  }),

  // Per user billing: 20 requests per 15 minutes
  billing: new RateLimiterMemory({
    keyPrefix: "user_billing",
    points: 20,
    duration: 15 * 60,
    blockDuration: 15 * 60,
  }),
};

/**
 * User-level rate limiting middleware
 * Applies rate limits per authenticated user
 * @param {string} limiterType - Type of rate limiter to use (general, ai, billing)
 */
function userRateLimit(limiterType = "general") {
  return async (req, res, next) => {
    // Skip if user is not authenticated
    if (!req.user || !req.user.id) {
      return next();
    }

    const limiter = userLimiters[limiterType];
    if (!limiter) {
      logger.warn(`Unknown user rate limiter type: ${limiterType}`);
      return next();
    }

    const userId = req.user.id;

    try {
      const rateLimitRes = await limiter.consume(userId, 1);

      // Add rate limit headers
      res.set({
        "X-RateLimit-User-Limit": limiter.points,
        "X-RateLimit-User-Remaining": rateLimitRes.remainingPoints,
        "X-RateLimit-User-Reset": new Date(
          Date.now() + rateLimitRes.msBeforeNext,
        ).toISOString(),
      });

      next();
    } catch (rejRes) {
      const retryAfter = Math.ceil(rejRes.msBeforeNext / 1000);

      logger.warn("User rate limit exceeded", {
        userId,
        limiterType,
        retryAfter,
        correlationId: req.correlationId,
      });

      res.set({
        "Retry-After": retryAfter,
        "X-RateLimit-User-Limit": limiter.points,
        "X-RateLimit-User-Remaining": 0,
        "X-RateLimit-User-Reset": new Date(
          Date.now() + rejRes.msBeforeNext,
        ).toISOString(),
      });

      res.status(429).json({
        ok: false,
        error: "Too many requests from this user",
        message: `User rate limit exceeded. Try again in ${retryAfter} seconds.`,
        retryAfter,
      });
    }
  };
}

module.exports = {
  userRateLimit,
  userLimiters,
};
