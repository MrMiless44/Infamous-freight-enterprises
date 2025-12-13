const jwt = require("jsonwebtoken");
const expressRateLimit = require("express-rate-limit");
const { RateLimiterMemory } = require("rate-limiter-flexible");
const { logger } = require("./logger");

// Express Rate Limiter for simpler, per-endpoint rate limiting
const createLimiter = (options = {}) => {
  return expressRateLimit({
    windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
    max: options.max || 100, // Limit each IP to 100 requests per windowMs
    message:
      options.message ||
      "Too many requests from this IP, please try again later.",
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === "/health" || req.path === "/api/health";
    },
    handler: (req, res) => {
      logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
      res.status(429).json({
        error: "Too many requests",
        message: "You have exceeded the rate limit. Please try again later.",
        retryAfter: req.rateLimit.resetTime,
      });
    },
  });
};

// Preset limiters for different endpoints
const limiters = {
  // General API endpoints
  general: createLimiter({ windowMs: 15 * 60 * 1000, max: 100 }),

  // Authentication endpoints (stricter)
  auth: createLimiter({ windowMs: 15 * 60 * 1000, max: 5 }),

  // Billing endpoints (moderate)
  billing: createLimiter({ windowMs: 15 * 60 * 1000, max: 30 }),

  // AI endpoints (moderate - can be expensive)
  ai: createLimiter({ windowMs: 1 * 60 * 1000, max: 20 }), // 20 per minute
};

// Legacy memory-based limiter (kept for backward compatibility)
const configuredPoints = parseInt(process.env.RATE_LIMIT_POINTS || "100", 10);
const configuredDuration = parseInt(
  process.env.RATE_LIMIT_DURATION || "60",
  10,
);

const limiter = new RateLimiterMemory({
  points: Number.isFinite(configuredPoints) ? configuredPoints : 100,
  duration: Number.isFinite(configuredDuration) ? configuredDuration : 60,
});

async function rateLimit(req, res, next) {
  try {
    await limiter.consume(req.ip || req.connection.remoteAddress || "global");
    next();
  } catch (err) {
    const rateLimitError = new Error("Too many requests");
    rateLimitError.status = 429;
    next(rateLimitError);
  }
}

function authenticate(req, res, next) {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return next();
  }

  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing bearer token" });
  }

  try {
    const token = header.replace("Bearer ", "").trim();
    req.user = jwt.verify(token, secret);
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
}

function requireScope(scope) {
  return (req, res, next) => {
    if (!scope) {
      return next();
    }

    const scopes = req.user?.scopes || [];
    if (!scopes.includes(scope)) {
      return res.status(403).json({ error: "Insufficient scope" });
    }

    next();
  };
}

function auditLog(req, _res, next) {
  if (process.env.AUDIT_LOG !== "off") {
    logger.info({
      ts: new Date().toISOString(),
      path: req.path,
      method: req.method,
      user: req.user?.sub,
      ip: req.ip,
    });
  }
  next();
}

module.exports = {
  rateLimit,
  authenticate,
  requireScope,
  auditLog,
  limiters,
  createLimiter,
};
