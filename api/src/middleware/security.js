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

async function authenticate(req, res, next) {
  const currentSecret = process.env.JWT_SECRET || process.env.JWT_SECRET_CURRENT;
  const previousSecret = process.env.JWT_SECRET_PREVIOUS;
  if (!currentSecret) {
    return next();
  }

  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing bearer token" });
  }

  try {
    const token = header.replace("Bearer ", "").trim();
    // Verify token with 1 hour max age for added security
    try {
      req.user = jwt.verify(token, currentSecret, { maxAge: "1h" });
    } catch (primaryErr) {
      // If signature invalid and a previous secret exists, try verifying with previous
      if (
        previousSecret &&
        (primaryErr.name === "JsonWebTokenError" || primaryErr.name === "NotBeforeError" || primaryErr.name === "TokenExpiredError")
      ) {
        try {
          req.user = jwt.verify(token, previousSecret, { maxAge: "1h" });
        } catch (_secondaryErr) {
          throw primaryErr; // rethrow original for consistent error handling
        }
      } else {
        throw primaryErr;
      }
    }
    next();
  } catch (err) {
    // Handle specific JWT errors with detailed responses
    if (err.name === "TokenExpiredError") {
      logger.warn(`Token expired for user attempt from IP: ${req.ip}`);
      return res.status(401).json({ 
        error: "Token expired", 
        message: "Your session has expired. Please log in again.",
        code: "TOKEN_EXPIRED"
      });
    }
    if (err.name === "JsonWebTokenError") {
      logger.warn(`Invalid JWT token: ${err.message}`);
      return res.status(401).json({ 
        error: "Invalid token", 
        message: "Authentication token is invalid.",
        code: "INVALID_TOKEN"
      });
    }
    if (err.name === "NotBeforeError") {
      logger.warn(`Token used before valid: ${err.message}`);
      return res.status(401).json({ 
        error: "Token not yet valid", 
        message: "This token cannot be used yet.",
        code: "TOKEN_NOT_ACTIVE"
      });
    }
    // Catch-all for unexpected errors
    logger.error(`Unexpected JWT verification error: ${err.message}`);
    return res.status(401).json({ 
      error: "Authentication failed", 
      message: "Unable to verify authentication token.",
      code: "AUTH_ERROR"
    });
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

/**
 * Generate a JWT token with proper expiration
 * @param {Object} payload - Token payload (user data)
 * @param {string} [expiresIn='1h'] - Token expiration time
 * @returns {string} Signed JWT token
 */
function generateToken(payload, expiresIn = "1h") {
  const secret = process.env.JWT_SECRET || process.env.JWT_SECRET_CURRENT;
  if (!secret) {
    throw new Error("JWT_SECRET or JWT_SECRET_CURRENT is not configured");
  }

  return jwt.sign(payload, secret, {
    expiresIn,
    issuer: "infamous-freight-api",
    audience: "infamous-freight-app",
  });
}

/**
 * Verify and decode a JWT token
 * @param {string} token - JWT token to verify
 * @returns {Object} Decoded token payload
 */
function verifyToken(token) {
  const currentSecret = process.env.JWT_SECRET || process.env.JWT_SECRET_CURRENT;
  const previousSecret = process.env.JWT_SECRET_PREVIOUS;
  if (!currentSecret) {
    throw new Error("JWT_SECRET or JWT_SECRET_CURRENT is not configured");
  }

  try {
    return jwt.verify(token, currentSecret, {
      maxAge: "1h",
      issuer: "infamous-freight-api",
      audience: "infamous-freight-app",
    });
  } catch (primaryErr) {
    if (previousSecret) {
      return jwt.verify(token, previousSecret, {
        maxAge: "1h",
        issuer: "infamous-freight-api",
        audience: "infamous-freight-app",
      });
    }
    throw primaryErr;
  }
}

module.exports = {
  rateLimit,
  authenticate,
  requireScope,
  auditLog,
  limiters,
  createLimiter,
  generateToken,
  verifyToken,
};
