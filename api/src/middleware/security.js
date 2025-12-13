const jwt = require("jsonwebtoken");
const { RateLimiterMemory } = require("rate-limiter-flexible");
const { logger } = require("./logger");

const configuredPoints = parseInt(process.env.RATE_LIMIT_POINTS || "100", 10);
const configuredDuration = parseInt(process.env.RATE_LIMIT_DURATION || "60", 10);

const limiter = new RateLimiterMemory({
  points: Number.isFinite(configuredPoints) ? configuredPoints : 100,
  duration: Number.isFinite(configuredDuration) ? configuredDuration : 60
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
      ip: req.ip
    });
  }
  next();
}

module.exports = { rateLimit, authenticate, requireScope, auditLog };
