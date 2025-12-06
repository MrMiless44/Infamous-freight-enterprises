const jwt = require("jsonwebtoken");
const { RateLimiterMemory } = require("rate-limiter-flexible");

const limiter = new RateLimiterMemory({ points: 30, duration: 60 });

async function rateLimit(req, res, next) {
  try {
    await limiter.consume(req.ip || req.connection.remoteAddress || "global");
    next();
  } catch (err) {
    res.status(429).json({ error: "Too many requests" });
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
    console.info(
      JSON.stringify({
        ts: new Date().toISOString(),
        path: req.path,
        method: req.method,
        user: req.user?.sub,
        ip: req.ip
      })
    );
  }
  next();
}

module.exports = { rateLimit, authenticate, requireScope, auditLog };
