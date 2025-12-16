const jwt = require("jsonwebtoken");
const { logger } = require("./logger");

const JWT_SECRET = process.env.JWT_SECRET;
const AI_API_KEY = process.env.AI_SYNTHETIC_API_KEY;

/**
 * Hybrid authentication middleware
 * Supports both API key and JWT token authentication
 */
async function authHybrid(req, res, next) {
  const authHeader = req.headers.authorization;
  const apiKey = req.headers["x-api-key"];

  // API Key authentication (for AI/system services)
  if (apiKey && apiKey === AI_API_KEY) {
    req.auth = {
      mode: "api-key",
      scopes: ["ai:query", "data:read", "system:admin", "ai:repair"],
      subject: "ai-synthetic-engine",
    };
    logger.info("Authenticated via API key");
    return next();
  }

  // JWT Bearer token authentication (for users)
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7).trim();
    
    if (!JWT_SECRET) {
      logger.error("JWT_SECRET not configured");
      return res.status(500).json({ error: "Authentication not configured" });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET, { 
        maxAge: "1h",
        issuer: "infamous-freight-api",
        audience: "infamous-freight-app",
      });
      
      req.auth = {
        mode: "jwt",
        subject: decoded.sub || decoded.id,
        scopes: decoded.scopes || ["user:basic"],
        user: decoded,
      };
      
      // Also set req.user for backward compatibility
      req.user = decoded;
      
      logger.info(`Authenticated user: ${req.auth.subject}`);
      return next();
    } catch (err) {
      // Handle specific JWT errors with detailed responses
      if (err.name === "TokenExpiredError") {
        logger.warn(`Token expired - attempt from IP: ${req.ip}`);
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
      logger.error(`Unexpected JWT verification error: ${err.message}`, { stack: err.stack });
      return res.status(401).json({ 
        error: "Authentication failed",
        message: "Unable to verify authentication token.",
        code: "AUTH_ERROR"
      });
    }
  }

  // No valid authentication provided
  return res.status(401).json({ 
    error: "Unauthorized",
    message: "Missing or invalid authentication credentials" 
  });
}

/**
 * API Key authentication middleware
 * Validates X-API-Key header against configured key
 */
async function apiKeyAuth(req, res, next) {
  const apiKey = req.headers["x-api-key"];

  if (!apiKey) {
    return res.status(401).json({ 
      error: "Missing API key",
      message: "X-API-Key header is required" 
    });
  }

  if (apiKey !== AI_API_KEY) {
    logger.warn(`Invalid API key attempt from IP: ${req.ip}`);
    return res.status(401).json({ 
      error: "Invalid API key",
      message: "The provided API key is not valid" 
    });
  }

  req.auth = {
    mode: "api-key",
    scopes: ["ai:query", "data:read", "system:admin", "ai:repair"],
    subject: "ai-synthetic-engine",
  };

  logger.info("Authenticated via API key");
  next();
}

/**
 * JWT authentication middleware
 * Validates Bearer token with 1-hour max age
 */
async function jwtAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ 
      error: "Missing bearer token",
      message: "Authorization header with Bearer token is required" 
    });
  }

  if (!JWT_SECRET) {
    logger.error("JWT_SECRET not configured");
    return res.status(500).json({ error: "Authentication not configured" });
  }

  const token = authHeader.slice(7).trim();

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { 
      maxAge: "1h",
      issuer: "infamous-freight-api",
      audience: "infamous-freight-app",
    });
    
    req.auth = {
      mode: "jwt",
      subject: decoded.sub || decoded.id,
      scopes: decoded.scopes || ["user:basic"],
      user: decoded,
    };
    
    // Also set req.user for backward compatibility
    req.user = decoded;
    
    logger.info(`Authenticated user: ${req.auth.subject}`);
    next();
  } catch (err) {
    // Handle specific JWT errors with detailed responses
    if (err.name === "TokenExpiredError") {
      logger.warn(`Token expired in jwtAuth - attempt from IP: ${req.ip}`);
      return res.status(401).json({ 
        error: "Token expired",
        message: "Your session has expired. Please log in again.",
        code: "TOKEN_EXPIRED"
      });
    }
    if (err.name === "JsonWebTokenError") {
      logger.warn(`Invalid JWT token in jwtAuth: ${err.message}`);
      return res.status(401).json({ 
        error: "Invalid token",
        message: "Authentication token is invalid.",
        code: "INVALID_TOKEN"
      });
    }
    if (err.name === "NotBeforeError") {
      logger.warn(`Token used before valid in jwtAuth: ${err.message}`);
      return res.status(401).json({ 
        error: "Token not yet valid",
        message: "This token cannot be used yet.",
        code: "TOKEN_NOT_ACTIVE"
      });
    }
    // Catch-all for unexpected errors
    logger.error(`Unexpected JWT verification error in jwtAuth: ${err.message}`, { stack: err.stack });
    return res.status(401).json({ 
      error: "Authentication failed",
      message: "Unable to verify authentication token.",
      code: "AUTH_ERROR"
    });
  }
}

module.exports = { authHybrid, apiKeyAuth, jwtAuth };
