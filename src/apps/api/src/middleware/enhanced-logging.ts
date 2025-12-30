/**
 * Enhanced Request/Response Logging Middleware
 * Logs all HTTP requests and responses with detailed metrics
 */

import { Request, Response, NextFunction } from "express";
import winston from "winston";
import { v4 as uuidv4 } from "uuid";

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  defaultMeta: { service: "infamous-freight-api" },
  transports: [
    new winston.transports.File({
      filename: "logs/error.log",
      level: "error",
    }),
    new winston.transports.File({
      filename: "logs/combined.log",
    }),
    new winston.transports.File({
      filename: "logs/requests.log",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
      ),
    }),
  ],
});

// Add console transport in development
if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          return `${timestamp} [${level}]: ${message} ${
            Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ""
          }`;
        }),
      ),
    }),
  );
}

// Extend Express Request to include custom properties
declare global {
  namespace Express {
    interface Request {
      id: string;
      startTime: number;
      userAgent?: string;
      userId?: string;
      method: string;
      path: string;
    }
  }
}

/**
 * Logging middleware that tracks request/response lifecycle
 */
export function requestLoggingMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  // Generate unique request ID
  req.id = uuidv4();
  req.startTime = Date.now();

  // Extract user info from JWT if available
  if ((req as any).user) {
    req.userId = (req as any).user.id;
  }

  // Capture response details
  const originalJson = res.json.bind(res);
  let responseData: any;

  res.json = function (data: any) {
    responseData = data;
    return originalJson(data);
  };

  // Log on response finish
  res.on("finish", () => {
    const duration = Date.now() - req.startTime;
    const logData = {
      requestId: req.id,
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      query: req.query,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      durationMs: duration,
      userAgent: req.get("user-agent"),
      userId: req.userId,
      ip: req.ip || req.connection.remoteAddress,
      responseSize: res.get("content-length") || "unknown",
    };

    // Log based on status code
    if (res.statusCode >= 500) {
      logger.error("Request failed", {
        ...logData,
        error: responseData?.error || "Internal Server Error",
        stack: responseData?.stack,
      });
    } else if (res.statusCode >= 400) {
      logger.warn("Request error", {
        ...logData,
        error: responseData?.error,
      });
    } else {
      logger.info(`${req.method} ${req.path}`, logData);
    }

    // Performance warning for slow requests
    if (duration > 1000) {
      logger.warn("Slow request detected", {
        requestId: req.id,
        path: req.path,
        duration: `${duration}ms`,
      });
    }
  });

  // Log errors
  res.on("error", (error: Error) => {
    logger.error("Response error", {
      requestId: req.id,
      path: req.path,
      error: error.message,
      stack: error.stack,
    });
  });

  next();
}

/**
 * Detailed request body logging middleware
 */
export function requestBodyLoggingMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (["POST", "PATCH", "PUT"].includes(req.method)) {
    logger.debug("Request body", {
      requestId: req.id,
      path: req.path,
      method: req.method,
      body: sanitizeData(req.body),
    });
  }
  next();
}

/**
 * Security event logging
 */
export function securityEventLogger(
  eventType: string,
  details: any,
  severity: "low" | "medium" | "high" | "critical" = "medium",
) {
  logger.warn(`Security Event: ${eventType}`, {
    eventType,
    severity,
    timestamp: new Date().toISOString(),
    ...details,
  });
}

/**
 * Business event logging
 */
export function businessEventLogger(eventType: string, details: any) {
  logger.info(`Business Event: ${eventType}`, {
    eventType,
    timestamp: new Date().toISOString(),
    ...details,
  });
}

/**
 * Performance metrics logging
 */
export function performanceLogger(
  operation: string,
  durationMs: number,
  metadata?: any,
) {
  logger.info("Performance metric", {
    operation,
    durationMs,
    timestamp: new Date().toISOString(),
    ...metadata,
  });
}

/**
 * Database query logging
 */
export function databaseQueryLogger(
  query: string,
  durationMs: number,
  params?: any,
) {
  if (durationMs > 1000) {
    logger.warn("Slow database query", {
      query,
      durationMs,
      params: sanitizeData(params),
      timestamp: new Date().toISOString(),
    });
  } else if (process.env.LOG_LEVEL === "debug") {
    logger.debug("Database query", {
      query,
      durationMs,
      params: sanitizeData(params),
    });
  }
}

/**
 * API call logging (for external services)
 */
export function externalApiLogger(
  service: string,
  endpoint: string,
  method: string,
  statusCode: number,
  durationMs: number,
  error?: Error,
) {
  const logData = {
    service,
    endpoint,
    method,
    statusCode,
    durationMs,
    timestamp: new Date().toISOString(),
  };

  if (error || statusCode >= 400) {
    logger.warn(`External API Error: ${service}`, {
      ...logData,
      error: error?.message,
    });
  } else {
    logger.info(`External API Call: ${service}`, logData);
  }
}

/**
 * Sanitize sensitive data from logs
 */
function sanitizeData(data: any): any {
  if (!data) return data;

  const sensitiveFields = [
    "password",
    "token",
    "secret",
    "apiKey",
    "creditCard",
    "ssn",
  ];
  const sanitized = { ...data };

  const sanitizeObject = (obj: any) => {
    for (const key in obj) {
      if (sensitiveFields.some((field) => key.toLowerCase().includes(field))) {
        obj[key] = "***REDACTED***";
      } else if (typeof obj[key] === "object" && obj[key] !== null) {
        sanitizeObject(obj[key]);
      }
    }
  };

  sanitizeObject(sanitized);
  return sanitized;
}

/**
 * Request correlation logger
 * Ensures request ID is passed through async operations
 */
export function createCorrelatedLogger(req: Request) {
  return {
    log: (message: string, meta?: any) => {
      logger.info(message, { requestId: req.id, ...meta });
    },
    warn: (message: string, meta?: any) => {
      logger.warn(message, { requestId: req.id, ...meta });
    },
    error: (message: string, meta?: any) => {
      logger.error(message, { requestId: req.id, ...meta });
    },
    debug: (message: string, meta?: any) => {
      logger.debug(message, { requestId: req.id, ...meta });
    },
  };
}

export default logger;
