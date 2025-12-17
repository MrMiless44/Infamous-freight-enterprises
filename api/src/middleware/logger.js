const pino = require("pino");
const pinoHttp = require("pino-http");
const { v4: uuidv4 } = require("uuid");

const level = process.env.LOG_LEVEL || "info";
const isProduction = process.env.NODE_ENV === "production";
let transport;

if (!isProduction) {
  const hasPretty = (() => {
    try {
      require.resolve("pino-pretty");
      return true;
    } catch (_err) {
      return false;
    }
  })();

  if (hasPretty) {
    transport = {
      target: "pino-pretty",
      options: {
        colorize: true,
        translateTime: "SYS:standard",
        ignore: "pid,hostname",
      },
    };
  }
}

const logger = pino({
  level,
  transport,
});

/**
 * Middleware to add correlation ID to requests
 */
const correlationMiddleware = (req, res, next) => {
  // Use existing correlation ID or generate new one
  req.correlationId =
    req.headers["x-correlation-id"] ||
    req.headers["x-request-id"] ||
    uuidv4();

  // Add to response headers for tracing
  res.setHeader("X-Correlation-ID", req.correlationId);

  // Add to logger context
  req.log = logger.child({
    correlationId: req.correlationId,
    requestId: req.correlationId,
  });

  next();
};

/**
 * Middleware to track request performance
 */
const performanceMiddleware = (req, res, next) => {
  const startTime = Date.now();

  // Capture original end function
  const originalEnd = res.end;

  // Override end to capture metrics
  res.end = function (...args) {
    const duration = Date.now() - startTime;

    // Log performance metrics
    const logData = {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      correlationId: req.correlationId,
      userAgent: req.get("user-agent"),
      ip: req.ip || req.connection.remoteAddress,
    };

    // Add user info if authenticated
    if (req.user) {
      logData.userId = req.user.sub;
      logData.userRoles = req.user.roles;
    }

    // Log with appropriate level based on duration and status
    if (duration > 1000 || res.statusCode >= 500) {
      logger.error(logData, "Slow or failed request");
    } else if (duration > 500 || res.statusCode >= 400) {
      logger.warn(logData, "Degraded request");
    } else {
      logger.info(logData, "Request completed");
    }

    // Optionally ship log to Datadog via HTTP intake (agentless)
    if (process.env.DD_API_KEY && process.env.DD_LOGS_HTTP_ENABLED === "true") {
      try {
        // Lazy import to avoid hard dependency when disabled
        const axios = require("axios");
        axios.post(
          "https://http-intake.logs.datadoghq.com/api/v2/logs",
          [
            {
              ddsource: "node",
              service: process.env.DD_SERVICE || "infamous-freight-api",
              env: process.env.DD_ENV || process.env.NODE_ENV || "development",
              message: "http_request",
              ...logData,
            },
          ],
          {
            headers: {
              "DD-API-KEY": process.env.DD_API_KEY,
              "Content-Type": "application/json",
            },
            timeout: 1500,
          },
        ).catch(() => { });
      } catch (_err) {
        // ignore when axios not installed
      }
    }

    // Call original end function
    originalEnd.apply(res, args);
  };

  next();
};

const httpLogger = pinoHttp({
  logger,
  customLogLevel: (req, res, err) => {
    if (res.statusCode >= 400 && res.statusCode < 500) {
      return "warn";
    } else if (res.statusCode >= 500 || err) {
      return "error";
    }
    return "info";
  },
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      correlationId: req.correlationId,
      userId: req.user?.sub,
    }),
    res: (res) => ({
      statusCode: res.statusCode,
    }),
  },
});

module.exports = {
  logger,
  httpLogger,
  correlationMiddleware,
  performanceMiddleware,
};

