const { logger } = require("./logger");

/**
 * Format error context for consistent logging across the API
 */
function formatErrorContext(err, req) {
  return {
    timestamp: new Date().toISOString(),
    userId: req.user?.sub || "anonymous",
    requestId: req.id || req.headers["x-request-id"] || "unknown",
    path: req.path,
    method: req.method,
    statusCode: err.status || 500,
    errorType: err.name || "Error",
    errorMessage: err.message,
    stack: err.stack,
    ip: req.ip || req.connection.remoteAddress,
  };
}

/**
 * Global error handling middleware
 * Provides consistent error responses and centralized logging
 */
function errorHandler(err, req, res, next) {
  const errorContext = formatErrorContext(err, req);

  // Log all errors with context for debugging
  logger.error(errorContext);

  // File upload errors
  if (err.name === "MulterError" || err.code === "LIMIT_FILE_SIZE") {
    logger.warn({
      msg: "File upload validation failed",
      ...errorContext,
      reason: err.name === "MulterError" ? err.code : "FILE_SIZE_LIMIT",
    });
    return res.status(400).json({
      success: false,
      error: "File Upload Error",
      message: err.message || "Invalid file upload",
      requestId: errorContext.requestId,
    });
  }

  // Validation errors
  if (err.status === 400 || err.array) {
    logger.warn({
      msg: "Validation error",
      ...errorContext,
      details: err.array?.() || err.message,
    });
    return res.status(400).json({
      success: false,
      error: "Validation Error",
      details: err.array?.() || err.message,
      requestId: errorContext.requestId,
    });
  }

  // Authentication errors
  if (err.status === 401) {
    logger.info({
      msg: "Authentication failed",
      ...errorContext,
      reason: err.message,
    });
    return res.status(401).json({
      success: false,
      error: "Unauthorized",
      message: err.message || "Authentication required",
      requestId: errorContext.requestId,
    });
  }

  // Forbidden errors
  if (err.status === 403) {
    logger.warn({
      msg: "Access denied",
      ...errorContext,
      reason: err.message,
    });
    return res.status(403).json({
      success: false,
      error: "Forbidden",
      message: err.message || "Access denied",
      requestId: errorContext.requestId,
    });
  }

  // Not found errors
  if (err.status === 404) {
    logger.debug({
      msg: "Resource not found",
      path: req.path,
      method: req.method,
    });
    return res.status(404).json({
      success: false,
      error: "Not Found",
      message: err.message || "Resource not found",
      requestId: errorContext.requestId,
    });
  }

  // Service unavailable errors
  if (err.status === 503) {
    logger.error({
      msg: "Service unavailable",
      ...errorContext,
    });
    return res.status(503).json({
      success: false,
      error: err.message || "Service Unavailable",
      requestId: errorContext.requestId,
    });
  }

  const status = Number.isInteger(err.status) ? err.status : 500;
  const isServerError = status >= 500;

  // Log severity based on error type
  if (isServerError) {
    logger.error({
      msg: "Server error occurred",
      ...errorContext,
      severity: "critical",
    });
  }

  res.status(status).json({
    success: false,
    error: isServerError ? "Server Error" : "Request Error",
    message:
      isServerError && process.env.NODE_ENV === "production"
        ? "Internal server error"
        : err.message || "Unexpected error",
    requestId: errorContext.requestId,
  });
}

module.exports = errorHandler;
