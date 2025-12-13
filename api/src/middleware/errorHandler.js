const logger = require("./logger");

/**
 * Global error handling middleware
 */
function errorHandler(err, req, res, next) {
  logger.error({
    msg: "Error occurred",
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  // Validation errors
  if (err.status === 400 || err.array) {
    return res.status(400).json({
      success: false,
      error: "Validation Error",
      details: err.array?.() || err.message,
    });
  }

  // Authentication errors
  if (err.status === 401) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized",
      message: err.message || "Authentication required",
    });
  }

  // Forbidden errors
  if (err.status === 403) {
    return res.status(403).json({
      success: false,
      error: "Forbidden",
      message: err.message || "Access denied",
    });
  }

  // Not found errors
  if (err.status === 404) {
    return res.status(404).json({
      success: false,
      error: "Not Found",
      message: err.message || "Resource not found",
    });
  }

  // Generic server error
  res.status(err.status || 500).json({
    success: false,
    error: "Server Error",
    message: process.env.NODE_ENV === "production" ? "Internal server error" : err.message,
  });
}

module.exports = errorHandler;
