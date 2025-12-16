const { logger } = require("./logger");

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

  // File upload errors
  if (err.name === "MulterError" || err.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({
      success: false,
      error: "File Upload Error",
      message: err.message || "Invalid file upload",
    });
  }

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

  // Service unavailable errors
  if (err.status === 503) {
    return res.status(503).json({
      success: false,
      error: err.message || "Service Unavailable",
    });
  }

  const status = Number.isInteger(err.status) ? err.status : 500;
  const isServerError = status >= 500;

  res.status(status).json({
    success: false,
    error: isServerError ? "Server Error" : "Request Error",
    message:
      isServerError && process.env.NODE_ENV === "production"
        ? "Internal server error"
        : err.message || "Unexpected error",
  });
}

module.exports = errorHandler;
