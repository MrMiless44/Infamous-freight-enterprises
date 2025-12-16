/**
 * Middleware Index
 * Centralized exports for all middleware functions
 */

module.exports = {
  logger: require("./logger"),
  security: require("./security"),
  auth: require("./auth.hybrid"),
  errorHandler: require("./errorHandler"),
  securityHeaders: require("./securityHeaders"),
  validation: require("./validation"),
  zodValidation: require("./zodValidation"),
  schemas: require("./schemas"),
};
