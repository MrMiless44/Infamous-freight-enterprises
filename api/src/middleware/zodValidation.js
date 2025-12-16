const { z } = require("zod");

/**
 * Zod validation middleware
 * Validates request body, query, or params against a Zod schema
 * 
 * @param {Object} schemas - Object containing schemas for body, query, params
 * @param {z.ZodSchema} schemas.body - Schema for request body
 * @param {z.ZodSchema} schemas.query - Schema for query parameters
 * @param {z.ZodSchema} schemas.params - Schema for route parameters
 * @returns {Function} Express middleware function
 */
function validateRequest(schemas = {}) {
  return async (req, res, next) => {
    const errors = [];

    // Validate request body
    if (schemas.body) {
      const result = schemas.body.safeParse(req.body);
      if (!result.success) {
        errors.push({
          location: "body",
          issues: result.error.issues.map(issue => ({
            path: issue.path.join("."),
            message: issue.message,
            code: issue.code
          }))
        });
      } else {
        req.body = result.data; // Use validated/transformed data
      }
    }

    // Validate query parameters
    if (schemas.query) {
      const result = schemas.query.safeParse(req.query);
      if (!result.success) {
        errors.push({
          location: "query",
          issues: result.error.issues.map(issue => ({
            path: issue.path.join("."),
            message: issue.message,
            code: issue.code
          }))
        });
      } else {
        req.query = result.data;
      }
    }

    // Validate route parameters
    if (schemas.params) {
      const result = schemas.params.safeParse(req.params);
      if (!result.success) {
        errors.push({
          location: "params",
          issues: result.error.issues.map(issue => ({
            path: issue.path.join("."),
            message: issue.message,
            code: issue.code
          }))
        });
      } else {
        req.params = result.data;
      }
    }

    // If validation errors exist, return 400
    if (errors.length > 0) {
      return res.status(400).json({
        error: "Validation failed",
        code: "VALIDATION_ERROR",
        details: errors
      });
    }

    next();
  };
}

/**
 * Validate request body only (convenience wrapper)
 */
function validateBody(schema) {
  return validateRequest({ body: schema });
}

/**
 * Validate query parameters only (convenience wrapper)
 */
function validateQuery(schema) {
  return validateRequest({ query: schema });
}

/**
 * Validate route parameters only (convenience wrapper)
 */
function validateParams(schema) {
  return validateRequest({ params: schema });
}

module.exports = {
  validateRequest,
  validateBody,
  validateQuery,
  validateParams,
  z // Re-export zod for convenience
};
