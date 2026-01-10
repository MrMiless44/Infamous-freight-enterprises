/**
 * Input Sanitization Middleware
 * Protects against XSS attacks using DOMPurify and validator.js
 */

import { Request, Response, NextFunction } from "express";
import createDOMPurify from "isomorphic-dompurify";
import validator from "validator";
import { logger } from "./logger";

const DOMPurify = createDOMPurify();

// Configure DOMPurify to be strict
DOMPurify.setConfig({
  ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "br"],
  ALLOWED_ATTR: ["href", "target"],
  ALLOW_DATA_ATTR: false,
});

export interface SanitizationOptions {
  /**
   * Fields to sanitize (empty = sanitize all string fields)
   */
  fields?: string[];

  /**
   * Fields to skip sanitization
   */
  skipFields?: string[];

  /**
   * Allow HTML tags (default: false)
   */
  allowHtml?: boolean;

  /**
   * Log sanitization events
   */
  logSanitization?: boolean;
}

/**
 * Sanitize a single value
 */
function sanitizeValue(value: any, options: SanitizationOptions): any {
  if (typeof value !== "string") {
    return value;
  }

  // Trim whitespace
  let sanitized = validator.trim(value);

  // Remove XSS vectors
  if (options.allowHtml) {
    // Allow some HTML but sanitize
    sanitized = DOMPurify.sanitize(sanitized);
  } else {
    // Strip all HTML
    sanitized = validator.stripLow(sanitized);
    sanitized = sanitized.replace(/<[^>]*>/g, ""); // Remove HTML tags
  }

  // Escape dangerous characters
  sanitized = validator.escape(sanitized);

  // Check if value was modified
  if (sanitized !== value && options.logSanitization) {
    logger.warn("Input sanitized", {
      original: value.substring(0, 100),
      sanitized: sanitized.substring(0, 100),
    });
  }

  return sanitized;
}

/**
 * Recursively sanitize object
 */
function sanitizeObject(
  obj: any,
  options: SanitizationOptions,
  path: string = "",
): any {
  if (obj === null || obj === undefined) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map((item, index) =>
      sanitizeObject(item, options, `${path}[${index}]`),
    );
  }

  if (typeof obj === "object") {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      const fieldPath = path ? `${path}.${key}` : key;

      // Skip fields if specified
      if (
        options.skipFields?.includes(fieldPath) ||
        options.skipFields?.includes(key)
      ) {
        sanitized[key] = value;
        continue;
      }

      // Only sanitize specified fields if provided
      if (options.fields && options.fields.length > 0) {
        if (
          !options.fields.includes(fieldPath) &&
          !options.fields.includes(key)
        ) {
          sanitized[key] = value;
          continue;
        }
      }

      sanitized[key] = sanitizeObject(value, options, fieldPath);
    }
    return sanitized;
  }

  return sanitizeValue(obj, options);
}

/**
 * Middleware to sanitize request body, query, and params
 */
export function sanitizeMiddleware(
  options: SanitizationOptions = {},
): (req: Request, res: Response, next: NextFunction) => void {
  const defaultOptions: SanitizationOptions = {
    allowHtml: false,
    logSanitization: process.env.NODE_ENV !== "production",
    skipFields: ["password", "token", "apiKey"], // Don't sanitize secrets
    ...options,
  };

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Sanitize body
      if (req.body) {
        req.body = sanitizeObject(req.body, defaultOptions);
      }

      // Sanitize query parameters
      if (req.query) {
        req.query = sanitizeObject(req.query, defaultOptions);
      }

      // Sanitize URL parameters
      if (req.params) {
        req.params = sanitizeObject(req.params, defaultOptions);
      }

      next();
    } catch (err) {
      logger.error("Sanitization failed", { error: (err as Error).message });
      next(err);
    }
  };
}

/**
 * Sanitize specific fields in request
 */
export function sanitizeFields(
  ...fields: string[]
): (req: Request, res: Response, next: NextFunction) => void {
  return sanitizeMiddleware({ fields });
}

/**
 * Sanitize all except specific fields
 */
export function sanitizeExcept(
  ...skipFields: string[]
): (req: Request, res: Response, next: NextFunction) => void {
  return sanitizeMiddleware({ skipFields });
}

/**
 * Allow HTML but sanitize dangerous content
 */
export function sanitizeWithHtml(
  options: SanitizationOptions = {},
): (req: Request, res: Response, next: NextFunction) => void {
  return sanitizeMiddleware({ ...options, allowHtml: true });
}

/**
 * Utility: Sanitize a single string value (for manual sanitization)
 */
export function sanitizeString(value: string, allowHtml = false): string {
  return sanitizeValue(value, { allowHtml, logSanitization: false });
}

/**
 * Utility: Check if string contains XSS vectors
 */
export function containsXSS(value: string): boolean {
  const xssPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi, // onclick, onerror, etc.
    /<iframe/gi,
    /eval\(/gi,
    /expression\(/gi,
  ];

  return xssPatterns.some((pattern) => pattern.test(value));
}

/**
 * Utility: Validate email
 */
export function isValidEmail(email: string): boolean {
  return validator.isEmail(email, {
    allow_display_name: false,
    require_tld: true,
  });
}

/**
 * Utility: Validate URL
 */
export function isValidUrl(url: string): boolean {
  return validator.isURL(url, {
    protocols: ["http", "https"],
    require_protocol: true,
  });
}

/**
 * Utility: Validate UUID
 */
export function isValidUUID(uuid: string): boolean {
  return validator.isUUID(uuid, 4);
}

export default sanitizeMiddleware;
