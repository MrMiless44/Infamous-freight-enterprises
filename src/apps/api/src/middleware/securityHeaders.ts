// @ts-nocheck
/**
 * Enhanced Security Headers Middleware
 * Implements comprehensive security headers per OWASP recommendations
 */

import { Request, Response, NextFunction } from "express";
import helmet from "helmet";

/**
 * Enhanced Helmet configuration
 */
export const enhancedSecurityHeaders = helmet({
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "cdn.jsdelivr.net",
      ],
      styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
      fontSrc: ["'self'", "fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https:", "wss:"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      manifestSrc: ["'self'"],
    },
    reportUri: "/api/security/csp-report",
  },

  // Cross-Origin Resource Sharing
  crossOriginResourcePolicy: { policy: "cross-origin" },

  // Cross-Origin Opener Policy
  crossOriginOpenerPolicy: { policy: "same-origin" },

  // Cross-Origin Embedder Policy
  crossOriginEmbedderPolicy: true,

  // DNS Prefetch Control
  dnsPrefetchControl: { allow: false },

  // Expect-CT (Certificate Transparency)
  expectCt: { maxAge: 86400, enforce: true },

  // Feature Policy / Permissions Policy
  permissionsPolicy: {
    features: {
      accelerometer: ["()"],
      camera: ["()"],
      geolocation: ["()"],
      gyroscope: ["()"],
      magnetometer: ["()"],
      microphone: ["()"],
      payment: ["()"],
      usb: ["()"],
    },
  },

  // Referrer Policy
  referrerPolicy: { policy: "strict-no-referrer" },

  // X-Content-Type-Options
  noSniff: true,

  // X-Frame-Options
  frameguard: { action: "deny" },

  // X-Powered-By
  hidePoweredBy: true,

  // X-XSS-Protection
  xssFilter: true,

  // Strict-Transport-Security
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
});

/**
 * Custom security headers middleware
 */
export const customSecurityHeaders = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  // Prevent clickjacking
  res.setHeader("X-Frame-Options", "DENY");

  // Disable MIME type sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Enable XSS protection in older browsers
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // Prevent malicious redirects
  res.setHeader("X-Content-Security-Policy", "default-src 'self'");

  // Remove server identification
  res.removeHeader("Server");
  res.removeHeader("X-Powered-By");

  // Add custom security headers
  res.setHeader("X-Application-Name", "Infamous Freight Enterprises");
  res.setHeader("X-Build-Version", process.env.BUILD_VERSION || "unknown");

  // Cache control for sensitive endpoints
  if (req.path.includes("/api/auth") || req.path.includes("/api/billing")) {
    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, max-age=0",
    );
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }

  next();
};

export default enhancedSecurityHeaders;
