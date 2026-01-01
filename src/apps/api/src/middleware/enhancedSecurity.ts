/**
 * Enhanced Security Headers Middleware
 * Implements comprehensive security best practices
 * Compliant with OWASP recommendations
 */

import helmet from "helmet";
import type { Express } from "express";

/**
 * Configure enhanced security headers
 * Prevents XSS, clickjacking, MIME-sniffing attacks
 */
export function configureSecurityHeaders(app: Express) {
  app.use(
    helmet({
      // Content Security Policy
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts for Next.js
          styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: [
            "'self'",
            "https://api.stripe.com",
            "https://api.paypal.com",
            "https://sentry.io",
            process.env.API_URL || "",
          ].filter(Boolean),
          fontSrc: ["'self'", "data:"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"], // Prevent clickjacking
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"], // Additional clickjacking protection
        },
      },

      // HTTP Strict Transport Security (HSTS)
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
      },

      // Referrer Policy
      referrerPolicy: {
        policy: "strict-origin-when-cross-origin",
      },

      // Don't allow browsers to sniff MIME types
      noSniff: true,

      // Disable X-Powered-By header
      hidePoweredBy: true,

      // Enable XSS filter in older browsers
      xssFilter: true,

      // Prevent DNS prefetch leaks
      dnsPrefetchControl: {
        allow: false,
      },

      // Don't send referer for cross-origin requests
      crossOriginEmbedderPolicy: true,
      crossOriginOpenerPolicy: { policy: "same-origin" },
      crossOriginResourcePolicy: { policy: "same-origin" },

      // Permissions Policy (formerly Feature Policy)
      permittedCrossDomainPolicies: {
        permittedPolicies: "none",
      },
    }),
  );

  // Additional custom headers
  app.use((req, res, next) => {
    // Permissions Policy
    res.setHeader(
      "Permissions-Policy",
      "geolocation=(self), microphone=(), camera=(), payment=(self)",
    );

    // Expect-CT (Certificate Transparency)
    res.setHeader("Expect-CT", "max-age=86400, enforce");

    // Custom security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");

    next();
  });
}

export default configureSecurityHeaders;
