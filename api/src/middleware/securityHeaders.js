/**
 * Security Headers Configuration
 *
 * Implements HTTP security headers to protect against common web vulnerabilities:
 * - XSS (Cross-Site Scripting)
 * - Clickjacking
 * - MIME type sniffing
 * - Cache poisoning
 * - SSL/TLS downgrade attacks
 *
 * All headers are configured following OWASP best practices.
 */

const helmet = require("helmet");

/**
 * Enhanced security headers middleware
 * Use this instead of the default helmet() for production environments
 */
function securityHeaders(app) {
  // Helmet.js provides sensible defaults for most headers
  app.use(helmet());

  // Additional hardened configurations
  app.use(
    helmet.contentSecurityPolicy({
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"], // Adjust based on your needs
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        upgradeInsecureRequests: [], // Remove if not using HTTPS
      },
      reportUri: "/api/csp-violation", // Optional: CSP violation reports
    }),
  );

  // Enforce HTTPS and HSTS
  app.use(
    helmet.hsts({
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true, // Add to HSTS preload list
    }),
  );

  // Prevent browsers from MIME-sniffing
  app.use(helmet.noSniff());

  // Prevent clickjacking attacks
  app.use(
    helmet.frameguard({
      action: "deny", // Prevent all framing
    }),
  );

  // Remove X-Powered-By header
  app.use(helmet.hidePoweredBy());

  // Disable client-side caching for sensitive data
  app.use((req, res, next) => {
    // Apply no-cache for certain routes
    if (req.path.includes("/api/auth") || req.path.includes("/api/billing")) {
      res.set({
        "Cache-Control":
          "no-store, no-cache, must-revalidate, proxy-revalidate",
        Pragma: "no-cache",
        Expires: "0",
      });
    }
    next();
  });

  // Referrer Policy
  app.use(
    helmet.referrerPolicy({
      policy: "strict-origin-when-cross-origin",
    }),
  );

  // Permissions Policy (formerly Feature Policy)
  app.use(helmet.permittedCrossDomainPolicies());

  console.log("✓ Security headers initialized");
}

/**
 * CSP Violation Report Handler
 * Logs Content Security Policy violations from browsers
 * Route: POST /api/csp-violation
 */
function handleCSPViolation(req, res) {
  const violation = req.body;

  // Handle null or empty body
  if (!violation) {
    res.status(204).end();
    return;
  }

  console.warn("CSP Violation detected:", {
    "violated-directive": violation["violated-directive"],
    "blocked-uri": violation["blocked-uri"],
    "source-file": violation["source-file"],
    "original-policy": violation["original-policy"],
    timestamp: new Date().toISOString(),
  });

  // Optionally send to monitoring service (Sentry, DataDog, etc)
  if (process.env.SENTRY_DSN) {
    const Sentry = require("./sentry");
    Sentry.captureMessage("CSP Violation", "warning", {
      violation,
    });
  }

  res.status(204).send(); // No content response
}

module.exports = {
  securityHeaders,
  handleCSPViolation,
};
