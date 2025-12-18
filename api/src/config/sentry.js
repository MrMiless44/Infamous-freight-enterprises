/**
 * Sentry Configuration for Error Tracking
 *
 * Initializes Sentry to capture and report errors in production.
 * All errors are automatically sent to your Sentry dashboard for analysis.
 *
 * Environment variables required:
 * - SENTRY_DSN: Your Sentry project DSN (get from sentry.io)
 * - NODE_ENV: Environment (development, staging, production)
 */

const Sentry = require("@sentry/node");

let profilingIntegrationFactory = null;
try {
  ({
    nodeProfilingIntegration: profilingIntegrationFactory,
  } = require("@sentry/profiling-node"));
} catch (error) {
  profilingIntegrationFactory = null;
}

function initSentry(app) {
  const isProduction = process.env.NODE_ENV === "production";
  const sentryDsn = process.env.SENTRY_DSN;

  // Only initialize Sentry if DSN is provided and in production
  if (sentryDsn && isProduction) {
    Sentry.init({
      dsn: sentryDsn,
      environment: process.env.NODE_ENV,
      // Setting this option to true will send default PII data to Sentry.
      // For example, automatic IP address collection on events
      sendDefaultPii: true,
      tracesSampleRate: 0.1, // Sample 10% of transactions
      profilesSampleRate: 0.1, // Sample 10% of profiles
      integrations: [
        profilingIntegrationFactory ? profilingIntegrationFactory() : null,
        new Sentry.Integrations.Http({ tracing: true }),
        new Sentry.Integrations.Express({
          request: true,
          serverName: false,
          transaction: "name",
          version: false,
          paths: [],
        }),
      ].filter(Boolean),
      // Ignore certain errors that aren't useful
      ignoreErrors: [
        // Browser extensions
        "top.GLOBALS",
        "chrome-extension://",
        "moz-extension://",
        // Network timeouts
        "NetworkError",
        "Network request failed",
      ],
    });

    // Attach Sentry request handler as early as possible
    app.use(Sentry.Handlers.requestHandler());
    app.use(Sentry.Handlers.tracingHandler());

    console.log("✓ Sentry error tracking initialized");
  } else if (!isProduction) {
    console.log("ℹ Sentry disabled in development/test environment");
  } else {
    console.warn("⚠ Sentry DSN not configured - error tracking disabled");
  }
}

/**
 * Error handler middleware for Sentry
 * Must be attached AFTER all other middleware and routes
 */
function attachErrorHandler(app) {
  const sentryDsn = process.env.SENTRY_DSN;

  if (sentryDsn && process.env.NODE_ENV === "production") {
    // Error handler middleware - must come last
    app.use(Sentry.Handlers.errorHandler());
  }
}

/**
 * Manually capture exceptions
 * Use this in try-catch blocks to send specific errors to Sentry
 *
 * Example:
 * try {
 *   // some code
 * } catch (error) {
 *   Sentry.captureException(error, { level: 'error' });
 * }
 */
function captureException(error, context = {}) {
  if (process.env.SENTRY_DSN) {
    Sentry.captureException(error, { contexts: { custom: context } });
  }
}

/**
 * Manually capture messages
 * Use this for informational logging to Sentry
 */
function captureMessage(message, level = "info") {
  if (process.env.SENTRY_DSN) {
    Sentry.captureMessage(message, level);
  }
}

module.exports = {
  Sentry,
  initSentry,
  attachErrorHandler,
  captureException,
  captureMessage,
};
