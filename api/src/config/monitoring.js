/**
 * Production Monitoring Configuration
 * Consolidated monitoring setup for API, Web, and Database
 */

module.exports = {
  // Datadog Configuration
  datadog: {
    enabled: process.env.DD_TRACE_ENABLED === "true",
    service: process.env.DD_SERVICE || "infamous-freight-api",
    env: process.env.DD_ENV || process.env.NODE_ENV || "development",
    version: "2.0.0",
    runtimeMetrics: process.env.DD_RUNTIME_METRICS_ENABLED === "true",
    tracesSampleRate: 1.0,
    logsInjection: true,
  },

  // Sentry Configuration
  sentry: {
    dsn: process.env.SENTRY_DSN,
    enabled: !!process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || "development",
    tracesSampleRate: 1.0,
    profilesSampleRate: 0.1, // 10% of transactions
  },

  // Performance Monitoring
  performance: {
    enabled: process.env.PERFORMANCE_MONITORING_ENABLED !== "false",
    slowQueryThreshold: parseInt(
      process.env.SLOW_QUERY_THRESHOLD || "1000",
      10,
    ), // ms
    slowApiThreshold: parseInt(process.env.SLOW_API_THRESHOLD || "500", 10), // ms
    enableProfiling: process.env.NODE_ENV === "production",
  },

  // Database Performance
  database: {
    poolSize: parseInt(process.env.DB_POOL_SIZE || "10", 10),
    poolTimeout: parseInt(process.env.DB_POOL_TIMEOUT || "30000", 10), // ms
    connectionTimeout: parseInt(
      process.env.DB_CONNECTION_TIMEOUT || "10000",
      10,
    ), // ms
  },

  // Web Vitals (Frontend)
  webVitals: {
    enabled: process.env.NEXT_PUBLIC_ENV === "production",
    reportingUrl: process.env.NEXT_PUBLIC_VITALS_ENDPOINT,
    lcpThreshold: 2500, // ms
    fidThreshold: 100, // ms
    clsThreshold: 0.1,
  },

  // Rate Limiting Thresholds
  rateLimits: {
    general: 100, // per 15 minutes
    auth: 5, // per 15 minutes
    ai: 20, // per minute
    billing: 30, // per 15 minutes
  },

  // Alerts and Thresholds
  alerts: {
    errorRateThreshold: 0.01, // 1% error rate
    responseTimeP95: 500, // ms
    responseTimeP99: 1000, // ms
    uptimeTarget: 0.999, // 99.9%
  },

  // Logging Configuration
  logging: {
    level: process.env.LOG_LEVEL || "info",
    format: process.env.LOG_FORMAT || "json",
    destinations: [
      "console",
      ...(process.env.NODE_ENV === "production" ? ["datadog", "sentry"] : []),
    ],
  },
};
