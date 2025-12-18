/**
 * Sentry Instrumentation Setup
 *
 * IMPORTANT: This file MUST be imported at the very top of your application,
 * before any other modules. It initializes Sentry to properly instrument
 * all Node.js internals and third-party libraries.
 *
 * Usage:
 *   // At the very top of server.js
 *   require("./instrument.js");
 *   // Then all other imports
 */

require('dotenv').config()

const Sentry = require('@sentry/node')

// Try to load profiling integration
let profilingIntegration = null
try {
    const { nodeProfilingIntegration } = require('@sentry/profiling-node')
    profilingIntegration = nodeProfilingIntegration()
} catch (error) {
    // Profiling not available - fail open
}

const isProduction = process.env.NODE_ENV === 'production'
const sentryDsn = process.env.SENTRY_DSN

// Initialize Sentry early for proper instrumentation
if (sentryDsn && isProduction) {
    Sentry.init({
        dsn: sentryDsn,
        environment: process.env.NODE_ENV,
        sendDefaultPii: true,
        tracesSampleRate: 0.1, // Sample 10% of transactions
        profilesSampleRate: 0.1, // Sample 10% of profiles
        integrations: [
            profilingIntegration,
            new Sentry.Integrations.Http({ tracing: true }),
            new Sentry.Integrations.Express({
                app: true,
                request: true,
                serverName: true,
                trackClientIp: true
            }),
            new Sentry.Integrations.OnUncaughtException(),
            new Sentry.Integrations.OnUnhandledRejection()
        ]
    })
}
