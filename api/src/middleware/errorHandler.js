// Global error handler
let Sentry;
try {
    Sentry = require('@sentry/node');
} catch (_) {
    Sentry = null;
}

function errorHandler(err, req, res, next) {
    const status = err.status || err.statusCode || 500;
    const message = err.message || 'Internal Server Error';

    // Log structured error
    console.error('Request failed', {
        method: req.method,
        path: req.originalUrl || req.path,
        status,
        error: message,
        user: req.user?.sub,
    });

    // Sentry capture
    if (Sentry && process.env.SENTRY_DSN) {
        Sentry.captureException(err, {
            tags: { path: req.path, method: req.method },
            user: req.user ? { id: req.user.sub } : undefined,
        });
    }

    res.status(status).json({ error: message });
}

module.exports = errorHandler;
