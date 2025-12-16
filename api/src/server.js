require("dotenv").config();
const express = require("express");
const cors = require("cors");
const swaggerUi = require("swagger-ui-express");
const swaggerSpec = require("./core/swagger");
const { httpLogger, logger } = require("./middleware/logger");
const { rateLimit } = require("./middleware/security");
const errorHandler = require("./middleware/errorHandler");
const {
  securityHeaders,
  handleCSPViolation,
} = require("./middleware/securityHeaders");
const { initSentry, attachErrorHandler } = require("./core/config/sentry");
const config = require("./core/config");
const healthRoutes = require("./api/health");
const aiRoutes = require("./api/ai.commands");
const billingRoutes = require("./api/billing");
const voiceRoutes = require("./api/voice");
const aiSimRoutes = require("./api/aiSim.internal");
const usersRoutes = require("./api/users");
const shipmentsRoutes = require("./api/shipments");
const metricsRoutes = require("./api/metrics");
const { metricsMiddleware } = require("@infamous-freight/shared/metrics");

const app = express();

// Initialize Sentry for error tracking (must be early)
initSentry(app);

app.set("trust proxy", 1);

const defaultOrigins = ["http://localhost:3000"];
const allowedOrigins = (process.env.CORS_ORIGINS || defaultOrigins.join(","))
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const allowedOriginsSet = new Set(allowedOrigins);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && !allowedOriginsSet.has(origin)) {
    return res.status(403).json({
      error: "CORS Rejected",
      message:
        "Origin is not allowed. Update CORS_ORIGINS to permit this origin.",
    });
  }
  next();
});

// Apply enhanced security headers
securityHeaders(app);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOriginsSet.has(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true,
  }),
);
app.use(httpLogger);
app.use(rateLimit);
app.use(express.json({ limit: "12mb" }));
// Metrics instrumentation (request counters and duration)
app.use(metricsMiddleware);

// Swagger API Documentation
app.use(
  "/api/docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, {
    customCss: ".swagger-ui .topbar { display: none }",
    customSiteTitle: "Infamous Freight API Docs",
  }),
);

// Routes
app.use("/api", healthRoutes);
app.use("/api", aiRoutes);
app.use("/api", billingRoutes);
app.use("/api", voiceRoutes);
app.use("/api", usersRoutes);
app.use("/api", shipmentsRoutes);
app.use("/api", metricsRoutes);

// CSP Violation Report Handler
app.post("/api/csp-violation", handleCSPViolation);

// Internal synthetic engine simulator
app.use("/internal", aiSimRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Error handler (must be last, after Sentry)
app.use(errorHandler);

// Attach Sentry error handler (must be after all other middleware)
attachErrorHandler(app);

const apiConfig = config.getApiConfig();
const port = apiConfig.port;
const host = apiConfig.host;

if (require.main === module) {
  app.listen(port, host, () => {
    logger.info(`Infamous Freight API listening on ${host}:${port}`);
  });
}

module.exports = app;
