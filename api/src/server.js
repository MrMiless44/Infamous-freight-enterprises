require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { httpLogger, logger } = require("./middleware/logger");
const { rateLimit } = require("./middleware/security");
const errorHandler = require("./middleware/errorHandler");
const config = require("./config");
const healthRoutes = require("./routes/health");
const aiRoutes = require("./routes/ai.commands");
const billingRoutes = require("./routes/billing");
const voiceRoutes = require("./routes/voice");
const aiSimRoutes = require("./routes/aiSim.internal");

const app = express();

app.set("trust proxy", 1);

const defaultOrigins = ["http://localhost:3000"];
const allowedOrigins = (process.env.CORS_ORIGINS || defaultOrigins.join(","))
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);
const allowedOriginsSet = new Set(allowedOrigins);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && !allowedOriginsSet.has(origin)) {
    return res.status(403).json({
      error: "CORS Rejected",
      message: "Origin is not allowed. Update CORS_ORIGINS to permit this origin.",
    });
  }
  next();
});

app.use(helmet());
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOriginsSet.has(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true
  })
);
app.use(httpLogger);
app.use(rateLimit);
app.use(express.json({ limit: "12mb" }));

// Routes
app.use("/api", healthRoutes);
app.use("/api", aiRoutes);
app.use("/api", billingRoutes);
app.use("/api", voiceRoutes);

// Internal synthetic engine simulator
app.use("/internal", aiSimRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Error handler (must be last)
app.use(errorHandler);

const apiConfig = config.getApiConfig();
const port = apiConfig.port;
const host = apiConfig.host;

if (require.main === module) {
  app.listen(port, host, () => {
    logger.info(`Infamous Freight API listening on ${host}:${port}`);
  });
}

module.exports = app;
