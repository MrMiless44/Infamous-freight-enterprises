require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("rate-limiter-flexible");
const { httpLogger, logger } = require("./middleware/logger");
const errorHandler = require("./middleware/errorHandler");
const config = require("./config");
const healthRoutes = require("./routes/health");
const aiRoutes = require("./routes/ai.commands");
const billingRoutes = require("./routes/billing");
const voiceRoutes = require("./routes/voice");
const aiSimRoutes = require("./routes/aiSim.internal");

const app = express();

app.set("trust proxy", 1);

// Rate limiting
const rateLimiter = new rateLimit.RateLimiterMemory({
  points: 100, // Number of points
  duration: 60, // Per 60 seconds
});

const rateLimiterMiddleware = (req, res, next) => {
  rateLimiter
    .consume(req.ip)
    .then(() => {
      next();
    })
    .catch(() => {
      res.status(429).json({ error: "Too many requests" });
    });
};

const defaultOrigins = ["http://localhost:3000"];
const allowedOrigins = (process.env.CORS_ORIGINS || defaultOrigins.join(","))
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(helmet());
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true
  })
);
app.use(httpLogger);
app.use(express.json({ limit: "12mb" }));
app.use(rateLimiterMiddleware);

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

app.listen(port, host, () => {
  logger.info(`Infamous Freight API listening on ${host}:${port}`);
});
