/**
 * © 2025 Infæmous Freight. All Rights Reserved.
 *
 * Proprietary Software - Sole Proprietor: Santorio Djuan Miles
 * Unauthorized copying, modification, or distribution is prohibited
 */

import express from "express";
import { createServer } from "http";
import cors from "cors";
import "./cron";
import config from "./config";

import { health } from "./routes/health";
import { auth } from "./routes/auth";
import { ai } from "./routes/ai";
import { avatar } from "./routes/avatar";
import { route } from "./routes/route";
import { invoices } from "./routes/invoices";
import { admin } from "./routes/admin";
import { voice } from "./routes/voice";
import { billing, billingWebhook } from "./routes/billing";
import { dispatch } from "./routes/dispatch";
import { driver } from "./routes/driver";
import { fleet } from "./routes/fleet";
import { customer } from "./routes/customer";
import { predictions } from "./routes/predictions";
import { rateLimit } from "./middleware/rateLimit";
import { auditTrail } from "./middleware/audit";
import errorHandler from "./middleware/errorHandler";
import { websocketService } from "./services/websocket";
import { cacheService } from "./services/cache";
import { monitoring } from "./routes/monitoring";
import { tracingMiddleware } from "./services/tracing";

const app = express();
const httpServer = createServer(app);

// Initialize services
async function initializeServices() {
  try {
    // Initialize cache service (with optional Redis)
    const redisAvailable = await cacheService.initializeRedis();
    console.info("Cache service initialized", { redisAvailable });

    // Initialize WebSocket service
    websocketService.initializeWebSocket(httpServer);
    console.info("WebSocket service initialized");
  } catch (error) {
    console.error("Failed to initialize services:", error);
    // Continue with degraded functionality
  }
}

app.use(cors());
app.use("/api/billing/webhook", billingWebhook);
app.use(express.json());
app.use(tracingMiddleware()); // Phase 3: Distributed tracing
app.use(rateLimit);
app.use(auditTrail);

app.use("/api/health", health);
app.use("/api/metrics", monitoring);
app.use("/api/auth", auth);
app.use("/api/ai", ai);
app.use("/api/avatar", avatar);
app.use("/api/route", route);
app.use("/api/invoices", invoices);
app.use("/api/admin", admin);
app.use("/api/voice", voice);
app.use("/api/billing", billing);
app.use("/api/dispatch", dispatch);
app.use("/api/drivers", driver);
app.use("/api/fleet", fleet);
app.use("/api/customers", customer);
app.use("/api/predictions", predictions);
app.use(errorHandler);

const apiConfig = config.getApiConfig();
const port = Number(apiConfig.port);

// Initialize services and start server
initializeServices().then(() => {
  httpServer.listen(port, () => {
    console.info(`API running on port ${port}`);
    console.info("Services ready for WebSocket and caching");
  });
});
