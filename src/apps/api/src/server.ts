import express, { type Server } from "express";
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
import { billing } from "./routes/billing";
import { dispatch } from "./routes/dispatch";
import { driver } from "./routes/driver";
import { fleet } from "./routes/fleet";
import { customer } from "./routes/customer";
import { rateLimit } from "./middleware/rateLimit";
import { auditTrail } from "./middleware/audit";
import errorHandler from "./middleware/errorHandler";
import { WebSocketService } from "./services/websocket";
import { CacheService } from "./services/cache";

const app = express();
const httpServer = createServer(app);

// Initialize services
async function initializeServices() {
  try {
    // Initialize cache service (with optional Redis)
    await CacheService.initialize();
    console.info("Cache service initialized");

    // Initialize WebSocket service
    WebSocketService.initialize(httpServer);
    console.info("WebSocket service initialized");
  } catch (error) {
    console.error("Failed to initialize services:", error);
    // Continue with degraded functionality
  }
}

app.use(cors());
app.use(express.json());
app.use(rateLimit);
app.use(auditTrail);

app.use("/api/health", health);
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
