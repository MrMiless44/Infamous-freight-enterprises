import express from "express";
import cors from "cors";
import { env } from "./config/env";
import "./cron";

import { health } from "./routes/health";
import { auth } from "./routes/auth";
import { ai } from "./routes/ai";
import { avatar } from "./routes/avatar";
import { route } from "./routes/route";
import { invoices } from "./routes/invoices";
import { admin } from "./routes/admin";
import { voice } from "./routes/voice";
import { billing } from "./routes/billing";
import { rateLimit } from "./middleware/rateLimit";
import { auditTrail } from "./middleware/audit";

const app = express();
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

app.listen(env.PORT, () => console.log(`API running on port ${env.PORT}`));
