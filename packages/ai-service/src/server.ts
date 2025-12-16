import express from "express";
import helmet from "helmet";
import cors from "cors";
import { z } from "zod";
import { sendAICommand } from "@infamous-freight/shared/aiClient";
import { metricsMiddleware, register } from "@infamous-freight/shared/metrics";

const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors());
app.use(metricsMiddleware);

const CommandSchema = z.object({
  command: z.string(),
  payload: z.record(z.any()).optional(),
  context: z.object({
    userId: z.string(),
    mode: z.string(),
  }),
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.get("/metrics", async (_req, res) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

app.post("/command", async (req, res) => {
  try {
    const data = CommandSchema.parse(req.body);
    const result = await sendAICommand(data.command, data.payload ?? {}, data.context);
    res.json({ ok: true, result });
  } catch (e) {
    const message = (e as Error).message || "Invalid request";
    res.status(400).json({ ok: false, error: message });
  }
});

const port = Number(process.env.PORT || 4001);
app.listen(port, () => console.log(`🤖 AI Service listening on ${port}`));
