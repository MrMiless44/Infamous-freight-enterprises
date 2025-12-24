import { randomUUID } from "node:crypto";
import { Router } from "express";
import multer from "multer";
import { z } from "zod";
import { calibrate } from "../ai/v2";
import { prisma } from "../db/prisma";
import { requireAuth } from "../middleware/auth";

const MAX_FILE_SIZE_MB = Number(process.env.VOICE_MAX_FILE_SIZE_MB ?? 10);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE_MB * 1024 * 1024 },
});

const intents = [
  { intent: "invoice_audit", keywords: ["invoice", "billing", "charge"] },
  { intent: "route_support", keywords: ["route", "stop", "dispatch", "eta"] },
  { intent: "driver_support", keywords: ["driver", "avatar", "coaching"] },
  { intent: "safety", keywords: ["safety", "incident", "hazard"] },
  { intent: "status_update", keywords: ["status", "update", "progress"] },
] as const;

type VoiceIntent = (typeof intents)[number]["intent"] | "general_assist";

const commandSchema = z.object({
  text: z.string().min(1, "text is required").max(2000),
  channel: z.string().optional(),
  metadata: z.record(z.any()).optional(),
});

function detectIntent(text: string): { intent: VoiceIntent; tags: string[] } {
  const normalized = text.toLowerCase();
  let best: { intent: VoiceIntent; tags: string[] } = {
    intent: "general_assist",
    tags: [],
  };

  for (const entry of intents) {
    const tags = entry.keywords.filter((keyword) =>
      normalized.includes(keyword),
    );
    if (tags.length > best.tags.length) {
      best = { intent: entry.intent, tags };
    }
  }

  return best;
}

function suggestedNextSteps(intent: VoiceIntent) {
  const steps: Record<VoiceIntent, string[]> = {
    invoice_audit: [
      "Queue invoice for audit workflow",
      "Escalate to compliance if anomalies are detected",
      "Notify AP lead with summary",
    ],
    route_support: [
      "Update dispatch with latest ETA",
      "Sync driver turn-by-turn instructions",
      "Record routing decision in audit log",
    ],
    driver_support: [
      "Refresh driver avatar state",
      "Create coaching note tied to this request",
      "Surface relevant route memories to the driver",
    ],
    safety: [
      "Open safety incident ticket",
      "Attach GPS and telematics data",
      "Notify safety lead on-call",
    ],
    status_update: [
      "Log status update in route session",
      "Share latest checkpoint with operations",
      "Pin this update to the driver profile",
    ],
    general_assist: [
      "Route to operator inbox",
      "Capture request context in memory",
      "Flag for post-run learning loop",
    ],
  };

  return steps[intent] ?? steps.general_assist;
}

export const voice = Router();

voice.use(requireAuth);

voice.post("/command", async (req, res) => {
  const parsed = commandSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const normalizedText = parsed.data.text.trim();
  const { intent, tags } = detectIntent(normalizedText);
  const baseConfidence = Math.min(
    0.95,
    0.55 + Math.min(normalizedText.length, 400) / 400 + tags.length * 0.05,
  );
  const confidence = Number(calibrate(baseConfidence, 0.94).toFixed(2));

  type AvatarMemoryRecord = Awaited<
    ReturnType<typeof prisma.avatarMemory.findMany>
  >[number];

  const memory: AvatarMemoryRecord[] = await prisma.avatarMemory.findMany({
    where: {
      userId: req.user.id,
      organizationId: req.user.organizationId,
    },
    orderBy: { confidence: "desc" },
    take: 3,
  });

  const decision = await prisma.aiDecision.create({
    data: {
      organizationId: req.user.organizationId,
      type: `voice:${intent}`,
      confidence,
      rationale: JSON.stringify({
        summary: normalizedText.slice(0, 240),
        tags,
        channel: parsed.data.channel ?? "command",
        memoryKeys: memory.map((entry) => entry.key),
      }),
    },
  });

  return res.json({
    ok: true,
    intent,
    confidence,
    decisionId: decision.id,
    channel: parsed.data.channel ?? "command",
    recommended: suggestedNextSteps(intent),
    trace: {
      tags,
      summary: normalizedText.slice(0, 240),
      memory: memory.map((entry) => ({
        key: entry.key,
        confidence: entry.confidence,
        pinned: entry.pinned,
      })),
    },
  });
});

voice.post("/ingest", upload.single("audio"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "audio file is required" });
  }

  const referenceId = randomUUID();

  await prisma.aiDecision.create({
    data: {
      organizationId: req.user.organizationId,
      type: "voice:ingest",
      confidence: 1,
      rationale: JSON.stringify({
        filename: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
      }),
    },
  });

  return res.status(201).json({
    ok: true,
    referenceId,
    sizeMb: Number((req.file.size / 1024 / 1024).toFixed(2)),
    mimetype: req.file.mimetype,
    filename: req.file.originalname,
    note:
      "File accepted. Connect a speech-to-text provider to stream transcripts.",
  });
});
