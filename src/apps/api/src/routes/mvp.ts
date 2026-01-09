import { randomUUID } from "node:crypto";
import crypto from "crypto";
import AWS from "aws-sdk";
import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { requireApiKey } from "../middleware/apiKeyAuth";

const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
const PRESIGN_EXPIRES_SECONDS = Number(
  process.env.S3_PRESIGN_EXPIRES_SECONDS ?? 900,
);

const bucket =
  process.env.S3_BUCKET ||
  process.env.S3_BUCKET_NAME ||
  "infamous-freight-docs";

const s3 = new AWS.S3({
  accessKeyId: process.env.S3_ACCESS_KEY || process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey:
    process.env.S3_SECRET_KEY || process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || "us-east-1",
});

const presignSchema = z.object({
  fileName: z.string().min(1),
  mime: z.string().min(1),
  bytes: z.number().int().positive().max(MAX_UPLOAD_BYTES),
  type: z.enum(["invoice", "rate_conf", "bol", "other"]),
  sha256: z.string().optional(),
});

const rateConfirmationSchema = z.object({
  documentId: z.string().min(1),
});

const invoiceAuditSchema = z.object({
  invoiceDocumentId: z.string().min(1),
  rateConfirmationId: z.string().optional(),
});

const detentionSchema = z
  .object({
    shipmentId: z.string().optional(),
    stops: z
      .array(
        z.object({
          kind: z.enum(["pickup", "dropoff"]),
          locationName: z.string().optional(),
          plannedArrive: z.string().datetime().optional(),
          plannedDepart: z.string().datetime().optional(),
          actualArrive: z.string().datetime().optional(),
          actualDepart: z.string().datetime().optional(),
        }),
      )
      .optional(),
    policy: z
      .object({
        freeMinutes: z.number().int().nonnegative().default(120),
        ratePerHourCents: z.number().int().nonnegative().default(5000),
      })
      .optional(),
  })
  .refine((data) => data.shipmentId || data.stops?.length, {
    message: "shipmentId or stops required",
  });

function buildS3Key(
  orgId: string,
  type: string,
  fileName: string,
  seed: string,
) {
  const extension = fileName.includes(".")
    ? fileName.slice(fileName.lastIndexOf("."))
    : "";
  const hash = crypto
    .createHash("sha256")
    .update(`${orgId}:${type}:${seed}`)
    .digest("hex");
  return `${orgId}/${type}/${hash}${extension}`;
}

async function createJob({
  organizationId,
  type,
  input,
}: {
  organizationId: string;
  type: "parse_rate_confirmation" | "audit_invoice" | "detention_detection";
  input: Record<string, unknown>;
}) {
  return prisma.job.create({
    data: {
      organizationId,
      type,
      status: "queued",
      input,
    },
  });
}

export const mvp = Router();

mvp.get("/health", (_, res) => {
  res.json({ status: "ok" });
});

mvp.use(requireApiKey());

mvp.post("/uploads/presign", async (req, res) => {
  const parsed = presignSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const orgId = req.user!.organizationId;
  const documentId = randomUUID();
  const s3Key = buildS3Key(
    orgId,
    parsed.data.type,
    parsed.data.fileName,
    documentId,
  );

  await prisma.document.create({
    data: {
      id: documentId,
      organizationId: orgId,
      type: parsed.data.type,
      s3Key,
      sha256: parsed.data.sha256 ?? "pending",
      bytes: parsed.data.bytes,
      mime: parsed.data.mime,
      uploadedBy: req.user?.id,
    },
  });

  const uploadUrl = s3.getSignedUrl("putObject", {
    Bucket: bucket,
    Key: s3Key,
    Expires: PRESIGN_EXPIRES_SECONDS,
    ContentType: parsed.data.mime,
    ContentLength: parsed.data.bytes,
  });

  return res.status(201).json({
    documentId,
    uploadUrl,
    s3Key,
    expiresIn: PRESIGN_EXPIRES_SECONDS,
  });
});

mvp.post("/rate-confirmations/parse", async (req, res) => {
  const parsed = rateConfirmationSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const document = await prisma.document.findFirst({
    where: {
      id: parsed.data.documentId,
      organizationId: req.user!.organizationId,
    },
  });

  if (!document) {
    return res.status(404).json({ error: "Document not found" });
  }

  const job = await createJob({
    organizationId: req.user!.organizationId,
    type: "parse_rate_confirmation",
    input: { documentId: document.id },
  });

  return res.status(202).json({ jobId: job.id, status: job.status });
});

mvp.post("/invoices/audit", async (req, res) => {
  const parsed = invoiceAuditSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const job = await createJob({
    organizationId: req.user!.organizationId,
    type: "audit_invoice",
    input: parsed.data,
  });

  return res.status(202).json({ jobId: job.id, status: job.status });
});

mvp.post("/detention-detection", async (req, res) => {
  const parsed = detentionSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const job = await createJob({
    organizationId: req.user!.organizationId,
    type: "detention_detection",
    input: parsed.data,
  });

  return res.status(202).json({ jobId: job.id, status: job.status });
});

mvp.get("/jobs/:id", async (req, res) => {
  const job = await prisma.job.findFirst({
    where: { id: req.params.id, organizationId: req.user!.organizationId },
  });

  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }

  return res.json({
    id: job.id,
    type: job.type,
    status: job.status,
    input: job.input,
    output: job.output,
    error: job.error,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
  });
});
