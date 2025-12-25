import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { requireAuth } from "../middleware/auth";

const createInvoiceSchema = z.object({
  amount: z.number().positive(),
  vendor: z.string().min(1),
  status: z.string().optional(),
});

const updateStatusSchema = z.object({
  status: z.string().min(1),
});

export const invoices = Router();

invoices.use(requireAuth);

invoices.get("/", async (req, res) => {
  const items = await prisma.invoice.findMany({
    where: { organizationId: req.user.organizationId },
  });
  res.json(items);
});

invoices.post("/", async (req, res) => {
  const parsed = createInvoiceSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.message });
  }

  const invoice = await prisma.invoice.create({
    data: {
      organizationId: req.user.organizationId,
      amount: parsed.data.amount,
      vendor: parsed.data.vendor,
      status: parsed.data.status ?? "pending",
    },
  });

  res.status(201).json(invoice);
});

invoices.patch("/:id/status", async (req, res) => {
  const parsed = updateStatusSchema.safeParse(req.body);
  if (!parsed.success)
    return res.status(400).json({ error: parsed.error.message });

  const invoice = await prisma.invoice.findFirst({
    where: { id: req.params.id, organizationId: req.user.organizationId },
  });

  if (!invoice) return res.sendStatus(404);

  const updated = await prisma.invoice.update({
    where: { id: invoice.id },
    data: { status: parsed.data.status },
  });

  res.json(updated);
});
