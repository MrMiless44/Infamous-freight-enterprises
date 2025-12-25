import { Router } from "express";
import { prisma } from "../db/prisma";
import { requireAuth } from "../middleware/auth";

export const route = Router();

route.use(requireAuth);

route.post("/start", async (req, res) => {
  const session = await prisma.routeSession.create({
    data: { userId: req.user.id, organizationId: req.user.organizationId },
  });
  res.json(session);
});

route.post("/:id/event", async (req, res) => {
  const { id } = req.params;
  const { type, meta } = req.body as { type?: string; meta?: string };
  if (!type || !meta)
    return res.status(400).json({ error: "type and meta required" });

  const session = await prisma.routeSession.findFirst({
    where: { id, organizationId: req.user.organizationId },
  });

  if (!session) return res.sendStatus(404);

  const event = await prisma.routeEvent.create({
    data: { sessionId: session.id, type, meta },
  });
  res.json(event);
});

route.post("/:id/end", async (req, res) => {
  const { id } = req.params;
  const session = await prisma.routeSession.findFirst({
    where: { id, organizationId: req.user.organizationId },
  });

  if (!session) return res.sendStatus(404);

  const ended = await prisma.routeSession.update({
    where: { id: session.id },
    data: { endedAt: new Date() },
  });
  res.json(ended);
});
