import crypto from "crypto";
import { NextFunction, Request, Response } from "express";
import { prisma } from "../db/prisma";
import { AuthUser } from "./auth";

function hashKey(key: string) {
  return crypto.createHash("sha256").update(key).digest("hex");
}

function extractApiKey(header?: string, explicitKey?: string) {
  if (explicitKey) return explicitKey.trim();
  if (!header) return null;
  if (header.startsWith("Bearer ")) {
    return header.slice("Bearer ".length).trim();
  }
  return null;
}

export function requireApiKey() {
  return async (req: Request, res: Response, next: NextFunction) => {
    const apiKeyValue = extractApiKey(
      req.headers.authorization,
      req.headers["x-api-key"] as string | undefined,
    );

    if (!apiKeyValue) {
      return res.status(401).json({ error: "API key required" });
    }

    const apiKey = await prisma.apiKey.findUnique({
      where: { keyHash: hashKey(apiKeyValue) },
    });

    if (!apiKey) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    await prisma.apiKey.update({
      where: { id: apiKey.id },
      data: { lastUsedAt: new Date() },
    });

    const user: AuthUser = {
      id: apiKey.id,
      organizationId: apiKey.organizationId,
      role: apiKey.role,
    };

    req.user = user;
    return next();
  };
}
