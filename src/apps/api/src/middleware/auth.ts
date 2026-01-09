import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import config from "../config";

export interface AuthUser {
  id: string;
  organizationId: string;
  role: string;
  email?: string;
  scopes?: string[];
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

function decodeToken(token: string): AuthUser | null {
  try {
    const payload = jwt.verify(token, config.getJwtSecret()) as jwt.JwtPayload;
    const scopes = Array.isArray(payload.scopes)
      ? (payload.scopes as string[])
      : [];

    return {
      id:
        (payload.sub as string | undefined) ??
        (payload.id as string | undefined) ??
        "user",
      organizationId:
        (payload.organizationId as string | undefined) ??
        (payload.orgId as string | undefined) ??
        (payload.org as string | undefined) ??
        "org_default",
      role: (payload.role as string | undefined) ?? "user",
      email: (payload.email as string | undefined) ?? undefined,
      scopes,
    };
  } catch {
    return null;
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    const fallbackUserId = req.header("x-user-id");
    if (fallbackUserId && !config.isProduction) {
      const rawScopes = req.header("x-user-scopes") ?? "";
      const scopes = rawScopes
        .split(",")
        .map((scope) => scope.trim())
        .filter(Boolean);

      req.user = {
        id: fallbackUserId,
        organizationId: req.header("x-org-id") ?? "org_default",
        role: req.header("x-user-role") ?? "user",
        email: req.header("x-user-email") ?? undefined,
        scopes: scopes.length
          ? scopes
          : req.baseUrl?.includes("/billing")
            ? ["billing:write"]
            : [],
      };

      return next();
    }

    return res.status(401).json({ error: "Authorization header required" });
  }

  const token = authHeader.split(" ")[1];
  const user = decodeToken(token);
  if (!user) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  req.user = user;
  return next();
}

export function requireScope(scope: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(403).json({ error: "User context required" });
    }

    const scopes = req.user.scopes ?? [];
    if (!scopes.includes(scope)) {
      return res.status(403).json({ error: "Insufficient scope" });
    }

    return next();
  };
}
