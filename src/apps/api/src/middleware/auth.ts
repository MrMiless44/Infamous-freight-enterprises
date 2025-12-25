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
    return res.sendStatus(401);
  }

  const token = authHeader.split(" ")[1];
  const user = decodeToken(token);
  if (!user) {
    return res.sendStatus(401);
  }

  req.user = user;
  return next();
}

export function requireScope(scope: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith("Bearer ")) {
        return res.sendStatus(401);
      }

      const token = authHeader.split(" ")[1];
      const user = decodeToken(token);
      if (!user) {
        return res.sendStatus(401);
      }

      req.user = user;
    }

    const scopes = req.user.scopes ?? [];
    if (!scopes.includes(scope)) {
      return res.sendStatus(403);
    }

    return next();
  };
}
