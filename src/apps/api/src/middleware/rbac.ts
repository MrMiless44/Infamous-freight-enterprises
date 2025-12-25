import { NextFunction, Request, Response } from "express";

export function requireRole(roles: string | string[]) {
  const allowed = Array.isArray(roles) ? roles : [roles];

  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) return res.sendStatus(401);
    if (!allowed.includes(req.user.role)) {
      return res.sendStatus(403);
    }
    return next();
  };
}
