import { NextFunction, Request, Response } from "express";

export function auditTrail(req: Request, _res: Response, next: NextFunction) {
  const userInfo = req.user
    ? `${req.user.id}@${req.user.organizationId}`
    : "anonymous";
  const message = `[AUDIT] ${req.method} ${req.originalUrl} by ${userInfo}`;
  console.warn(message);
  next();
}
