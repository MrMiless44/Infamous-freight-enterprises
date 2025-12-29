import { Request, Response, NextFunction } from "express";
import { validationResult } from "express-validator";

export class AppError extends Error {
  public status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.name = "AppError";
    Error.captureStackTrace(this, this.constructor);
  }
}

export function validate(req: Request, res: Response, next: NextFunction) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: "error",
      errors: errors.array(),
    });
  }
  return next();
}

// Aliases for compatibility with problem statement
export const protect = requireAuth;
export const restrictTo = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new AppError("Unauthorized", 401);
    }
    if (!roles.includes(req.user.role)) {
      throw new AppError("Forbidden", 403);
    }
    return next();
  };
};

// Re-export requireAuth for use in the validate module
import { requireAuth } from "./auth";
export { requireAuth };
