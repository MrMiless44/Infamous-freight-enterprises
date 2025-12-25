import { NextFunction, Request, Response } from "express";

export function errorHandler(
  err: Error & { status?: number },
  _req: Request,
  res: Response,
  next: NextFunction,
) {
  if (res.headersSent) {
    return next(err);
  }

  const status = err.status ?? 500;
  const message = err.message ?? "Server Error";

  return res.status(status).json({ error: message });
}

export default errorHandler;

// Support CommonJS require in legacy tests
declare const module:
  | {
      exports?: unknown;
    }
  | undefined;
if (typeof module !== "undefined" && module?.exports) {
  module.exports = errorHandler;
}
