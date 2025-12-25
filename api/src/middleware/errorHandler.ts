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

  const status = err?.status ?? 500;
  const message = err?.message ?? "Server Error";

  return res.status(status).json({ error: message });
}

export default errorHandler;

// Support CommonJS require in legacy tests
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const module: any;
if (typeof module !== "undefined" && module?.exports) {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  module.exports = errorHandler;
}
