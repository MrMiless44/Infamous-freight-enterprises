/**
 * CSRF Protection Middleware
 * Prevents Cross-Site Request Forgery attacks
 */

import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { logger } from "./logger";

export interface CsrfOptions {
  cookieName?: string;
  headerName?: string;
  excludeMethods?: string[];
  tokenLength?: number;
}

/**
 * CSRF token storage (in production, use secure session storage)
 */
const tokenStore = new Map<string, string>();

export class CsrfMiddleware {
  private cookieName: string;
  private headerName: string;
  private excludeMethods: string[];
  private tokenLength: number;

  constructor(options: CsrfOptions = {}) {
    this.cookieName = options.cookieName || "X-CSRF-TOKEN";
    this.headerName = options.headerName || "x-csrf-token";
    this.excludeMethods = options.excludeMethods || ["GET", "HEAD", "OPTIONS"];
    this.tokenLength = options.tokenLength || 32;
  }

  /**
   * Generate CSRF token
   */
  private generateToken(): string {
    return crypto.randomBytes(this.tokenLength).toString("hex");
  }

  /**
   * Middleware: Generate/verify CSRF tokens
   */
  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      // Skip CSRF check for safe methods
      if (this.excludeMethods.includes(req.method.toUpperCase())) {
        return next();
      }

      // Get session ID (from cookie or header)
      const sessionId = req.sessionID || crypto.randomUUID();

      // GET request: Generate and send token
      if (req.method === "GET") {
        const token = this.generateToken();
        tokenStore.set(sessionId, token);

        // Send token in cookie and header
        res.cookie(this.cookieName, token, {
          httpOnly: false, // Must be accessible to JavaScript
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 60 * 60 * 1000, // 1 hour
        });

        res.setHeader(this.headerName, token);
        return next();
      }

      // POST/PUT/DELETE request: Verify token
      const tokenFromHeader = req.get(this.headerName);
      const tokenFromCookie = req.cookies?.[this.cookieName];
      const storedToken = tokenStore.get(sessionId);

      if (!tokenFromHeader && !tokenFromCookie) {
        logger.warn("CSRF token missing", {
          path: req.path,
          method: req.method,
          sessionId,
        });
        return res.status(403).json({
          error: "CSRF token required",
          code: "CSRF_TOKEN_MISSING",
        });
      }

      const token = tokenFromHeader || tokenFromCookie;

      if (token !== storedToken) {
        logger.warn("CSRF token invalid", {
          path: req.path,
          method: req.method,
          sessionId,
          provided: token?.substring(0, 5) + "...",
          stored: storedToken?.substring(0, 5) + "...",
        });
        return res.status(403).json({
          error: "Invalid CSRF token",
          code: "CSRF_TOKEN_INVALID",
        });
      }

      // Clean up used token
      tokenStore.delete(sessionId);

      next();
    };
  }

  /**
   * Generate new token for client
   */
  generateClientToken(sessionId: string): string {
    const token = this.generateToken();
    tokenStore.set(sessionId, token);
    return token;
  }

  /**
   * Verify token manually (for API endpoints)
   */
  verifyToken(sessionId: string, token: string): boolean {
    const storedToken = tokenStore.get(sessionId);
    const isValid = token === storedToken;

    if (isValid) {
      tokenStore.delete(sessionId);
    }

    return isValid;
  }
}

// Export singleton instance
export const csrf = new CsrfMiddleware();
export default csrf;
