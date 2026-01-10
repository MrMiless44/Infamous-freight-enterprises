/**
 * Authentication Service with JWT Token Rotation
 * Implements 15-minute access tokens and 7-day refresh tokens
 */

import jwt from "jsonwebtoken";
import { createClient } from "redis";
import config from "../config/config";
import { logger } from "../middleware/logger";

const redis = createClient({
  url: process.env.REDIS_URL || "redis://localhost:6379",
});

redis.connect().catch((err) => {
  logger.error("Redis connection error for auth service", {
    error: err.message,
  });
});

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface RefreshResult {
  accessToken: string;
}

export class AuthService {
  private readonly ACCESS_TOKEN_EXPIRY = "15m";
  private readonly REFRESH_TOKEN_EXPIRY = "7d";
  private readonly REFRESH_TOKEN_SECRET: string;

  constructor() {
    this.REFRESH_TOKEN_SECRET =
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + "-refresh";
  }

  /**
   * Generate access + refresh token pair
   */
  generateTokenPair(
    userId: string,
    scopes: string[],
    email?: string,
  ): TokenPair {
    const accessToken = jwt.sign(
      {
        sub: userId,
        scopes,
        email,
        type: "access",
      },
      config.getJwtSecret(),
      { expiresIn: this.ACCESS_TOKEN_EXPIRY },
    );

    const refreshToken = jwt.sign(
      {
        sub: userId,
        type: "refresh",
      },
      this.REFRESH_TOKEN_SECRET,
      { expiresIn: this.REFRESH_TOKEN_EXPIRY },
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: 15 * 60, // 15 minutes in seconds
    };
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken(
    refreshToken: string,
    getUserScopes: (userId: string) => Promise<string[]>,
  ): Promise<RefreshResult> {
    try {
      // Verify refresh token
      const decoded = jwt.verify(
        refreshToken,
        this.REFRESH_TOKEN_SECRET,
      ) as any;

      if (decoded.type !== "refresh") {
        throw new Error("Invalid token type");
      }

      // Check if refresh token is blacklisted
      const isBlacklisted = await this.isTokenBlacklisted(refreshToken);
      if (isBlacklisted) {
        throw new Error("Token has been revoked");
      }

      // Fetch current user scopes from database
      const scopes = await getUserScopes(decoded.sub);

      // Generate new access token
      const accessToken = jwt.sign(
        {
          sub: decoded.sub,
          scopes,
          type: "access",
        },
        config.getJwtSecret(),
        { expiresIn: this.ACCESS_TOKEN_EXPIRY },
      );

      return { accessToken };
    } catch (err) {
      logger.error("Token refresh failed", { error: (err as Error).message });
      throw new Error("Invalid or expired refresh token");
    }
  }

  /**
   * Revoke refresh token (logout)
   */
  async revokeRefreshToken(refreshToken: string): Promise<void> {
    try {
      const decoded = jwt.verify(
        refreshToken,
        this.REFRESH_TOKEN_SECRET,
      ) as any;
      const exp =
        decoded.exp || Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;
      const ttl = exp - Math.floor(Date.now() / 1000);

      if (ttl > 0) {
        // Add to blacklist with TTL matching token expiry
        await redis.setEx(`blacklist:${refreshToken}`, ttl, "1");
        logger.info("Refresh token revoked", { userId: decoded.sub });
      }
    } catch (err) {
      logger.error("Token revocation failed", {
        error: (err as Error).message,
      });
    }
  }

  /**
   * Check if token is blacklisted
   */
  private async isTokenBlacklisted(token: string): Promise<boolean> {
    try {
      const result = await redis.get(`blacklist:${token}`);
      return result !== null;
    } catch (err) {
      logger.error("Blacklist check failed", { error: (err as Error).message });
      return false; // Fail open to avoid blocking legitimate requests
    }
  }

  /**
   * Verify access token
   */
  verifyAccessToken(token: string): any {
    return jwt.verify(token, config.getJwtSecret());
  }

  /**
   * Decode token without verification (for debugging)
   */
  decodeToken(token: string): any {
    return jwt.decode(token);
  }
}

export const authService = new AuthService();
export default authService;
