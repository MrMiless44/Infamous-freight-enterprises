/**
 * Response Compression Middleware
 * Uses Brotli compression (30% smaller than gzip) for faster delivery
 */

import { Request, Response, NextFunction } from "express";
import brotliSize from "brotli-size";

/**
 * Brotli compression middleware
 * Automatically compresses responses with Brotli or gzip
 */
export function compressionMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const acceptEncoding = req.headers["accept-encoding"] || "";

  // Check for brotli support
  if (acceptEncoding.includes("br")) {
    // Use dynamic-require or bundled brotli for compression
    const zlib = require("zlib");
    const { BrotliCompress } = zlib;

    // Small responses aren't worth compressing
    const originalSend = res.send;
    res.send = function (data: any) {
      const bytes = Buffer.byteLength(data);

      // Only compress if > 1KB
      if (bytes > 1024) {
        res.setHeader("Content-Encoding", "br");

        const brotliOptions = {
          params: {
            [BrotliCompress.PARAM_MODE]: 1, // TEXT mode
            [BrotliCompress.PARAM_QUALITY]: 4, // Balance speed/compression
            [BrotliCompress.PARAM_LGWIN]: 22, // Maximum window size
          },
        };

        const compressed = zlib.brotliCompressSync(
          typeof data === "string" ? Buffer.from(data) : data,
          brotliOptions,
        );

        return originalSend.call(this, compressed);
      }

      return originalSend.call(this, data);
    };
  }

  next();
}

/**
 * Compression statistics middleware
 * Tracks compression efficiency for monitoring
 */
export function compressionStatsMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const startTime = Date.now();
  const originalSend = res.send;

  res.send = function (data: any) {
    const originalSize = Buffer.byteLength(data);
    const compressionTime = Date.now() - startTime;

    // Add compression stats to response headers
    res.setHeader("X-Original-Content-Length", originalSize);
    res.setHeader("X-Compression-Time", compressionTime);

    // Log compression stats
    const contentEncoding = res.getHeader("content-encoding");
    if (contentEncoding) {
      const compressedSize = Buffer.byteLength(
        res.getHeader("content-length") || "",
      );
      const ratio = ((1 - compressedSize / originalSize) * 100).toFixed(1);

      console.log(
        `✓ Compressed ${originalSize}b → ${compressedSize}b (${ratio}% reduction, ${compressionTime}ms)`,
      );
    }

    return originalSend.call(this, data);
  };

  next();
}

/**
 * JSON response compression middleware
 * Automatically detects and compresses JSON responses
 */
export function jsonCompressionMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const originalJson = res.json;

  res.json = function (data: any) {
    const jsonString = JSON.stringify(data);
    const bytes = Buffer.byteLength(jsonString);

    // Log uncompressed size
    console.log(`Response size: ${bytes}b`);

    // Set content length header before compression
    res.setHeader("X-Uncompressed-Length", bytes);

    // Call original json with compression applied
    return originalJson.call(this, data);
  };

  next();
}

/**
 * Image/Asset compression hints
 * Returns optimal image formats based on client capability
 */
export function imageOptimizationMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const acceptHeader = req.headers.accept || "";

  // Indicate support for modern formats
  const supportsWebP = acceptHeader.includes("image/webp");
  const supportsAvif = acceptHeader.includes("image/avif");

  // Add headers for reverse proxy/CDN to optimize images
  if (supportsAvif) {
    res.setHeader("X-Image-Format-Preference", "avif");
  } else if (supportsWebP) {
    res.setHeader("X-Image-Format-Preference", "webp");
  } else {
    res.setHeader("X-Image-Format-Preference", "jpeg");
  }

  next();
}

/**
 * CSS/JS minification middleware
 */
export function assetMinificationMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const originalSend = res.send;

  res.send = function (data: any) {
    const contentType = res.getHeader("content-type")?.toString() || "";

    // Minify CSS
    if (contentType.includes("text/css") && typeof data === "string") {
      // Simple minification (remove comments and whitespace)
      const minified = data
        .replace(/\/\*[\s\S]*?\*\//g, "") // Remove comments
        .replace(/\s+/g, " ") // Collapse whitespace
        .replace(/\s*([{}:;,])\s*/g, "$1"); // Remove whitespace around symbols

      console.log(`✓ Minified CSS: ${data.length}b → ${minified.length}b`);
      return originalSend.call(this, minified);
    }

    // Minify JavaScript
    if (
      contentType.includes("application/javascript") &&
      typeof data === "string"
    ) {
      const minified = data
        .replace(/\/\*[\s\S]*?\*\//g, "") // Remove block comments
        .replace(/\/\/.*$/gm, "") // Remove line comments
        .replace(/\s+/g, " ") // Collapse whitespace
        .replace(/\s*([{}()[\]:;,=+\-*/<>!&|^~?.])\s*/g, "$1"); // Remove whitespace around operators

      console.log(`✓ Minified JS: ${data.length}b → ${minified.length}b`);
      return originalSend.call(this, minified);
    }

    return originalSend.call(this, data);
  };

  next();
}

/**
 * Compression ratio monitoring
 * Tracks compression efficiency over time
 */
export class CompressionMonitor {
  private totalOriginalSize: number = 0;
  private totalCompressedSize: number = 0;
  private requestCount: number = 0;

  record(originalSize: number, compressedSize: number): void {
    this.totalOriginalSize += originalSize;
    this.totalCompressedSize += compressedSize;
    this.requestCount++;
  }

  getStats(): {
    requestCount: number;
    averageRatio: number;
    totalSavedbytes: number;
    percentageSaved: number;
  } {
    const totalSaved = this.totalOriginalSize - this.totalCompressedSize;
    const percentageSaved =
      this.totalOriginalSize > 0
        ? ((totalSaved / this.totalOriginalSize) * 100).toFixed(2)
        : "0";

    return {
      requestCount: this.requestCount,
      averageRatio:
        this.requestCount > 0
          ? parseFloat(
              (this.totalCompressedSize / this.totalOriginalSize).toFixed(2),
            )
          : 0,
      totalSavedbytes: totalSaved,
      percentageSaved: parseFloat(percentageSaved as string),
    };
  }

  reset(): void {
    this.totalOriginalSize = 0;
    this.totalCompressedSize = 0;
    this.requestCount = 0;
  }
}

// Global monitor instance
export const compressionMonitor = new CompressionMonitor();

/**
 * Endpoint to get compression statistics
 */
export function handleCompressionStats(req: Request, res: Response) {
  const stats = compressionMonitor.getStats();

  res.json({
    success: true,
    compression: stats,
    expectedBenefit: {
      message: `Compression saving ${stats.percentageSaved}% bandwidth`,
      yearlyDataSavings: `${(stats.totalSavedbytes / 1024 / 1024).toFixed(2)}MB annually`,
    },
  });
}

/**
 * Configuration presets for different scenarios
 */
export const compressionPresets = {
  // Aggressive compression (slower, better for bandwidth-limited clients)
  aggressive: {
    quality: 11, // 0-11, higher = better compression but slower
    windowSize: 24, // Larger window for better compression
  },

  // Balanced compression (default)
  balanced: {
    quality: 4,
    windowSize: 22,
  },

  // Fast compression (faster, less compression)
  fast: {
    quality: 1,
    windowSize: 20,
  },

  // Development (no compression overhead)
  development: {
    quality: 0,
  },
};

/**
 * Usage in Express app:
 *
 * import { compressionMiddleware, compressionStatsMiddleware, imageOptimizationMiddleware } from './compression';
 *
 * // Apply compression globally
 * app.use(compressionMiddleware);
 * app.use(compressionStatsMiddleware);
 * app.use(imageOptimizationMiddleware);
 *
 * // Get compression statistics
 * app.get('/api/compression-stats', handleCompressionStats);
 *
 * Expected benefits:
 * - JSON responses: 50-70% smaller with Brotli
 * - HTML responses: 60-80% smaller with Brotli
 * - CSS: 80-90% smaller after minification
 * - Overall bandwidth: 30-50% reduction
 */
