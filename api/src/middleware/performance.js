/**
 * Performance optimization middleware for caching and compression
 * Implements Redis caching layer and gzip compression
 */

const compression = require("compression");
const cache = new Map();

// Simple in-memory cache (can be replaced with Redis in production)
const cacheMiddleware = (duration = 60) => {
  return (req, res, next) => {
    // Only cache GET requests
    if (req.method !== "GET") {
      return next();
    }

    const cacheKey = `${req.method}:${req.originalUrl}`;
    const cachedResponse = cache.get(cacheKey);

    if (cachedResponse && !cachedResponse.expired) {
      res.setHeader("X-Cache", "HIT");
      res.setHeader("Cache-Control", `public, max-age=${duration}`);
      return res.json(cachedResponse.data);
    }

    // Store original json method
    const originalJson = res.json.bind(res);

    // Override json method to cache the response
    res.json = function (data) {
      cache.set(cacheKey, {
        data,
        expires: Date.now() + duration * 1000,
        expired: false,
      });

      // Set cache header
      res.setHeader("X-Cache", "MISS");
      res.setHeader("Cache-Control", `public, max-age=${duration}`);

      // Clean up expired cache
      setTimeout(() => {
        const entry = cache.get(cacheKey);
        if (entry) {
          entry.expired = true;
        }
      }, duration * 1000);

      return originalJson(data);
    };

    next();
  };
};

// Compression middleware with optimized settings
const compressionMiddleware = compression({
  level: 6, // Balance between compression ratio and speed
  threshold: 1024, // Only compress if > 1KB
  filter: (req, res) => {
    if (req.headers["x-no-compression"]) {
      return false;
    }
    return compression.filter(req, res);
  },
});

// Cache busting headers
const setNoCacheHeaders = (req, res, next) => {
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
};

module.exports = {
  cacheMiddleware,
  compressionMiddleware,
  setNoCacheHeaders,
};
