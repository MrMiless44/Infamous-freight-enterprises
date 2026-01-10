// @ts-nocheck
/**
 * Next.js Image Optimization Configuration
 * Reduces bundle size and improves page load performance
 */

import type { NextConfig } from "next";
import withImages from "next-images";

const nextConfig: NextConfig = {
  // Image optimization
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "**.cloudinary.com",
      },
      {
        protocol: "https",
        hostname: "api.infamous-freight.com",
      },
    ],
    // Image formats (WebP for modern browsers, JPEG fallback)
    formats: ["image/avif", "image/webp"],
    // Responsive image sizes
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
    // Cache optimized images
    minimumCacheTTL: 60 * 60 * 24 * 365, // 1 year
  },

  // Code splitting & compression
  compress: true,
  swcMinify: true,

  // React strict mode
  reactStrictMode: true,

  // Optimize dependencies
  webpack: (config, { isServer }) => {
    config.optimization.splitChunks.cacheGroups = {
      default: false,
      vendors: false,
      // Vendor code
      vendor: {
        filename: "chunks/vendor-[hash].js",
        test: /node_modules/,
        name: "vendor",
        priority: 10,
        reuseExistingChunk: true,
        enforce: true,
      },
      // Common chunks used in multiple pages
      common: {
        minChunks: 2,
        priority: 5,
        reuseExistingChunk: true,
        filename: "chunks/common-[hash].js",
      },
    };

    return config;
  },

  // Output optimization
  outputFileTracing: true,

  // Environment variables
  env: {
    NEXT_PUBLIC_ENV: process.env.NODE_ENV,
    NEXT_PUBLIC_API_BASE_URL: process.env.API_BASE_URL,
  },

  // Redirects for legacy routes
  async redirects() {
    return [
      {
        source: "/api/old-endpoint",
        destination: "/api/new-endpoint",
        permanent: true,
      },
    ];
  },

  // Rewrites to proxy API
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.API_BASE_URL}/api/:path*`,
      },
    ];
  },

  // Headers for caching & security
  async headers() {
    return [
      {
        source: "/assets/:path*",
        headers: [
          {
            key: "Cache-Control",
            value: "public, max-age=31536000, immutable",
          },
        ],
      },
      {
        source: "/:path*",
        headers: [
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            key: "X-XSS-Protection",
            value: "1; mode=block",
          },
        ],
      },
    ];
  },

  // Experimental features (Next.js 13+)
  experimental: {
    // Enable experimental app directory
    appDir: false,
    // Optimize package imports
    optimizePackageImports: [
      "@mui/material",
      "@mui/icons-material",
      "lodash",
      "lodash-es",
    ],
  },

  // Build optimization
  productionBrowserSourceMaps: false, // Don't expose source maps in production

  // Font optimization
  optimizeFonts: true,
};

export default nextConfig;
