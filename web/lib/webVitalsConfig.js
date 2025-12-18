/**
 * Web Performance Optimization Configuration
 * Implements Next.js best practices for Core Web Vitals
 */

module.exports = {
  // Image Optimization
  images: {
    domains: ["localhost", "infamous-freight.fly.dev", "vercel.app"],
    formats: ["image/avif", "image/webp"],
    minimumCacheTTL: 60 * 60 * 24 * 365, // 1 year for optimized images
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
  },

  // Response Headers for Caching
  headers: async () => [
    {
      source: "/images/(.*)",
      headers: [
        {
          key: "Cache-Control",
          value: "public, max-age=31536000, immutable",
        },
      ],
    },
    {
      source: "/_next/static/(.*)",
      headers: [
        {
          key: "Cache-Control",
          value: "public, max-age=31536000, immutable",
        },
      ],
    },
    {
      source: "/api/(.*)",
      headers: [
        {
          key: "Cache-Control",
          value: "public, max-age=300, s-maxage=600",
        },
      ],
    },
    {
      source: "/(.*)",
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
        {
          key: "Referrer-Policy",
          value: "strict-origin-when-cross-origin",
        },
      ],
    },
  ],

  // Redirects for URL optimization
  redirects: async () => [
    // Add any necessary redirects here
  ],

  // Rewrites for API routing
  rewrites: async () => ({
    beforeFiles: [
      // API proxy configuration if needed
    ],
  }),

  // Bundle Analysis
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.optimization.splitChunks.cacheGroups = {
        ...config.optimization.splitChunks.cacheGroups,
        // Separate vendor bundles
        reactVendor: {
          test: /[\\/]node_modules[\\/](react|react-dom)[\\/]/,
          name: "vendor-react",
          priority: 10,
        },
        // SWR data fetching library
        swrVendor: {
          test: /[\\/]node_modules[\\/]swr[\\/]/,
          name: "vendor-swr",
          priority: 10,
        },
      };
    }
    return config;
  },
};
