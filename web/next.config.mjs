import bundleAnalyzer from "@next/bundle-analyzer";

const withBundleAnalyzer = bundleAnalyzer({
  enabled: process.env.ANALYZE === "true",
});

const nextConfig = {
  reactStrictMode: true,
  output: "standalone", // Enable standalone output for Docker optimization
  env: {
    NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL,
    NEXT_PUBLIC_APP_NAME: process.env.NEXT_PUBLIC_APP_NAME,
    NEXT_PUBLIC_ENV: process.env.NEXT_PUBLIC_ENV,
  },
  // Image optimization for Core Web Vitals
  images: {
    domains: ['localhost', 'infamous-freight.fly.dev', 'infamous-freight-ai.fly.dev', 'vercel.app'],
    formats: ['image/avif', 'image/webp'],
    minimumCacheTTL: 60 * 60 * 24 * 365, // 1 year for optimized images
  },
  // Rewrites: forward API calls to Fly after filesystem routes
  // Using afterFiles ensures Next API routes like /api/proxy/* remain intact
  rewrites: async () => ({
    afterFiles: [
      {
        source: '/api/:path*',
        destination: 'https://infamous-freight-api.fly.dev/api/:path*',
      },
    ],
  }),
  // Response headers for caching and security
  headers: async () => [
    {
      source: '/images/(.*)',
      headers: [
        {
          key: 'Cache-Control',
          value: 'public, max-age=31536000, immutable'
        }
      ]
    },
    {
      source: '/_next/static/(.*)',
      headers: [
        {
          key: 'Cache-Control',
          value: 'public, max-age=31536000, immutable'
        }
      ]
    },
    {
      source: '/api/(.*)',
      headers: [
        {
          key: 'Cache-Control',
          value: 'public, max-age=300, s-maxage=600'
        }
      ]
    }
  ],
  // Optimize for production
  poweredByHeader: false,
  compress: true,
  // Enable SWC minification
  swcMinify: true,
};

export default withBundleAnalyzer(nextConfig);
