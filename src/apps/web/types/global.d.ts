declare global {
  interface Window {
    datadog?: {
      rum?: {
        addAction?: (name: string, context?: Record<string, unknown>) => void;
      };
    };
  }
}

export {};

declare module "next-images" {
  import { NextConfig } from "next";
  const withImages: (
    config?: Record<string, unknown>,
  ) => (nextConfig: NextConfig) => NextConfig;
  export default withImages;
}
