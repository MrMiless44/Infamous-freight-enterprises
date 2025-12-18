# Getting Started with Speed Insights

This guide will help you get started with using Vercel Speed Insights on the Infamous Freight Enterprises project, showing you how to enable it, add the package to your project, deploy your app to Vercel, and view your data in the dashboard.

## Prerequisites

- A Vercel account. If you don't have one, you can [sign up for free](https://vercel.com/signup).
- A Vercel project. If you don't have one, you can [create a new project](https://vercel.com/new).
- The Vercel CLI installed. If you don't have it, you can install it using the following command:

```bash
# Using pnpm (recommended for this project)
pnpm add -g vercel

# Or using npm
npm install -g vercel

# Or using yarn
yarn global add vercel

# Or using bun
bun install -g vercel
```

## Setup Steps

### 1. Enable Speed Insights in Vercel Dashboard

On the [Vercel dashboard](/dashboard), select your Project followed by the **Speed Insights** tab. You can also select the button below to be taken there. Then, select **Enable** from the dialog.

> **💡 Note:** Enabling Speed Insights will add new routes (scoped at `/_vercel/speed-insights/*`) after your next deployment.

### 2. Add `@vercel/speed-insights` to Your Project

The `@vercel/speed-insights` package has already been added to the web package. If you need to install it manually:

```bash
# Using pnpm
pnpm add @vercel/speed-insights

# Using npm
npm install @vercel/speed-insights

# Using yarn
yarn add @vercel/speed-insights

# Using bun
bun add @vercel/speed-insights
```

### 3. Add the `SpeedInsights` Component to Your App

This project uses Next.js 14 with the Pages Router. The `SpeedInsights` component is already integrated in the main app file.

#### Current Implementation (Next.js 14)

The `SpeedInsights` component is already configured in `web/pages/_app.tsx`:

```tsx
import type { AppProps } from "next/app";
import { useEffect } from "react";
import { Analytics } from "@vercel/analytics/react";
import { SpeedInsights } from "@vercel/speed-insights/next";
import { datadogRum } from "@datadog/browser-rum";
import {
  reportWebVitals,
  trackCLS,
  trackLongTasks,
} from "../lib/webVitalsMonitoring";
import "../styles/global.css";

export default function App({ Component, pageProps }: AppProps) {
  // ... initialization code ...

  return (
    <div style={{ fontFamily: "system-ui, -apple-system, BlinkMacSystemFont" }}>
      <Component {...pageProps} />
      {process.env.NEXT_PUBLIC_ENV === "production" && (
        <>
          <Analytics />
          <SpeedInsights />
        </>
      )}
    </div>
  );
}
```

The `SpeedInsights` component is conditionally rendered only in production to avoid development overhead.

### 4. Web Vitals Monitoring

This project includes comprehensive Web Vitals monitoring through `web/lib/webVitalsMonitoring.js`:

- **Core Web Vitals Tracking**: CLS, FID, FCP, LCP, TTFB
- **Layout Shift Detection**: Tracks which elements cause Cumulative Layout Shift
- **Long Task Monitoring**: Monitors tasks that block the main thread
- **Datadog RUM Integration**: Sends metrics to Datadog for advanced monitoring

### 5. Deploy Your App to Vercel

You can deploy your app to Vercel's global [CDN](/docs/cdn) by running the following command from your terminal:

```bash
vercel deploy
```

Alternatively, you can [connect your project's git repository](/docs/git#deploying-a-git-repository), which will enable Vercel to deploy your latest pushes and merges to main.

Once your app is deployed, it's ready to begin tracking performance metrics.

> **💡 Note:** If everything is set up correctly, you should be able to find the `/_vercel/speed-insights/script.js` script inside the body tag of your page.

### 6. View Your Data in the Dashboard

Once your app is deployed, and users have visited your site, you can view the data in the dashboard.

To do so, go to your [dashboard](/dashboard), select your project, and click the **Speed Insights** tab.

After a few days of visitors, you'll be able to start exploring your metrics. For more information on how to use Speed Insights, see [Using Speed Insights](/docs/speed-insights/using-speed-insights).

## Performance Optimization Configuration

The project includes several optimizations for Core Web Vitals:

### Image Optimization (next.config.mjs)

```javascript
images: {
  domains: ['localhost', 'infamous-freight.fly.dev', 'infamous-freight-ai.fly.dev', 'vercel.app'],
  formats: ['image/avif', 'image/webp'],
  minimumCacheTTL: 60 * 60 * 24 * 365, // 1 year for optimized images
}
```

### Caching Headers (next.config.mjs)

- Static assets cached for 1 year with immutable flag
- API responses cached with appropriate TTLs
- Security headers configured for all routes

### Bundle Optimization

- Separate vendor bundles for React and SWR
- Code splitting for optimal performance
- Bundle analysis available with `ANALYZE=true`

## Next Steps

Now that you have Vercel Speed Insights set up, you can explore the following topics to learn more:

- [Learn how to use the `@vercel/speed-insights` package](/docs/speed-insights/package)
- [Learn about metrics](/docs/speed-insights/metrics)
- [Read about privacy and compliance](/docs/speed-insights/privacy-policy)
- [Explore pricing](/docs/speed-insights/limits-and-pricing)
- [Troubleshooting](/docs/speed-insights/troubleshooting)

## Monitoring and Compliance

Learn more about how Vercel supports [privacy and data compliance standards](/docs/speed-insights/privacy-policy) with Vercel Speed Insights.

This project is also integrated with:
- **Datadog RUM**: Advanced real user monitoring and session replay
- **Web Vitals**: Comprehensive performance metric tracking
- **Vercel Analytics**: Built-in analytics for your application
