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

/**
 * Main App Component
 *
 * This component integrates multiple monitoring and analytics solutions:
 * - Vercel Speed Insights: Tracks real-world performance metrics (Web Vitals)
 * - Vercel Analytics: Provides basic analytics data
 * - Datadog RUM: Advanced real user monitoring with session replay
 * - Web Vitals: Tracks Core Web Vitals (CLS, FID, FCP, LCP, TTFB)
 *
 * All monitoring is enabled only in production to avoid development overhead.
 *
 * See: docs/SPEED_INSIGHTS_SETUP.md for detailed information about Speed Insights setup
 */

export default function App({ Component, pageProps }: AppProps) {
  useEffect(() => {
    // Track Core Web Vitals
    if (typeof window !== "undefined") {
      import("web-vitals").then(
        ({ onCLS, onFID, onFCP, onLCP, onTTFB }) => {
          onCLS(reportWebVitals);
          onFCP(reportWebVitals);
          onLCP(reportWebVitals);
          onTTFB(reportWebVitals);
          // Note: FID is deprecated in favor of INP (Interaction to Next Paint)
          // but we keep it for older browsers
          if (onFID) {
            onFID(reportWebVitals);
          }
        },
      );

      // Track layout shifts and long tasks
      trackCLS();
      trackLongTasks();
    }
  }, []);

  if (
    typeof window !== "undefined" &&
    process.env.NEXT_PUBLIC_ENV === "production"
  ) {
    try {
      datadogRum.init({
        applicationId: process.env.NEXT_PUBLIC_DD_APP_ID || "",
        clientToken: process.env.NEXT_PUBLIC_DD_CLIENT_TOKEN || "",
        site: process.env.NEXT_PUBLIC_DD_SITE || "datadoghq.com",
        service: "infamous-freight-web",
        env: "production",
        sessionSampleRate: 100,
        trackUserInteractions: true,
        defaultPrivacyLevel: "mask-user-input",
      });
      datadogRum.startSessionReplayRecording();
    } catch (_e) {
      // Fail open if RUM package not installed
    }
  }
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
