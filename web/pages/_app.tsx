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
  useEffect(() => {
    // Track Core Web Vitals
    if (typeof window !== "undefined") {
      import("web-vitals").then(({ onCLS, onFID, onFCP, onLCP, onTTFB }) => {
        onCLS(reportWebVitals);
        onFID(reportWebVitals);
        onFCP(reportWebVitals);
        onLCP(reportWebVitals);
        onTTFB(reportWebVitals);
      });

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
