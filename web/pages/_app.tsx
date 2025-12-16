import type { AppProps } from "next/app";
import { Analytics } from "@vercel/analytics/react";
import { datadogRum } from "@datadog/browser-rum";
import "../styles/global.css";

export default function App({ Component, pageProps }: AppProps) {
  if (typeof window !== "undefined" && process.env.NEXT_PUBLIC_ENV === "production") {
    try {
      datadogRum.init({
        applicationId: process.env.NEXT_PUBLIC_DD_APP_ID || "",
        clientToken: process.env.NEXT_PUBLIC_DD_CLIENT_TOKEN || "",
        site: process.env.NEXT_PUBLIC_DD_SITE || "datadoghq.com",
        service: "infamous-freight-web",
        env: "production",
        sampleRate: 100,
        trackInteractions: true,
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
      {process.env.NEXT_PUBLIC_ENV === "production" && <Analytics />}
    </div>
  );
}
