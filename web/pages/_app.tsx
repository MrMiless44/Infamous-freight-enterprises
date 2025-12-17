import type { AppProps } from "next/app";
import { Analytics } from "@vercel/analytics/react";
import { SpeedInsights } from "@vercel/speed-insights/next";
import "../styles/global.css";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <div style={{ fontFamily: "system-ui, -apple-system, BlinkMacSystemFont" }}>
      <Component {...pageProps} />
      {process.env.NEXT_PUBLIC_ENV === "production" && <Analytics />}
      <SpeedInsights />
    </div>
  );
}
