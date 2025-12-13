import type { AppProps } from "next/app";
import { Analytics } from "@vercel/analytics/react";
import "../styles/global.css";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <div style={{ fontFamily: "system-ui, -apple-system, BlinkMacSystemFont" }}>
      <Component {...pageProps} />
      <Analytics />
    </div>
  );
}
