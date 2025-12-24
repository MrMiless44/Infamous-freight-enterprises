import { useEffect, useState } from "react";
import { track } from "@vercel/analytics";
import { VoicePanel } from "../components/VoicePanel";
import { BillingPanel } from "../components/BillingPanel";

export default function Dashboard() {
  const [status, setStatus] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Track page view
    track("dashboard_visited", {
      timestamp: new Date().toISOString(),
    });

    const base = process.env.NEXT_PUBLIC_API_BASE_URL || "/api";
    fetch(`${base}/health`)
      .then((res) => res.json())
      .then((data) => {
        setStatus(data);
        track("api_health_check", {
          status: data.ok ? "healthy" : "unhealthy",
        });
      })
      .catch((error) => {
        setStatus({ ok: false });
        track("api_health_error", {
          error: error instanceof Error ? error.message : "Unknown error",
        });
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <main style={{ padding: "2rem" }}>
      <h1 style={{ fontSize: "2rem" }}>Control Tower</h1>

      {loading && <p>Loading status…</p>}
      {!loading && (
        <pre
          style={{
            background: "#0b0b12",
            padding: "1rem",
            borderRadius: "12px",
            border: "1px solid rgba(255,255,255,0.05)",
          }}
        >
          {JSON.stringify(status, null, 2)}
        </pre>
      )}

      <VoicePanel />
      <BillingPanel />
    </main>
  );
}
