import { useEffect, useMemo, useState } from "react";
import { track } from "@vercel/analytics";
import AppLayout from "../components/AppLayout";
import { AvatarVoice } from "../components/AvatarVoice";
import { VoicePanel } from "../components/VoicePanel";
import { BillingPanel } from "../components/BillingPanel";
import { resolveApiBase } from "../hooks/useApi";
import styles from "../styles/dashboard.module.css";

export default function Dashboard() {
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    track("dashboard_visited", {
      timestamp: new Date().toISOString(),
    });

    const base = resolveApiBase();
    fetch(`${base}/health`)
      .then((res) => res.json())
      .then((data) => {
        setStatus(data);
        track("api_health_check", {
          status: (data as any)?.ok ? "healthy" : "unhealthy",
        });
      })
      .catch((error) => {
        setStatus({
          ok: false,
          error: error instanceof Error ? error.message : "Unknown",
        });
        track("api_health_error", {
          error: error instanceof Error ? error.message : "Unknown error",
        });
      })
      .finally(() => setLoading(false));
  }, []);

  const isHealthy = useMemo(
    () => Boolean((status as any)?.ok ?? (status as any)?.status === "ok"),
    [status],
  );

  return (
    <AppLayout
      kicker="Live control"
      title="Control tower"
      subtitle="Monitor health, send voice commands, and handle billing without jumping tabs."
    >
      <section className={styles.grid}>
        <div className={styles.statusCard}>
          <div className={styles.statusHeader}>
            <div>
              <p className="hero-kicker">System health</p>
              <h2 className="section-title" style={{ margin: 0 }}>
                {loading
                  ? "Checking…"
                  : isHealthy
                    ? "All systems go"
                    : "Needs attention"}
              </h2>
            </div>
            <span className={styles.badge}>
              <span
                style={{
                  display: "inline-block",
                  width: "10px",
                  height: "10px",
                  borderRadius: "999px",
                  background: loading
                    ? "#ffc94a"
                    : isHealthy
                      ? "#2ee6a8"
                      : "#ff7b7b",
                }}
              />
              {loading ? "Updating" : isHealthy ? "Healthy" : "Investigate"}
            </span>
          </div>

          <div className={styles.health}>
            {loading && <p className="subtle">Pinging API health…</p>}
            {!loading && (
              <pre className={styles.codeBlock}>
                {JSON.stringify(status, null, 2)}
              </pre>
            )}
          </div>
        </div>

        <div className="card">
          <h2 className="section-title">Quick actions</h2>
          <p className="subtle" style={{ marginTop: "0.25rem" }}>
            Run the core flows you use most.
          </p>
          <div className="timeline" style={{ marginTop: "0.75rem" }}>
            <span>Send a command</span>
            <span>Hear driver-safe status</span>
            <span>Collect a payment</span>
          </div>
        </div>
      </section>

      <section className={styles.section}>
        <h2>Live controls</h2>
        <p>Voice, coaching, and billing in one place.</p>
        <div className={styles.panels}>
          <div className="panel">
            <VoicePanel />
          </div>
          <div className="panel">
            <AvatarVoice />
          </div>
          <div className="panel">
            <BillingPanel />
          </div>
        </div>
      </section>
    </AppLayout>
  );
}
