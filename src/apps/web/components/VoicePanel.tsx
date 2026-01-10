import React, { useState } from "react";
import { useApi } from "../hooks/useApi";
import styles from "../styles/panels.module.css";

export function VoicePanel() {
  const api = useApi();
  const [text, setText] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);

  async function send() {
    if (!text.trim()) return;
    setLoading(true);
    try {
      const response = await api.post("/voice/command", { text });
      setResult(response);
    } catch (err) {
      setResult({ error: err instanceof Error ? err.message : String(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className={styles.panelHeader}>
        <div>
          <p className="hero-kicker" style={{ marginBottom: "0.15rem" }}>
            Voice / command
          </p>
          <h3 style={{ margin: 0 }}>Driver-safe prompts</h3>
        </div>
        <span className="pill">Live AI</span>
      </div>
      <p className="subtle" style={{ marginTop: "0.35rem" }}>
        Send concise commands; results return JSON you can act on immediately.
      </p>

      <div className={styles.panelBody}>
        <textarea
          className={styles.textarea}
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="Example: Reroute load 482 to avoid a 25 minute delay"
          rows={4}
        />

        <div className={styles.actionRow}>
          <button
            className="primary-btn"
            onClick={send}
            disabled={loading}
            style={loading ? { opacity: 0.8, cursor: "wait" } : undefined}
          >
            {loading ? "Sending…" : "Send to AI"}
          </button>
          <span className={styles.smallSubtle}>
            Tip: ask for “coach me” or “dispatch update”.
          </span>
        </div>

        {result && (
          <pre className={styles.result}>{JSON.stringify(result, null, 2)}</pre>
        )}
      </div>
    </div>
  );
}
