import React, { useState } from "react";
import { track } from "@vercel/analytics";
import { useApi } from "../hooks/useApi";

export function VoicePanel() {
  const api = useApi();
  const [text, setText] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);

  async function send() {
    if (!text.trim()) return;
    setLoading(true);
    
    track("voice_command_initiated", {
      commandLength: text.length,
      timestamp: new Date().toISOString(),
    });
    
    try {
      const response = await api.post("/voice/command", { text });
      setResult(response);
      
      track("voice_command_success", {
        commandLength: text.length,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setResult({ error: errorMessage });
      
      track("voice_command_error", {
        commandLength: text.length,
        error: errorMessage,
        timestamp: new Date().toISOString(),
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      style={{
        marginTop: "2rem",
        padding: "1rem",
        borderRadius: "12px",
        background: "#0b0b12",
      }}
    >
      <h3 style={{ marginTop: 0 }}>Voice / Command Input</h3>

      <textarea
        value={text}
        onChange={(event) => setText(event.target.value)}
        rows={3}
        style={{
          width: "100%",
          borderRadius: "8px",
          padding: "0.6rem",
          background: "#111",
          color: "#fff",
          border: "1px solid #222",
        }}
      />

      <button
        onClick={send}
        disabled={loading}
        style={{
          marginTop: "0.8rem",
          padding: "0.6rem 1.2rem",
          borderRadius: "999px",
          background: "linear-gradient(135deg,#ffcc33,#ff3366)",
          fontWeight: 600,
          color: "#050509",
          border: "none",
          cursor: "pointer",
        }}
      >
        {loading ? "Sending…" : "Send to AI"}
      </button>

      {result && (
        <pre
          style={{
            marginTop: "1rem",
            padding: "1rem",
            background: "#111",
            borderRadius: "8px",
            fontSize: "0.85rem",
          }}
        >
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  );
}
