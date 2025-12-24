import { useMemo, useState } from "react";

export function AvatarVoice() {
  const [status, setStatus] = useState<"idle" | "speaking" | "unsupported">(
    "idle",
  );

  const supported = useMemo(
    () => typeof window !== "undefined" && "speechSynthesis" in window,
    [],
  );

  const speak = (text: string) => {
    if (!supported) {
      setStatus("unsupported");
      return;
    }

    const utterance = new SpeechSynthesisUtterance(text);
    utterance.onstart = () => setStatus("speaking");
    utterance.onend = () => setStatus("idle");
    utterance.onerror = () => setStatus("idle");

    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(utterance);
  };

  return (
    <div
      style={{
        marginTop: "1.5rem",
        padding: "1rem",
        borderRadius: "12px",
        background: "#0b0b12",
        border: "1px solid rgba(255,255,255,0.08)",
      }}
    >
      <h3 style={{ marginTop: 0 }}>Avatar Voice</h3>
      <p style={{ marginTop: "0.25rem", color: "#b5b5c3", lineHeight: 1.5 }}>
        Command-driven voice for hands-free drivers. Tap to hear a live status
        reminder tailored for the current route.
      </p>

      <button
        onClick={() =>
          speak(
            "I'm monitoring your route. Maintain speed consistency to recover 7 minutes.",
          )
        }
        disabled={!supported || status === "speaking"}
        style={{
          marginTop: "0.8rem",
          padding: "0.7rem 1.2rem",
          borderRadius: "999px",
          background: supported
            ? "linear-gradient(135deg,#8ef4ff,#7b6dff)"
            : "#2a2a3c",
          color: supported ? "#050509" : "#7c7c94",
          fontWeight: 700,
          border: "none",
          cursor: supported ? "pointer" : "not-allowed",
          boxShadow: supported
            ? "0 10px 30px rgba(126,109,255,0.35)"
            : "none",
        }}
      >
        {status === "speaking" ? "Speaking…" : "🎤 Speak"}
      </button>

      <p
        style={{
          marginTop: "0.5rem",
          fontSize: "0.9rem",
          color: supported ? "#e9e9f1" : "#ff7b7b",
        }}
      >
        {supported
          ? status === "speaking"
            ? "Live coaching playing…"
            : "Ready for driver-safe prompts."
          : "Browser speech synthesis is not available here."}
      </p>

      <div
        style={{
          marginTop: "1rem",
          padding: "0.8rem",
          borderRadius: "10px",
          background: "#11111a",
          border: "1px dashed rgba(255,255,255,0.08)",
        }}
      >
        <p style={{ margin: "0 0 0.35rem 0", color: "#c3c3d6" }}>
          Voice command examples:
        </p>
        <ul style={{ margin: 0, paddingLeft: "1.2rem", color: "#f1f1f6" }}>
          <li>“What’s my next stop?”</li>
          <li>“Why am I behind schedule?”</li>
          <li>“Coach me”</li>
          <li>“Any safety issues?”</li>
          <li>“Dispatch update”</li>
        </ul>
      </div>
    </div>
  );
}
