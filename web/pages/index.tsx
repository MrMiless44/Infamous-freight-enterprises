import Link from "next/link";
import { AvatarGrid } from "../components/AvatarGrid";

export default function Home() {
  const appName = process.env.NEXT_PUBLIC_APP_NAME || "Infamous Freight AI";

  return (
    <main
      style={{
        minHeight: "100vh",
        padding: "3rem",
        maxWidth: "960px",
        margin: "0 auto"
      }}
    >
      <header>
        <p style={{ letterSpacing: "0.2em", textTransform: "uppercase", opacity: 0.7 }}>
          {process.env.NEXT_PUBLIC_ENV || "Development"}
        </p>
        <h1 style={{ fontSize: "3rem", marginBottom: "0.5rem" }}>{appName}</h1>
        <p style={{ maxWidth: "540px", lineHeight: 1.6 }}>
          Command the Infamous Freight synthetic intelligence stack. Voice automation, billing
          orchestration, fleet telemetry, and AI copilots converge in a single control tower.
        </p>
        <div style={{ marginTop: "1.5rem", display: "flex", gap: "1rem" }}>
          <Link
            href="/dashboard"
            style={{
              padding: "0.8rem 1.8rem",
              borderRadius: "999px",
              background: "linear-gradient(135deg,#ffcc33,#ff3366)",
              color: "#050509",
              fontWeight: 600
            }}
          >
            Launch Dashboard
          </Link>
          <Link
            href="/billing"
            style={{
              padding: "0.8rem 1.8rem",
              borderRadius: "999px",
              border: "1px solid rgba(255,255,255,0.3)",
              color: "#f9fafb"
            }}
          >
            Billing
          </Link>
        </div>
      </header>

      <AvatarGrid />
    </main>
  );
}
