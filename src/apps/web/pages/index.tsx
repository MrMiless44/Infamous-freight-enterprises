import { useEffect } from "react";
import Link from "next/link";
import { track } from "@vercel/analytics";
import AppLayout from "../components/AppLayout";
import { AvatarGrid } from "../components/AvatarGrid";
import styles from "../styles/home.module.css";

const stats = [
  { label: "Route time saved", value: "-27 min" },
  { label: "On-time arrivals", value: "98%" },
  { label: "Claims reduced", value: "-36%" },
];

const checklist = [
  "Voice-first dispatch and coaching",
  "Live shipment telemetry and alerts",
  "Stripe + PayPal billing in one tap",
  "AI copilots for safety and margins",
];

const playbook = [
  {
    title: "Drivers",
    detail: "Hear actionable, safe prompts that recover minutes per route.",
  },
  {
    title: "Dispatch",
    detail: "Live exceptions, bid suggestions, and compliance at a glance.",
  },
  {
    title: "Finance",
    detail: "Collect faster with Stripe/PayPal and see revenue in real time.",
  },
];

export default function Home() {
  const appName = process.env.NEXT_PUBLIC_APP_NAME || "Infamous Freight AI";

  useEffect(() => {
    track("homepage_visited", {
      app: appName,
      timestamp: new Date().toISOString(),
    });
  }, [appName]);

  return (
    <AppLayout
      kicker="Customer-ready"
      title="Freight control, finally friendly"
      subtitle="A single, driver-safe workspace that connects dispatch, billing, and AI copilots."
      actions={
        <div className={styles.heroActions}>
          <Link href="/dashboard" legacyBehavior>
            <a className="primary-btn">Launch dashboard</a>
          </Link>
          <Link href="/billing" legacyBehavior>
            <a className="ghost-btn">Open billing</a>
          </Link>
        </div>
      }
    >
      <section className={styles.heroGrid}>
        <div className={styles.heroCard}>
          <div className="glow" />
          <div className="card-content">
            <p className="hero-kicker">Pilot ready</p>
            <h2 className={styles.heroHighlight}>{appName}</h2>
            <p className={styles.heroCopy}>
              Voice automation, billing orchestration, fleet telemetry, and AI
              copilots converge in a single control tower designed for humans.
            </p>
            <div className={styles.statGrid}>
              {stats.map((item) => (
                <div key={item.label} className={styles.statItem}>
                  <h4 className="subtle">{item.label}</h4>
                  <p style={{ fontSize: "1.15rem", margin: 0 }}>{item.value}</p>
                </div>
              ))}
            </div>
            <ul className={styles.checklist}>
              {checklist.map((item) => (
                <li key={item}>✅ {item}</li>
              ))}
            </ul>
          </div>
        </div>

        <div className={styles.heroCard}>
          <div className="gradient" />
          <div className="card-content">
            <h3 className="cardTitle">Instant start</h3>
            <p className={styles.heroCopy}>
              Zero-complexity onboarding. Use the live demo dashboard, then
              connect your data when you are ready.
            </p>
            <div className="timeline" style={{ marginTop: "1rem" }}>
              <span>00:00 — Open dashboard</span>
              <span>00:02 — Send first voice command</span>
              <span>00:05 — Test a Stripe/PayPal payment</span>
            </div>
            <div className="heroActions" style={{ marginTop: "1.25rem" }}>
              <Link href="/dashboard" legacyBehavior>
                <a className="primary-btn">Try the control tower</a>
              </Link>
              <Link href="/api" legacyBehavior>
                <a className="ghost-btn">Review API docs</a>
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section className={`${styles.sectionBlock}`}>
        <div className={styles.sectionHeader}>
          <div>
            <h2 className="section-title">AI Avatars</h2>
            <p className="section-subtitle">
              Three copilots cover operations, dispatch, and risk so humans stay
              focused on exceptions.
            </p>
          </div>
          <div className="badge-stack">
            <span className="pill">Driver safe</span>
            <span className="pill">Live telemetry</span>
            <span className="pill">Coach-ready</span>
          </div>
        </div>
        <AvatarGrid />
      </section>

      <section className={`${styles.sectionBlock}`}>
        <div className={styles.sectionHeader}>
          <div>
            <h2 className="section-title">Ops playbook</h2>
            <p className="section-subtitle">
              Every team gets a friendlier starting point.
            </p>
          </div>
        </div>
        <div className={styles.playbook}>
          {playbook.map((item) => (
            <div key={item.title} className={styles.playCard}>
              <h4>{item.title}</h4>
              <p>{item.detail}</p>
            </div>
          ))}
        </div>
      </section>
    </AppLayout>
  );
}
