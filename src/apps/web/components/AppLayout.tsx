import Link from "next/link";
import { useRouter } from "next/router";
import type { ReactNode } from "react";

interface AppLayoutProps {
  title?: string;
  subtitle?: string;
  kicker?: string;
  actions?: ReactNode;
  children: ReactNode;
}

const links = [
  { href: "/", label: "Home" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/billing", label: "Billing" },
];

export function AppLayout({
  title,
  subtitle,
  kicker,
  actions,
  children,
}: AppLayoutProps) {
  const router = useRouter();
  const env = process.env.NEXT_PUBLIC_ENV || "Development";
  const appName = process.env.NEXT_PUBLIC_APP_NAME || "Infamous Freight AI";

  return (
    <div>
      <nav className="nav">
        <div className="nav-brand">
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              width: "34px",
              height: "34px",
              borderRadius: "10px",
              background: "linear-gradient(135deg,#ffcc33,#ff5e62)",
              color: "#050509",
              fontWeight: 800,
            }}
          >
            IF
          </span>
          <div>
            <div style={{ fontWeight: 700 }}>{appName}</div>
            <div className="subtle" style={{ fontSize: "0.85rem" }}>
              Command center for freight AI
            </div>
          </div>
        </div>
        <div className="nav-links">
          <span className="pill">{env}</span>
          {links.map((link) => {
            const active = router.pathname === link.href;
            return (
              <Link key={link.href} href={link.href} legacyBehavior>
                <a
                  className={active ? "primary-btn" : "ghost-btn"}
                  aria-current={active ? "page" : undefined}
                >
                  {link.label}
                </a>
              </Link>
            );
          })}
        </div>
      </nav>

      <div className="page-shell">
        {(title || subtitle) && (
          <header style={{ marginBottom: "1.75rem" }}>
            {kicker && <p className="hero-kicker">{kicker}</p>}
            {title && <h1 className="hero-title">{title}</h1>}
            {subtitle && <p className="section-subtitle">{subtitle}</p>}
            {actions && <div className="inline-actions">{actions}</div>}
          </header>
        )}
        {children}
      </div>
    </div>
  );
}

export default AppLayout;
