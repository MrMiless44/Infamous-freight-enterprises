import { useState } from "react";

interface PricingTier {
  id: string;
  name: string;
  price: number;
  interval: string;
  features: string[];
  popular?: boolean;
}

export default function PricingTable() {
  const [loading, setLoading] = useState(false);
  const [selectedTier, setSelectedTier] = useState<string | null>(null);

  const tiers: PricingTier[] = [
    {
      id: "starter",
      name: "Starter",
      price: 149,
      interval: "month",
      features: [
        "10 drivers",
        "100 shipments/month",
        "Basic AI routing",
        "Email support",
        "Mobile app access",
      ],
    },
    {
      id: "professional",
      name: "Professional",
      price: 399,
      interval: "month",
      features: [
        "50 drivers",
        "1,000 shipments/month",
        "Advanced AI optimization",
        "Voice AI copilot",
        "Priority support",
        "API access",
      ],
      popular: true,
    },
    {
      id: "enterprise",
      name: "Enterprise",
      price: 1299,
      interval: "month",
      features: [
        "Unlimited drivers",
        "Unlimited shipments",
        "Full AI suite",
        "Dedicated account manager",
        "24/7 phone support",
        "White-label options",
        "SLA guarantee",
      ],
    },
  ];

  const handleSubscribe = async (tierId: string) => {
    setLoading(true);
    setSelectedTier(tierId);

    try {
      const response = await fetch("/api/billing/subscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "demo@infamousfreight.ai",
          tierId,
        }),
      });

      const data = await response.json();

      if (data.ok) {
        alert(
          `✅ ${data.message}\nTier: ${data.tier.name}\nPrice: $${data.tier.price}/month`,
        );
      } else {
        alert(`❌ Error: ${data.error}`);
      }
    } catch (err) {
      alert(`❌ Network error: ${err}`);
    } finally {
      setLoading(false);
      setSelectedTier(null);
    }
  };

  return (
    <div
      style={{
        padding: "3rem 1.5rem",
        background: "#050509",
        minHeight: "100vh",
      }}
    >
      <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: "3rem" }}>
          <h1
            style={{
              fontSize: "2.5rem",
              color: "#f9fafb",
              marginBottom: "1rem",
            }}
          >
            Choose Your Plan
          </h1>
          <p style={{ fontSize: "1.1rem", color: "rgba(249,250,251,0.7)" }}>
            14-day free trial • No credit card required • Cancel anytime
          </p>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
            gap: "2rem",
            marginBottom: "3rem",
          }}
        >
          {tiers.map((tier) => (
            <div
              key={tier.id}
              style={{
                position: "relative",
                background: tier.popular
                  ? "linear-gradient(135deg, #1a1a33, #0a0a1a)"
                  : "#0a0a1a",
                border: tier.popular
                  ? "2px solid #ffcc33"
                  : "1px solid rgba(255,255,255,0.1)",
                borderRadius: "16px",
                padding: "2rem",
                boxShadow: tier.popular
                  ? "0 20px 60px rgba(255,204,51,0.2)"
                  : "0 10px 30px rgba(0,0,0,0.5)",
              }}
            >
              {tier.popular && (
                <div
                  style={{
                    position: "absolute",
                    top: "-12px",
                    left: "50%",
                    transform: "translateX(-50%)",
                    background: "linear-gradient(135deg, #ffcc33, #ff3366)",
                    color: "#050509",
                    padding: "0.4rem 1.2rem",
                    borderRadius: "20px",
                    fontSize: "0.75rem",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                  }}
                >
                  Most Popular
                </div>
              )}

              <h3
                style={{
                  fontSize: "1.5rem",
                  color: "#f9fafb",
                  marginBottom: "0.5rem",
                }}
              >
                {tier.name}
              </h3>

              <div style={{ marginBottom: "1.5rem" }}>
                <span
                  style={{
                    fontSize: "3rem",
                    fontWeight: 700,
                    color: "#f9fafb",
                  }}
                >
                  ${tier.price}
                </span>
                <span
                  style={{ fontSize: "1rem", color: "rgba(249,250,251,0.6)" }}
                >
                  /{tier.interval}
                </span>
              </div>

              <ul
                style={{ listStyle: "none", padding: 0, marginBottom: "2rem" }}
              >
                {tier.features.map((feature, idx) => (
                  <li
                    key={idx}
                    style={{
                      padding: "0.75rem 0",
                      color: "rgba(249,250,251,0.85)",
                      fontSize: "0.95rem",
                      borderBottom: "1px solid rgba(255,255,255,0.05)",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.5rem",
                    }}
                  >
                    <span style={{ color: "#ffcc33" }}>✓</span>
                    {feature}
                  </li>
                ))}
              </ul>

              <button
                onClick={() => handleSubscribe(tier.id)}
                disabled={loading && selectedTier === tier.id}
                style={{
                  width: "100%",
                  padding: "1rem",
                  background: tier.popular
                    ? "linear-gradient(135deg, #ffcc33, #ff3366)"
                    : "rgba(255,255,255,0.1)",
                  color: tier.popular ? "#050509" : "#f9fafb",
                  border: "none",
                  borderRadius: "8px",
                  fontSize: "1rem",
                  fontWeight: 600,
                  cursor: loading ? "not-allowed" : "pointer",
                  transition: "all 0.2s",
                  opacity: loading && selectedTier === tier.id ? 0.6 : 1,
                }}
              >
                {loading && selectedTier === tier.id
                  ? "Processing..."
                  : "Start Free Trial"}
              </button>
            </div>
          ))}
        </div>

        <div
          style={{
            textAlign: "center",
            padding: "2rem",
            background: "#0a0a1a",
            borderRadius: "12px",
          }}
        >
          <h3 style={{ color: "#f9fafb", marginBottom: "1rem" }}>
            Need a custom plan?
          </h3>
          <p style={{ color: "rgba(249,250,251,0.7)", marginBottom: "1.5rem" }}>
            Contact our sales team for enterprise pricing and custom solutions.
          </p>
          <a
            href="mailto:sales@infamousfreight.ai"
            style={{
              display: "inline-block",
              padding: "0.75rem 2rem",
              background: "rgba(255,255,255,0.1)",
              color: "#f9fafb",
              textDecoration: "none",
              borderRadius: "8px",
              fontWeight: 600,
            }}
          >
            Contact Sales
          </a>
        </div>
      </div>
    </div>
  );
}
