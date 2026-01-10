import React, { useState } from "react";
import { useRouter } from "next/router";
import { getSession } from "next-auth/react";
import Head from "next/head";
import styles from "../styles/pricing.module.css";

const PRICING_TIERS = [
  {
    id: "starter",
    name: "Starter",
    description: "Perfect for small teams",
    monthlyPrice: 299,
    annualPrice: 2990,
    features: [
      "10 active shipments",
      "Real-time tracking (30 days)",
      "Basic reporting",
      "Email support",
      "100 API requests/day",
      "1 user account",
    ],
    cta: "Start Free Trial",
    highlighted: false,
  },
  {
    id: "professional",
    name: "Professional",
    description: "Most popular for growing businesses",
    monthlyPrice: 799,
    annualPrice: 7990,
    features: [
      "Unlimited shipments",
      "Real-time tracking (1 year)",
      "Advanced reporting & AI",
      "Priority support",
      "10,000 API requests/day",
      "Up to 10 users",
      "Custom integrations",
      "Monthly business reviews",
    ],
    cta: "Start Free Trial",
    highlighted: true,
  },
  {
    id: "enterprise",
    name: "Enterprise",
    description: "For large organizations",
    monthlyPrice: 2999,
    annualPrice: 29990,
    features: [
      "Everything in Professional",
      "Custom pricing & features",
      "Dedicated account manager",
      "24/7 priority support",
      "Unlimited API requests",
      "Unlimited users",
      "White-label options",
      "Custom security & compliance",
      "SLA guarantees",
    ],
    cta: "Contact Sales",
    highlighted: false,
  },
];

interface PricingPageProps {
  session: any;
}

export default function PricingPage({ session }: PricingPageProps) {
  const router = useRouter();
  const [billingCycle, setBillingCycle] = useState<"monthly" | "annual">(
    "monthly",
  );
  const [loading, setLoading] = useState(false);

  const handleStartTrial = async (tierId: string) => {
    if (!session) {
      router.push("/api/auth/signin?callbackUrl=/pricing");
      return;
    }

    if (tierId === "enterprise") {
      // For enterprise, show contact form
      router.push("/contact-sales");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch("/api/billing/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tier: tierId,
          billingCycle,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to create checkout session");
      }

      const { url } = await response.json();
      window.location.href = url;
    } catch (error) {
      console.error("Checkout error:", error);
      alert("Failed to start checkout. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const getPrice = (tier: (typeof PRICING_TIERS)[0]) => {
    const price =
      billingCycle === "monthly" ? tier.monthlyPrice : tier.annualPrice;
    const monthlyEquivalent =
      billingCycle === "annual" ? Math.round((price / 12) * 100) / 100 : price;
    return { price, monthlyEquivalent };
  };

  return (
    <>
      <Head>
        <title>Pricing - Infamous Freight Enterprises</title>
        <meta
          name="description"
          content="Simple, transparent pricing for freight management"
        />
      </Head>

      <div className={styles.container}>
        {/* Header */}
        <section className={styles.header}>
          <h1>Simple, Transparent Pricing</h1>
          <p>Choose the perfect plan for your freight operations</p>

          {/* Billing Cycle Toggle */}
          <div className={styles.billingToggle}>
            <button
              className={billingCycle === "monthly" ? styles.active : ""}
              onClick={() => setBillingCycle("monthly")}
            >
              Monthly
            </button>
            <button
              className={billingCycle === "annual" ? styles.active : ""}
              onClick={() => setBillingCycle("annual")}
            >
              Annual
              <span className={styles.badge}>Save 2 months</span>
            </button>
          </div>
        </section>

        {/* Pricing Cards */}
        <section className={styles.pricingGrid}>
          {PRICING_TIERS.map((tier) => {
            const { price, monthlyEquivalent } = getPrice(tier);
            return (
              <div
                key={tier.id}
                className={`${styles.card} ${tier.highlighted ? styles.highlighted : ""}`}
              >
                {tier.highlighted && (
                  <div className={styles.badge2}>MOST POPULAR</div>
                )}

                <h3>{tier.name}</h3>
                <p className={styles.description}>{tier.description}</p>

                {/* Price */}
                <div className={styles.price}>
                  <span className={styles.amount}>${price}</span>
                  <span className={styles.period}>
                    {billingCycle === "monthly" ? "/month" : "/year"}
                  </span>
                </div>

                {billingCycle === "annual" && (
                  <p className={styles.monthlyEquivalent}>
                    ${monthlyEquivalent}/month billed annually
                  </p>
                )}

                {/* Trial Info */}
                <p className={styles.trialInfo}>
                  30-day free trial • No credit card required
                </p>

                {/* CTA Button */}
                <button
                  className={`${styles.cta} ${tier.highlighted ? styles.primary : styles.secondary}`}
                  onClick={() => handleStartTrial(tier.id)}
                  disabled={loading}
                >
                  {loading ? "Loading..." : tier.cta}
                </button>

                {/* Features */}
                <ul className={styles.features}>
                  {tier.features.map((feature, idx) => (
                    <li key={idx}>
                      <span className={styles.checkmark}>✓</span>
                      {feature}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </section>

        {/* FAQ */}
        <section className={styles.faq}>
          <h2>Frequently Asked Questions</h2>
          <div className={styles.faqItems}>
            <div className={styles.faqItem}>
              <h4>Can I upgrade or downgrade anytime?</h4>
              <p>
                Yes! Change your plan or cancel anytime. No long-term contracts.
              </p>
            </div>
            <div className={styles.faqItem}>
              <h4>What's included in the free trial?</h4>
              <p>
                Full access to all features in your chosen tier for 30 days.
                After the trial ends, you'll be charged the plan price.
              </p>
            </div>
            <div className={styles.faqItem}>
              <h4>Do you offer discounts for annual billing?</h4>
              <p>
                Yes! Pay annually and save 2 months (equivalent to 17%
                discount).
              </p>
            </div>
            <div className={styles.faqItem}>
              <h4>Is there a free version?</h4>
              <p>
                We offer 30-day free trials on all plans. After that, you'll
                need a paid subscription.
              </p>
            </div>
            <div className={styles.faqItem}>
              <h4>What's included in API limits?</h4>
              <p>
                API limits apply to programmatic requests. Web app usage is
                unlimited regardless of plan.
              </p>
            </div>
            <div className={styles.faqItem}>
              <h4>Can I contact sales for custom plans?</h4>
              <p>
                Absolutely! Contact our sales team for enterprise features,
                custom pricing, and dedicated support.
              </p>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className={styles.ctaSection}>
          <h2>Ready to get started?</h2>
          <p>
            Join hundreds of freight companies using Infamous Freight to
            optimize their operations.
          </p>
          <button
            className={styles.ctaButton}
            onClick={() => handleStartTrial("professional")}
            disabled={loading}
          >
            {loading ? "Loading..." : "Start Your Free Trial"}
          </button>
        </section>
      </div>
    </>
  );
}

export async function getServerSideProps(context: any) {
  const session = await getSession(context);

  return {
    props: {
      session,
    },
  };
}
