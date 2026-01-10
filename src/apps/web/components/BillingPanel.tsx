import React, { useState } from "react";
import { track } from "@vercel/analytics";
import { useApi } from "../hooks/useApi";
import styles from "../styles/panels.module.css";

export function BillingPanel() {
  const api = useApi();
  const [stripeSession, setStripeSession] = useState<string | null>(null);
  const [paypalOrder, setPaypalOrder] = useState<string | null>(null);

  async function createStripe() {
    try {
      const res = await api.post("/billing/stripe/session");
      setStripeSession(res.sessionId);
      track("payment_initiated", {
        method: "stripe",
        sessionId: res.sessionId,
      });
      if (res.url) {
        window.location.href = res.url;
      }
    } catch (error) {
      track("payment_error", {
        method: "stripe",
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  async function createPayPal() {
    try {
      const res = await api.post("/billing/paypal/order");
      setPaypalOrder(res.orderId);
      track("payment_initiated", {
        method: "paypal",
        orderId: res.orderId,
      });
      if (res.approvalUrl) {
        window.location.href = res.approvalUrl;
      }
    } catch (error) {
      track("payment_error", {
        method: "paypal",
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  return (
    <div>
      <div className={styles.panelHeader}>
        <div>
          <p className="hero-kicker" style={{ marginBottom: "0.15rem" }}>
            Billing
          </p>
          <h3 style={{ margin: 0 }}>Checkout in one tap</h3>
        </div>
        <span className="pill">Stripe + PayPal</span>
      </div>
      <p className="subtle" style={{ marginTop: "0.35rem" }}>
        Launch a test checkout to confirm payments end-to-end.
      </p>

      <div className={styles.billingActions}>
        <button className="primary-btn" onClick={createStripe}>
          Checkout with Stripe
        </button>
        <button className="ghost-btn" onClick={createPayPal}>
          Pay with PayPal
        </button>
      </div>

      <div className={styles.badgeGrid}>
        <div className={styles.badgeCard}>PCI handled by providers</div>
        <div className={styles.badgeCard}>Redirect flow returns to app</div>
        <div className={styles.badgeCard}>Events visible in dashboard</div>
      </div>

      {stripeSession && (
        <p style={{ marginTop: "0.9rem" }}>Stripe session: {stripeSession}</p>
      )}

      {paypalOrder && (
        <p style={{ marginTop: "0.35rem" }}>PayPal order: {paypalOrder}</p>
      )}
    </div>
  );
}
