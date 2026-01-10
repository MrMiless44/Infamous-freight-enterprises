import React, { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import Head from "next/head";
import styles from "../styles/billing.module.css";

export default function BillingSuccessPage() {
  const router = useRouter();
  const { data: session } = useSession();
  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [message, setMessage] = useState("");
  const [subscription, setSubscription] = useState(null);

  useEffect(() => {
    if (!session) return;

    const processCheckout = async () => {
      try {
        const { sessionId } = router.query;
        
        if (!sessionId) {
          setStatus("error");
          setMessage("No checkout session found");
          return;
        }

        // Fetch subscription details
        const response = await fetch("/api/billing/subscriptions", {
          method: "GET",
          headers: { "Content-Type": "application/json" },
        });

        if (response.ok) {
          const { subscription } = await response.json();
          setSubscription(subscription);
          setStatus("success");
          setMessage("Welcome! Your subscription is now active.");
        } else {
          setStatus("error");
          setMessage("Failed to confirm subscription");
        }
      } catch (error) {
        console.error("Checkout processing error:", error);
        setStatus("error");
        setMessage("An error occurred. Please contact support.");
      }
    };

    processCheckout();
  }, [session, router.query]);

  if (!session) {
    return (
      <div className={styles.container}>
        <div className={styles.card}>
          <h2>Please sign in to continue</h2>
          <button onClick={() => router.push("/api/auth/signin")}>Sign In</button>
        </div>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title>Billing Confirmation - Infamous Freight</title>
      </Head>

      <div className={styles.container}>
        {status === "loading" && (
          <div className={styles.card}>
            <h2>Processing your subscription...</h2>
            <p>Please wait while we confirm your payment.</p>
            <div className={styles.spinner}></div>
          </div>
        )}

        {status === "success" && (
          <div className={styles.successCard}>
            <div className={styles.successIcon}>✓</div>
            <h2>Subscription Activated!</h2>
            <p>{message}</p>

            {subscription && (
              <div className={styles.details}>
                <p>
                  <strong>Plan:</strong> {subscription.tier}
                </p>
                <p>
                  <strong>Billing Cycle:</strong> {subscription.billingCycle}
                </p>
                <p>
                  <strong>Price:</strong> ${subscription.priceMonthly}/month
                </p>
                <p>
                  <strong>Trial Ends:</strong> {new Date(subscription.trialEndsAt).toLocaleDateString()}
                </p>
              </div>
            )}

            <div className={styles.nextSteps}>
              <h3>Next Steps:</h3>
              <ol>
                <li>Complete your company profile</li>
                <li>Set up your first shipment</li>
                <li>Invite team members to collaborate</li>
                <li>Enable notifications and alerts</li>
              </ol>
            </div>

            <div className={styles.actions}>
              <button onClick={() => router.push("/dashboard")} className={styles.primary}>
                Go to Dashboard
              </button>
              <button onClick={() => router.push("/")} className={styles.secondary}>
                Back to Home
              </button>
            </div>

            <p className={styles.support}>
              Need help? <a href="mailto:support@infamousfreight.com">Contact our support team</a>
            </p>
          </div>
        )}

        {status === "error" && (
          <div className={styles.errorCard}>
            <div className={styles.errorIcon}>✕</div>
            <h2>Something went wrong</h2>
            <p>{message}</p>

            <div className={styles.actions}>
              <button onClick={() => router.push("/pricing")} className={styles.primary}>
                Back to Pricing
              </button>
              <button onClick={() => router.push("/contact-sales")} className={styles.secondary}>
                Contact Support
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
