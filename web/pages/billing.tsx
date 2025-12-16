import { useEffect } from "react";
import { track } from "@vercel/analytics";
import { BillingPanel } from "../components/BillingPanel";

export default function BillingPage() {
  useEffect(() => {
    // Track billing page visit
    track("billing_page_visited", {
      timestamp: new Date().toISOString(),
    });
  }, []);

  return (
    <main style={{ padding: "2rem" }}>
      <h1>Billing</h1>
      <BillingPanel />
    </main>
  );
}
