import AppLayout from "../components/AppLayout";
import { BillingPanel } from "../components/BillingPanel";

export default function BillingPage() {
  return (
    <AppLayout
      kicker="Payments"
      title="Billing"
      subtitle="Test payments in seconds with Stripe or PayPal."
    >
      <div className="card" style={{ marginBottom: "1rem" }}>
        <p className="subtle" style={{ margin: 0 }}>
          Choose a processor, launch checkout, and return here automatically.
          Use the dashboard to see payment events land in real time.
        </p>
      </div>
      <div className="panel">
        <BillingPanel />
      </div>
    </AppLayout>
  );
}
