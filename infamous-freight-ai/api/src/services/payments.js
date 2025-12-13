const Stripe = require("stripe");
const paypalSdk = require("@paypal/checkout-server-sdk");

let stripeClient;
let paypalClient;

const stripeSecret = process.env.STRIPE_SECRET_KEY;
const paypalClientId = process.env.PAYPAL_CLIENT_ID;
const paypalClientSecret = process.env.PAYPAL_CLIENT_SECRET;
const paypalEnv = (process.env.PAYPAL_ENV || "sandbox").toLowerCase();

function getStripeClient() {
  if (!stripeSecret) {
    return null;
  }
  if (!stripeClient) {
    stripeClient = new Stripe(stripeSecret, {
      apiVersion: "2023-10-16",
    });
  }
  return stripeClient;
}

function getPayPalClient() {
  if (!paypalClientId || !paypalClientSecret) {
    return null;
  }
  if (!paypalClient) {
    const Environment =
      paypalEnv === "live"
        ? paypalSdk.core.LiveEnvironment
        : paypalSdk.core.SandboxEnvironment;
    const environment = new Environment(paypalClientId, paypalClientSecret);
    paypalClient = new paypalSdk.core.PayPalHttpClient(environment);
  }
  return paypalClient;
}

async function createStripeIntent({ amount, currency = "usd", metadata = {} }) {
  const client = getStripeClient();
  if (!client) {
    throw new Error("STRIPE_NOT_CONFIGURED");
  }
  return client.paymentIntents.create({
    amount,
    currency,
    metadata,
    automatic_payment_methods: { enabled: true },
  });
}

async function createPayPalOrder({ amount, currency = "USD", referenceId }) {
  const client = getPayPalClient();
  if (!client) {
    throw new Error("PAYPAL_NOT_CONFIGURED");
  }
  const request = new paypalSdk.orders.OrdersCreateRequest();
  request.requestBody({
    intent: "CAPTURE",
    purchase_units: [
      {
        reference_id: referenceId,
        amount: {
          currency_code: currency,
          value: amount,
        },
      },
    ],
  });

  const response = await client.execute(request);
  return response.result;
}

async function capturePayPalOrder(orderId) {
  const client = getPayPalClient();
  if (!client) {
    throw new Error("PAYPAL_NOT_CONFIGURED");
  }
  const request = new paypalSdk.orders.OrdersCaptureRequest(orderId);
  request.requestBody({});
  const response = await client.execute(request);
  return response.result;
}

function buildStripeWebhook(eventPayload, signature) {
  const client = getStripeClient();
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!client || !webhookSecret) {
    return { type: "unverified", data: eventPayload };
  }

  // NOTE: Express json middleware loses access to the raw body, so this
  // fallback trusts the parsed payload. For production-grade signature
  // verification, add express.raw middleware before json parsing.
  try {
    return client.webhooks.constructEvent(
      Buffer.from(JSON.stringify(eventPayload)),
      signature,
      webhookSecret
    );
  } catch (err) {
    return { type: "invalid", error: err.message, data: eventPayload };
  }
}

/**
 * Get or create Stripe Customer
 */
async function getOrCreateStripeCustomer({ email, name, metadata = {} }) {
  const client = getStripeClient();
  if (!client) {
    throw new Error("STRIPE_NOT_CONFIGURED");
  }

  const customers = await client.customers.list({ email, limit: 1 });
  
  if (customers.data.length > 0) {
    return customers.data[0];
  }

  return client.customers.create({ email, name, metadata });
}

/**
 * Create Stripe Subscription
 */
async function createStripeSubscription({ customerId, priceId, trialDays = 14 }) {
  const client = getStripeClient();
  if (!client) {
    throw new Error("STRIPE_NOT_CONFIGURED");
  }

  return client.subscriptions.create({
    customer: customerId,
    items: [{ price: priceId }],
    trial_period_days: trialDays,
    payment_behavior: 'default_incomplete',
    expand: ['latest_invoice.payment_intent'],
  });
}

/**
 * Get pricing tiers for 2025 market
 */
function getPricingTiers() {
  return {
    starter: {
      id: 'starter',
      name: 'Starter',
      price: 149,
      interval: 'month',
      features: ['10 drivers', '100 shipments/month', 'Basic AI routing', 'Email support'],
      limits: { drivers: 10, shipments: 100, aiCalls: 500 },
    },
    professional: {
      id: 'professional',
      name: 'Professional',
      price: 399,
      interval: 'month',
      features: ['50 drivers', '1,000 shipments/month', 'Advanced AI', 'Voice copilot', 'API access'],
      limits: { drivers: 50, shipments: 1000, aiCalls: 5000 },
      popular: true,
    },
    enterprise: {
      id: 'enterprise',
      name: 'Enterprise',
      price: 1299,
      interval: 'month',
      features: ['Unlimited drivers', 'Unlimited shipments', 'Full AI suite', '24/7 support', 'White-label'],
      limits: { drivers: -1, shipments: -1, aiCalls: -1 },
    },
  };
}

/**
 * Calculate usage-based pricing
 */
function calculateUsageCost(usage) {
  const rates = {
    shipment: 1.5,
    aiOptimization: 2.0,
    voiceMinute: 0.15,
    apiCall: 0.01,
  };

  let total = 0;
  let breakdown = {};

  Object.keys(rates).forEach((key) => {
    if (usage[key + 's'] || usage[key]) {
      const quantity = usage[key + 's'] || usage[key];
      const cost = quantity * rates[key];
      total += cost;
      breakdown[key] = { quantity, rate: rates[key], cost };
    }
  });

  return { total: Math.round(total * 100) / 100, breakdown, currency: 'usd' };
}

module.exports = {
  createStripeIntent,
  createPayPalOrder,
  capturePayPalOrder,
  buildStripeWebhook,
  getOrCreateStripeCustomer,
  createStripeSubscription,
  getPricingTiers,
  calculateUsageCost,
};
