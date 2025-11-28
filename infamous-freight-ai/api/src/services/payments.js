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
      apiVersion: "2023-10-16"
    });
  }
  return stripeClient;
}

function getPayPalClient() {
  if (!paypalClientId || !paypalClientSecret) {
    return null;
  }
  if (!paypalClient) {
    const Environment = paypalEnv === "live"
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
    automatic_payment_methods: { enabled: true }
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
          value: amount
        }
      }
    ]
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

module.exports = {
  createStripeIntent,
  createPayPalOrder,
  capturePayPalOrder,
  buildStripeWebhook
};
