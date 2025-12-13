require("dotenv").config();

function assertEnv(keys, label) {
  const missing = keys.filter((key) => !process.env[key]);
  if (missing.length) {
    throw new Error(`${label} missing: ${missing.join(", ")}`);
  }
}

try {
  assertEnv(["DATABASE_URL", "JWT_SECRET"], "Core env variables");

  const provider = process.env.AI_PROVIDER || "synthetic";
  if (provider === "synthetic") {
    assertEnv(
      ["AI_SYNTHETIC_ENGINE_URL", "AI_SYNTHETIC_API_KEY"],
      "Synthetic AI configuration",
    );
  } else if (provider === "openai") {
    assertEnv(["OPENAI_API_KEY"], "OpenAI configuration");
  } else if (provider === "anthropic") {
    assertEnv(["ANTHROPIC_API_KEY"], "Anthropic configuration");
  }

  if (process.env.STRIPE_SECRET_KEY) {
    assertEnv(
      ["STRIPE_SUCCESS_URL", "STRIPE_CANCEL_URL"],
      "Stripe redirect URLs",
    );
  }

  const hasPayPalCreds =
    process.env.PAYPAL_CLIENT_ID || process.env.PAYPAL_SECRET;
  if (hasPayPalCreds) {
    assertEnv(["PAYPAL_CLIENT_ID", "PAYPAL_SECRET"], "PayPal credentials");
  }

  console.log("Environment variables look good.");
  process.exit(0);
} catch (err) {
  console.error(`Environment validation failed: ${err.message}`);
  process.exit(1);
}
