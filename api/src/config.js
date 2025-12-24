/**
 * Configuration helper with type checking
 * Ensures all required environment variables are present
 */
class Config {
  constructor() {
    this.nodeEnv = process.env.NODE_ENV || "development";
    this.isProduction = this.nodeEnv === "production";
    this.isDevelopment = this.nodeEnv === "development";
  }

  // API Configuration
  getApiConfig() {
    return {
      port: this.requireEnv("API_PORT", 4000),
      host: this.getEnv("API_HOST", "0.0.0.0"),
      basePath: this.getEnv("API_BASE_PATH", "/api"),
    };
  }

  // Database Configuration
  getDatabaseUrl() {
    return this.requireEnv("DATABASE_URL");
  }

  // CORS Configuration
  getCorsOrigins() {
    const origins = this.getEnv("CORS_ORIGINS", "http://localhost:3000");
    return origins.split(",").map((o) => o.trim());
  }

  // Third-party API Keys
  getApiKeys() {
    const stripeSecret =
      this.getEnv("STRIPE_SECRET_KEY") || this.getEnv("STRIPE_API_KEY");

    if (!stripeSecret) {
      throw new Error(
        "Missing required environment variable: STRIPE_SECRET_KEY (or STRIPE_API_KEY)",
      );
    }

    return {
      openai: this.requireEnv("OPENAI_API_KEY"),
      anthropic: this.requireEnv("ANTHROPIC_API_KEY"),
      stripe: stripeSecret,
      stripeWebhookSecret: this.requireEnv("STRIPE_WEBHOOK_SECRET"),
      paypalClientId: this.requireEnv("PAYPAL_CLIENT_ID"),
      paypalClientSecret: this.requireEnv("PAYPAL_CLIENT_SECRET"),
      paypalSecret: this.requireEnv("PAYPAL_SECRET"),
      aiSyntheticUrl: this.requireEnv("AI_SYNTHETIC_ENGINE_URL"),
      aiSyntheticKey: this.requireEnv("AI_SYNTHETIC_API_KEY"),
    };
  }

  // JWT Configuration
  getJwtSecret() {
    return this.requireEnv("JWT_SECRET");
  }

  // Logging Configuration
  getLogLevel() {
    return this.getEnv("LOG_LEVEL", this.isProduction ? "error" : "debug");
  }

  // Helper methods
  requireEnv(key, defaultValue = null) {
    const value = process.env[key];
    if (!value && defaultValue === null) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
    return value || defaultValue;
  }

  getEnv(key, defaultValue = "") {
    return process.env[key] || defaultValue;
  }

  getBoolean(key, defaultValue = false) {
    const value = process.env[key];
    if (!value) return defaultValue;
    return value.toLowerCase() === "true";
  }

  getNumber(key, defaultValue = 0) {
    const value = process.env[key];
    if (!value) return defaultValue;
    const num = parseInt(value, 10);
    return isNaN(num) ? defaultValue : num;
  }
}

module.exports = new Config();
