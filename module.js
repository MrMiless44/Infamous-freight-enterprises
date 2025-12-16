module.exports = {
  stripe: {
    secretKey: process.env.STRIPE_SECRET_KEY,
    successUrl: process.env.STRIPE_SUCCESS_URL,
    cancelUrl: process.env.STRIPE_CANCEL_URL,
  },
  // Validate at startup, fail fast
};
