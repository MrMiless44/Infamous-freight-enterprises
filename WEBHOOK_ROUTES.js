/**
 * Stripe Webhook Route Handler
 * Express.js route for handling Stripe webhook events
 */

const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { StripeWebhookHandler } = require('../services/stripeConfig');
const logger = require('../middleware/logger');

// ============================================================================
// WEBHOOK VERIFICATION
// ============================================================================

/**
 * Verify Stripe webhook signature
 * Raw body is required (not JSON parsed)
 */
router.post('/stripe', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];

  let event;

  try {
    // Construct event from raw body and signature
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );

    logger.info('Webhook signature verified', { type: event.type });
  } catch (err) {
    logger.error('Webhook signature verification failed', { error: err.message });
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Process the event
  try {
    await StripeWebhookHandler.handleWebhook(event);
    res.json({ received: true });
  } catch (err) {
    logger.error('Webhook processing failed', {
      type: event.type,
      error: err.message,
      stack: err.stack
    });

    // Return 200 to prevent Stripe retries (we log the error)
    res.json({ received: true, error: err.message });
  }
});

// ============================================================================
// WEBHOOK HEALTH CHECK
// ============================================================================

/**
 * GET /api/webhooks/health
 * Verify webhook endpoint is active
 */
router.get('/stripe/health', (req, res) => {
  res.json({
    status: 'ok',
    webhook_secret_configured: !!process.env.STRIPE_WEBHOOK_SECRET,
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// WEBHOOK TESTING (Development only)
// ============================================================================

/**
 * POST /api/webhooks/stripe/test
 * Send test webhook from Stripe Dashboard or use this endpoint
 * Only available in development
 */
router.post('/stripe/test', async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'Test webhooks not available in production' });
  }

  const testEvents = {
    'customer.created': {
      type: 'customer.created',
      data: {
        object: {
          id: 'cus_test123',
          email: 'test@example.com',
          name: 'Test Customer'
        }
      }
    },
    'customer.subscription.created': {
      type: 'customer.subscription.created',
      data: {
        object: {
          id: 'sub_test123',
          customer: 'cus_test123',
          status: 'active',
          current_period_start: Math.floor(Date.now() / 1000),
          current_period_end: Math.floor(Date.now() / 1000) + 2592000,
          items: {
            data: [{
              price: { id: 'price_test123' }
            }]
          }
        }
      }
    },
    'invoice.payment_succeeded': {
      type: 'invoice.payment_succeeded',
      data: {
        object: {
          id: 'in_test123',
          subscription: 'sub_test123',
          customer: 'cus_test123',
          status: 'paid',
          amount_due: 9900,
          amount_paid: 9900,
          total: 9900,
          subtotal: 9900,
          tax: 0,
          period_start: Math.floor(Date.now() / 1000),
          period_end: Math.floor(Date.now() / 1000) + 2592000
        }
      }
    }
  };

  const eventType = req.body.event_type || 'customer.subscription.created';
  const testEvent = testEvents[eventType];

  if (!testEvent) {
    return res.status(400).json({
      error: 'Invalid test event type',
      available: Object.keys(testEvents)
    });
  }

  try {
    await StripeWebhookHandler.handleWebhook(testEvent);
    res.json({ success: true, event: testEvent });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// WEBHOOK RETRY ENDPOINTS
// ============================================================================

/**
 * Manually trigger webhook for failed events
 * Useful for recovery from temporary issues
 */
router.post('/stripe/retry/:invoiceId', async (req, res) => {
  try {
    const { invoiceId } = req.params;

    // Get invoice from Stripe
    const invoice = await stripe.invoices.retrieve(invoiceId);

    // Construct webhook event
    const event = {
      type: 'invoice.payment_succeeded',
      data: { object: invoice }
    };

    // Process
    await StripeWebhookHandler.handleWebhook(event);

    res.json({ success: true, invoice });
  } catch (err) {
    logger.error('Manual webhook retry failed', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
