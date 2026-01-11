/**
 * Payment Routes
 * Core payment processing endpoints for Stripe integration
 */

const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { 
  SubscriptionManager, 
  CustomerManager 
} = require('../services/stripeConfig');
const { 
  authenticate, 
  requireScope, 
  limiters 
} = require('../middleware/security');
const { 
  validateString, 
  handleValidationErrors 
} = require('../middleware/validation');
const { body, validationResult } = require('express-validator');
const logger = require('../middleware/logger');
const db = require('../db');

// ============================================================================
// PRICING & PRODUCTS
// ============================================================================

/**
 * GET /api/payments/pricing
 * Get all available pricing plans
 */
router.get('/pricing', async (req, res, next) => {
  try {
    // Get prices from Stripe
    const prices = await stripe.prices.list({
      limit: 100,
      expand: ['data.product']
    });

    const pricing = prices.data
      .filter(price => price.type === 'recurring')
      .map(price => ({
        id: price.id,
        product_id: price.product.id,
        name: price.product.name,
        description: price.product.description,
        amount: price.unit_amount / 100,
        currency: price.currency.toUpperCase(),
        interval: price.recurring.interval,
        interval_count: price.recurring.interval_count,
        metadata: price.product.metadata
      }));

    res.json({ success: true, data: pricing });
  } catch (err) {
    next(err);
  }
});

// ============================================================================
// CHECKOUT SESSION
// ============================================================================

/**
 * POST /api/payments/checkout-session
 * Create Stripe checkout session
 */
router.post(
  '/checkout-session',
  limiters.general,
  authenticate,
  [
    body('priceId').notEmpty().withMessage('Price ID is required'),
    body('quantity').optional().isInt({ min: 1 }).withMessage('Quantity must be positive')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { priceId, quantity = 1 } = req.body;
      const userId = req.user.sub;

      // Get price details
      const price = await stripe.prices.retrieve(priceId, {
        expand: ['product']
      });

      // Link customer to Stripe if not already
      let stripeCustomerId = req.user.stripe_customer_id;
      if (!stripeCustomerId) {
        stripeCustomerId = await CustomerManager.linkToStripe(
          userId,
          req.user.email,
          req.user.name
        );
      }

      // Create checkout session
      const session = await stripe.checkout.sessions.create({
        customer: stripeCustomerId,
        line_items: [
          {
            price: priceId,
            quantity: quantity
          }
        ],
        mode: 'subscription',
        success_url: `${process.env.WEB_URL}/dashboard/billing?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.WEB_URL}/pricing`,
        billing_address_collection: 'required',
        locale: 'en',
        metadata: {
          user_id: userId,
          product_name: price.product.name
        }
      });

      logger.info('Checkout session created', {
        userId,
        sessionId: session.id,
        priceId
      });

      res.json({ success: true, data: { sessionId: session.id, url: session.url } });
    } catch (err) {
      next(err);
    }
  }
);

// ============================================================================
// SUBSCRIPTION MANAGEMENT
// ============================================================================

/**
 * POST /api/payments/subscribe
 * Create subscription with payment method
 */
router.post(
  '/subscribe',
  limiters.billing,
  authenticate,
  [
    body('priceId').notEmpty(),
    body('paymentMethodId').notEmpty()
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { priceId, paymentMethodId } = req.body;
      const userId = req.user.sub;

      // Get or create Stripe customer
      let stripeCustomerId = req.user.stripe_customer_id;
      if (!stripeCustomerId) {
        stripeCustomerId = await CustomerManager.linkToStripe(
          userId,
          req.user.email,
          req.user.name
        );
      }

      // Create subscription
      const subscription = await SubscriptionManager.createSubscription(
        userId,
        priceId,
        paymentMethodId
      );

      logger.info('Subscription created', {
        userId,
        subscriptionId: subscription.id
      });

      res.json({
        success: true,
        data: {
          subscription_id: subscription.id,
          status: subscription.status,
          current_period_end: new Date(subscription.current_period_end * 1000)
        }
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * GET /api/payments/subscription/:subscriptionId
 * Get subscription details
 */
router.get(
  '/subscription/:subscriptionId',
  authenticate,
  async (req, res, next) => {
    try {
      const subscription = await db.subscriptions.findUnique({
        where: { id: req.params.subscriptionId }
      });

      if (!subscription || subscription.customer_id !== req.user.sub) {
        return res.status(404).json({ error: 'Subscription not found' });
      }

      res.json({ success: true, data: subscription });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * POST /api/payments/subscription/:subscriptionId/upgrade
 * Upgrade to higher tier
 */
router.post(
  '/subscription/:subscriptionId/upgrade',
  limiters.billing,
  authenticate,
  [body('newPriceId').notEmpty()],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { newPriceId } = req.body;
      const subscription = await db.subscriptions.findUnique({
        where: { id: req.params.subscriptionId }
      });

      if (!subscription || subscription.customer_id !== req.user.sub) {
        return res.status(404).json({ error: 'Subscription not found' });
      }

      // Update in Stripe
      const updated = await SubscriptionManager.updateSubscriptionPrice(
        req.params.subscriptionId,
        newPriceId
      );

      logger.info('Subscription upgraded', {
        subscriptionId: req.params.subscriptionId,
        newPriceId
      });

      res.json({ success: true, data: updated });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * POST /api/payments/subscription/:subscriptionId/cancel
 * Cancel subscription
 */
router.post(
  '/subscription/:subscriptionId/cancel',
  limiters.billing,
  authenticate,
  async (req, res, next) => {
    try {
      const subscription = await db.subscriptions.findUnique({
        where: { id: req.params.subscriptionId }
      });

      if (!subscription || subscription.customer_id !== req.user.sub) {
        return res.status(404).json({ error: 'Subscription not found' });
      }

      // Cancel at end of period (graceful)
      const cancelled = await SubscriptionManager.cancelSubscription(
        req.params.subscriptionId,
        false
      );

      logger.info('Subscription cancel requested', {
        subscriptionId: req.params.subscriptionId
      });

      res.json({
        success: true,
        message: 'Subscription will cancel at end of billing period',
        data: cancelled
      });
    } catch (err) {
      next(err);
    }
  }
);

// ============================================================================
// INVOICES
// ============================================================================

/**
 * GET /api/payments/invoices
 * List all invoices for authenticated user
 */
router.get(
  '/invoices',
  authenticate,
  async (req, res, next) => {
    try {
      const invoices = await db.invoices.findMany({
        where: { customer_id: req.user.sub },
        orderBy: { created_at: 'desc' },
        take: 50
      });

      res.json({ success: true, data: invoices });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * GET /api/payments/invoices/:invoiceId/pdf
 * Download invoice PDF
 */
router.get(
  '/invoices/:invoiceId/pdf',
  authenticate,
  async (req, res, next) => {
    try {
      const invoice = await db.invoices.findUnique({
        where: { id: req.params.invoiceId }
      });

      if (!invoice || invoice.customer_id !== req.user.sub) {
        return res.status(404).json({ error: 'Invoice not found' });
      }

      // Get PDF from storage
      const pdfUrl = invoice.pdf_url;
      if (!pdfUrl) {
        return res.status(404).json({ error: 'PDF not generated yet' });
      }

      // Download or redirect to URL
      res.redirect(pdfUrl);
    } catch (err) {
      next(err);
    }
  }
);

/**
 * POST /api/payments/invoices/:invoiceId/retry
 * Retry failed payment
 */
router.post(
  '/invoices/:invoiceId/retry',
  limiters.billing,
  authenticate,
  async (req, res, next) => {
    try {
      const invoice = await db.invoices.findUnique({
        where: { id: req.params.invoiceId }
      });

      if (!invoice || invoice.customer_id !== req.user.sub) {
        return res.status(404).json({ error: 'Invoice not found' });
      }

      // Retry in Stripe
      const retried = await stripe.invoices.pay(invoice.stripe_invoice_id);

      logger.info('Invoice payment retried', { invoiceId: req.params.invoiceId });

      res.json({
        success: true,
        message: 'Payment retry initiated',
        data: retried
      });
    } catch (err) {
      next(err);
    }
  }
);

// ============================================================================
// PAYMENT METHODS
// ============================================================================

/**
 * GET /api/payments/methods
 * Get saved payment methods
 */
router.get(
  '/methods',
  authenticate,
  async (req, res, next) => {
    try {
      const customer = await db.customers.findUnique({
        where: { id: req.user.sub }
      });

      if (!customer.stripe_customer_id) {
        return res.json({ success: true, data: [] });
      }

      // Get payment methods from Stripe
      const methods = await stripe.paymentMethods.list({
        customer: customer.stripe_customer_id,
        type: 'card'
      });

      res.json({ success: true, data: methods.data });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * POST /api/payments/methods
 * Add payment method
 */
router.post(
  '/methods',
  limiters.billing,
  authenticate,
  [body('paymentMethodId').notEmpty()],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { paymentMethodId } = req.body;

      // Link to customer
      await CustomerManager.updatePaymentMethod(req.user.sub, paymentMethodId);

      logger.info('Payment method updated', { userId: req.user.sub });

      res.json({ success: true, message: 'Payment method updated' });
    } catch (err) {
      next(err);
    }
  }
);

// ============================================================================
// BILLING PORTAL
// ============================================================================

/**
 * POST /api/payments/billing-portal
 * Create Stripe customer portal session
 */
router.post(
  '/billing-portal',
  authenticate,
  async (req, res, next) => {
    try {
      const customer = await db.customers.findUnique({
        where: { id: req.user.sub }
      });

      if (!customer.stripe_customer_id) {
        return res.status(400).json({
          error: 'Customer not linked to Stripe',
          hint: 'Start a subscription first'
        });
      }

      // Create portal session
      const portalSession = await stripe.billingPortal.sessions.create({
        customer: customer.stripe_customer_id,
        return_url: `${process.env.WEB_URL}/dashboard/billing`
      });

      res.json({ success: true, data: { url: portalSession.url } });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
