/**
 * Stripe Configuration & Integration
 * Production-ready Stripe payment handling
 */

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const logger = require('./logger');

// ============================================================================
// STRIPE EVENT HANDLERS
// ============================================================================

class StripeWebhookHandler {
  /**
   * Handle all Stripe webhook events
   */
  static async handleWebhook(event) {
    logger.info('Stripe webhook received', { type: event.type });

    switch (event.type) {
      // Customer events
      case 'customer.created':
        return this.handleCustomerCreated(event.data.object);
      case 'customer.updated':
        return this.handleCustomerUpdated(event.data.object);
      case 'customer.deleted':
        return this.handleCustomerDeleted(event.data.object);

      // Subscription events
      case 'customer.subscription.created':
        return this.handleSubscriptionCreated(event.data.object);
      case 'customer.subscription.updated':
        return this.handleSubscriptionUpdated(event.data.object);
      case 'customer.subscription.deleted':
        return this.handleSubscriptionDeleted(event.data.object);

      // Payment events
      case 'invoice.created':
        return this.handleInvoiceCreated(event.data.object);
      case 'invoice.payment_succeeded':
        return this.handleInvoicePaymentSucceeded(event.data.object);
      case 'invoice.payment_failed':
        return this.handleInvoicePaymentFailed(event.data.object);

      // Charge events
      case 'charge.refunded':
        return this.handleChargeRefunded(event.data.object);

      default:
        logger.warn('Unhandled webhook event', { type: event.type });
    }
  }

  // ========================================================================
  // CUSTOMER HANDLERS
  // ========================================================================

  static async handleCustomerCreated(customer) {
    logger.info('Customer created in Stripe', { stripeCustomerId: customer.id });

    // Update local customer record
    await prisma.customer.update({
      where: { stripe_customer_id: customer.id },
      data: {
        stripe_sync_at: new Date(),
        stripe_data: customer
      }
    }).catch(err => {
      logger.warn('Could not update customer', { error: err.message });
    });
  }

  static async handleCustomerUpdated(customer) {
    logger.info('Customer updated in Stripe', { stripeCustomerId: customer.id });

    await prisma.customer.update({
      where: { stripe_customer_id: customer.id },
      data: {
        email: customer.email || undefined,
        stripe_sync_at: new Date(),
        stripe_data: customer
      }
    }).catch(err => {
      logger.warn('Could not update customer', { error: err.message });
    });
  }

  static async handleCustomerDeleted(customer) {
    logger.info('Customer deleted in Stripe', { stripeCustomerId: customer.id });

    await prisma.customer.update({
      where: { stripe_customer_id: customer.id },
      data: {
        deleted_at: new Date(),
        status: 'deleted'
      }
    });
  }

  // ========================================================================
  // SUBSCRIPTION HANDLERS
  // ========================================================================

  static async handleSubscriptionCreated(subscription) {
    logger.info('Subscription created', {
      stripeSubscriptionId: subscription.id,
      customerId: subscription.customer
    });

    // Get customer from DB
    const customer = await prisma.customer.findUnique({
      where: { stripe_customer_id: subscription.customer }
    });

    if (!customer) {
      logger.error('Customer not found for subscription', {
        stripeCustomerId: subscription.customer
      });
      return;
    }

    // Create subscription in database
    const plan = subscription.items.data[0];
    await prisma.subscription.create({
      data: {
        customer_id: customer.id,
        stripe_subscription_id: subscription.id,
        stripe_price_id: plan.price.id,
        status: subscription.status,
        current_period_start: new Date(subscription.current_period_start * 1000),
        current_period_end: new Date(subscription.current_period_end * 1000),
        auto_renew: !subscription.cancel_at
      }
    });
  }

  static async handleSubscriptionUpdated(subscription) {
    logger.info('Subscription updated', {
      stripeSubscriptionId: subscription.id,
      status: subscription.status
    });

    const plan = subscription.items.data[0];

    await prisma.subscription.update({
      where: { stripe_subscription_id: subscription.id },
      data: {
        stripe_price_id: plan.price.id,
        status: subscription.status,
        current_period_start: new Date(subscription.current_period_start * 1000),
        current_period_end: new Date(subscription.current_period_end * 1000),
        auto_renew: !subscription.cancel_at,
        updated_at: new Date()
      }
    });
  }

  static async handleSubscriptionDeleted(subscription) {
    logger.info('Subscription cancelled', {
      stripeSubscriptionId: subscription.id
    });

    await prisma.subscription.update({
      where: { stripe_subscription_id: subscription.id },
      data: {
        status: 'cancelled',
        cancelled_at: new Date(),
        auto_renew: false
      }
    });
  }

  // ========================================================================
  // INVOICE & PAYMENT HANDLERS
  // ========================================================================

  static async handleInvoiceCreated(invoice) {
    logger.info('Invoice created', {
      stripeInvoiceId: invoice.id,
      amount: invoice.amount_due
    });

    const subscription = await prisma.subscription.findUnique({
      where: { stripe_subscription_id: invoice.subscription }
    });

    if (!subscription) return;

    await prisma.invoice.create({
      data: {
        customer_id: subscription.customer_id,
        subscription_id: subscription.id,
        stripe_invoice_id: invoice.id,
        amount_subtotal: invoice.subtotal / 100,
        amount_tax: invoice.tax / 100,
        amount_total: invoice.total / 100,
        status: 'draft',
        period_start: new Date(invoice.period_start * 1000),
        period_end: new Date(invoice.period_end * 1000)
      }
    });
  }

  static async handleInvoicePaymentSucceeded(invoice) {
    logger.info('Payment succeeded', {
      stripeInvoiceId: invoice.id,
      amount: invoice.total / 100
    });

    await prisma.invoice.update({
      where: { stripe_invoice_id: invoice.id },
      data: {
        status: 'paid',
        paid_at: new Date()
      }
    });

    // Send receipt email
    await this.sendReceiptEmail(invoice);
  }

  static async handleInvoicePaymentFailed(invoice) {
    logger.error('Payment failed', {
      stripeInvoiceId: invoice.id,
      amount: invoice.total / 100
    });

    await prisma.invoice.update({
      where: { stripe_invoice_id: invoice.id },
      data: {
        status: 'failed'
      }
    });

    // Send failure notification
    await this.sendPaymentFailureEmail(invoice);
  }

  static async handleChargeRefunded(charge) {
    logger.info('Charge refunded', {
      stripeChargeId: charge.id,
      amount: charge.amount_refunded / 100
    });

    const invoice = await prisma.invoice.findUnique({
      where: { stripe_invoice_id: charge.invoice }
    });

    if (invoice) {
      await prisma.invoice.update({
        where: { id: invoice.id },
        data: { status: 'refunded' }
      });
    }
  }

  static async sendReceiptEmail(invoice) {
    // Implement email sending (SendGrid, etc)
    logger.info('Receipt email queued', { invoiceId: invoice.id });
  }

  static async sendPaymentFailureEmail(invoice) {
    // Implement email sending (SendGrid, etc)
    logger.info('Failure email queued', { invoiceId: invoice.id });
  }
}

// ============================================================================
// SUBSCRIPTION MANAGEMENT
// ============================================================================

class SubscriptionManager {
  /**
   * Create a new subscription for a customer
   */
  static async createSubscription(customerId, priceId, paymentMethodId) {
    try {
      const customer = await prisma.customer.findUnique({
        where: { id: customerId }
      });

      if (!customer.stripe_customer_id) {
        throw new Error('Customer not linked to Stripe');
      }

      // Create subscription in Stripe
      const subscription = await stripe.subscriptions.create({
        customer: customer.stripe_customer_id,
        items: [{ price: priceId }],
        default_payment_method: paymentMethodId,
        payment_behavior: 'error_if_incomplete'
      });

      logger.info('Subscription created in Stripe', {
        customerId,
        stripeSubscriptionId: subscription.id
      });

      return subscription;
    } catch (err) {
      logger.error('Failed to create subscription', { customerId, error: err.message });
      throw err;
    }
  }

  /**
   * Update subscription pricing (upgrade/downgrade)
   */
  static async updateSubscriptionPrice(subscriptionId, newPriceId) {
    try {
      const subscription = await prisma.subscription.findUnique({
        where: { id: subscriptionId }
      });

      const stripeSubscription = await stripe.subscriptions.retrieve(
        subscription.stripe_subscription_id
      );

      const updated = await stripe.subscriptions.update(
        subscription.stripe_subscription_id,
        {
          items: [
            {
              id: stripeSubscription.items.data[0].id,
              price: newPriceId
            }
          ],
          proration_behavior: 'create_prorations'
        }
      );

      logger.info('Subscription updated', { subscriptionId, newPriceId });
      return updated;
    } catch (err) {
      logger.error('Failed to update subscription', { subscriptionId, error: err.message });
      throw err;
    }
  }

  /**
   * Cancel subscription
   */
  static async cancelSubscription(subscriptionId, immediate = false) {
    try {
      const subscription = await prisma.subscription.findUnique({
        where: { id: subscriptionId }
      });

      const cancelled = await stripe.subscriptions.update(
        subscription.stripe_subscription_id,
        {
          cancel_at_period_end: !immediate
        }
      );

      logger.info('Subscription cancelled', { subscriptionId, immediate });
      return cancelled;
    } catch (err) {
      logger.error('Failed to cancel subscription', { subscriptionId, error: err.message });
      throw err;
    }
  }

  /**
   * Retry failed payment
   */
  static async retryPayment(invoiceId) {
    try {
      const invoice = await prisma.invoice.findUnique({
        where: { id: invoiceId }
      });

      const result = await stripe.invoices.pay(invoice.stripe_invoice_id);

      logger.info('Payment retry sent', { invoiceId });
      return result;
    } catch (err) {
      logger.error('Failed to retry payment', { invoiceId, error: err.message });
      throw err;
    }
  }
}

// ============================================================================
// CUSTOMER MANAGEMENT
// ============================================================================

class CustomerManager {
  /**
   * Link customer to Stripe
   */
  static async linkToStripe(customerId, email, name) {
    try {
      // Check if already linked
      const customer = await prisma.customer.findUnique({
        where: { id: customerId }
      });

      if (customer.stripe_customer_id) {
        return customer.stripe_customer_id;
      }

      // Create in Stripe
      const stripeCustomer = await stripe.customers.create({
        email,
        name,
        metadata: {
          app_customer_id: customerId
        }
      });

      // Update local record
      await prisma.customer.update({
        where: { id: customerId },
        data: { stripe_customer_id: stripeCustomer.id }
      });

      logger.info('Customer linked to Stripe', { customerId, stripeId: stripeCustomer.id });
      return stripeCustomer.id;
    } catch (err) {
      logger.error('Failed to link customer', { customerId, error: err.message });
      throw err;
    }
  }

  /**
   * Update payment method
   */
  static async updatePaymentMethod(customerId, paymentMethodId) {
    try {
      const customer = await prisma.customer.findUnique({
        where: { id: customerId }
      });

      await stripe.customers.update(customer.stripe_customer_id, {
        invoice_settings: {
          default_payment_method: paymentMethodId
        }
      });

      logger.info('Payment method updated', { customerId });
    } catch (err) {
      logger.error('Failed to update payment method', { customerId, error: err.message });
      throw err;
    }
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  stripe,
  StripeWebhookHandler,
  SubscriptionManager,
  CustomerManager
};
