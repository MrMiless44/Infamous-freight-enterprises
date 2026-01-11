# 💳 Payment Processing Setup: Stripe & PayPal

**Status**: Complete Implementation Guide  
**Time to Setup**: 1-2 hours  
**Difficulty**: Beginner-friendly

---

## 🔵 STRIPE SETUP (Recommended)

### Step 1: Create Stripe Account

```bash
# 1. Go to Stripe
https://stripe.com

# 2. Click "Start now" → Sign up with email

# 3. Verify email & complete profile
Company name: Infamous Freight Enterprises
Website: infamousfreight.com
Business type: Software/SaaS
Industry: Logistics & Freight
Timezone: UTC

# 4. Activate live mode (after testing)
```

### Step 2: Get API Keys

```bash
# 1. Go to Stripe Dashboard
https://dashboard.stripe.com/apikeys

# 2. Copy your keys:

Publishable key (starts with pk_):
pk_test_xxxxxxxxxxxxxxxxxxxxx
(use in frontend, safe to expose)

Secret key (starts with sk_):
sk_test_xxxxxxxxxxxxxxxxxxxxx
(NEVER share - use only in backend)

# 3. Add to .env.local
VITE_STRIPE_PUBLISHABLE_KEY=pk_test_xxxxxxxxxxxxxxxxxxxxx
STRIPE_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxx
STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxxxxxxxxxx (get next)

# 4. Get webhook secret
https://dashboard.stripe.com/webhooks
Create endpoint → Select URL: https://yoursite.com/api/webhook
Add events: invoice.payment_succeeded, customer.subscription.deleted
Copy webhook signing secret
```

### Step 3: Create Products & Prices

**In Stripe Dashboard:**

```bash
# 1. Go to Products
https://dashboard.stripe.com/products

# 2. Create Product: "Starter Plan"
Click "+ New product"
Name: Starter Plan
Type: Service (or Subscription)
Description: Best for small teams
Image: (optional logo)

# 3. Add Price
Price: $29.00
Currency: USD
Billing period: Monthly (or Annually)
Recurring: Yes
Click "Create product"

# 4. Copy Price ID
Example: price_1a2b3c4d5e6f7g8h9i0j

# 5. Repeat for other plans:
- Professional Plan: $99/month (price_xxxx)
- Enterprise Plan: $299/month (price_xxxx)
```

### Step 4: Frontend Checkout Integration

**HTML Payment Form:**

```html
<!-- Install Stripe JS -->
<script src="https://js.stripe.com/v3/"></script>

<!-- Pricing Page Example -->
<div class="pricing-container">
  <!-- Starter Plan -->
  <div class="plan starter">
    <h3>Starter Plan</h3>
    <p class="price">$29<span>/month</span></p>
    <ul class="features">
      <li>✅ 5 active shipments</li>
      <li>✅ Basic tracking</li>
      <li>✅ Email support</li>
      <li>✅ Mobile app</li>
    </ul>
    <button onclick="checkout('price_starter')">Subscribe Now</button>
  </div>

  <!-- Professional Plan -->
  <div class="plan professional">
    <h3>Professional</h3>
    <p class="price">$99<span>/month</span></p>
    <ul class="features">
      <li>✅ Everything in Starter</li>
      <li>✅ 50 active shipments</li>
      <li>✅ Advanced analytics</li>
      <li>✅ API access</li>
      <li>✅ Team collaboration</li>
    </ul>
    <button onclick="checkout('price_professional')">Subscribe Now</button>
  </div>

  <!-- Enterprise Plan -->
  <div class="plan enterprise">
    <h3>Enterprise</h3>
    <p class="price">$299<span>/month</span></p>
    <ul class="features">
      <li>✅ Everything in Professional</li>
      <li>✅ Unlimited shipments</li>
      <li>✅ Unlimited API calls</li>
      <li>✅ 24/7 support</li>
      <li>✅ Dedicated manager</li>
      <li>✅ Custom features</li>
    </ul>
    <button onclick="checkout('price_enterprise')">Contact Sales</button>
  </div>
</div>

<!-- Checkout Script -->
<script>
const stripe = Stripe(import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY);

async function checkout(priceId) {
  try {
    // Send priceId to backend
    const response = await fetch('/api/payments/checkout-session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ priceId })
    });

    const { sessionId } = await response.json();

    // Redirect to Stripe Checkout
    const { error } = await stripe.redirectToCheckout({ sessionId });

    if (error) {
      console.error('Error:', error.message);
      alert('Payment failed: ' + error.message);
    }
  } catch (err) {
    console.error('Error:', err);
    alert('Something went wrong');
  }
}
</script>
```

### Step 5: Backend Checkout Session

**Create with Express.js:**

```javascript
// api/src/routes/payments.js
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const router = express.Router();

// Create checkout session
router.post('/checkout-session', authenticate, async (req, res, next) => {
  try {
    const { priceId } = req.body;

    // Create customer if not exists
    let customer = await stripe.customers.list({
      email: req.user.email,
      limit: 1
    });

    if (customer.data.length === 0) {
      customer = await stripe.customers.create({
        email: req.user.email,
        name: req.user.name,
        metadata: { userId: req.user.id }
      });
    } else {
      customer = customer.data[0];
    }

    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      customer: customer.id,
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${process.env.WEB_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.WEB_URL}/pricing`,
    });

    res.json({ sessionId: session.id });
  } catch (err) {
    next(err);
  }
});

// Handle webhook
router.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];

  try {
    const event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );

    switch (event.type) {
      case 'customer.subscription.created':
        // New subscription
        const sub = event.data.object;
        await db.subscriptions.create({
          stripe_subscription_id: sub.id,
          stripe_customer_id: sub.customer,
          status: 'active'
        });
        break;

      case 'invoice.payment_succeeded':
        // Payment successful
        const invoice = event.data.object;
        await db.subscriptions.update(invoice.subscription, {
          status: 'active'
        });
        break;

      case 'invoice.payment_failed':
        // Payment failed
        const failedInvoice = event.data.object;
        await sendEmail(
          failedInvoice.customer_email,
          'Payment Failed',
          'Please update your payment method'
        );
        break;
    }

    res.json({received: true});
  } catch (err) {
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

module.exports = router;
```

---

## 🟦 PAYPAL SETUP (International Alternative)

### Step 1: Create PayPal Business Account

```bash
# 1. Go to PayPal
https://www.paypal.com/business

# 2. Create Business Account
Email: miless8787@gmail.com
Name: Infamous Freight Enterprises
Business type: Software/SaaS

# 3. Complete verification
Confirm email
Phone verification
Business details
```

### Step 2: Get API Credentials

```bash
# 1. Go to Developer Dashboard
https://developer.paypal.com/dashboard/

# 2. Login & go to Apps & Credentials
Accounts tab → Sandbox

# 3. Copy credentials:
Client ID: AS....(sandbox)
Secret: ELT....(sandbox)

# 4. Add to .env.local
PAYPAL_CLIENT_ID=AS...
PAYPAL_CLIENT_SECRET=ELT...
PAYPAL_MODE=sandbox (or live)
```

### Step 3: Create Billing Plans

```bash
# 1. In Developer Dashboard
Subscriptions → Create plan

Plan 1: Starter Plan
- Name: Starter
- Description: 5 shipments/month
- Regular Billing: $29/month
- Billing Cycles: 12
- Auto Renew: Yes

Plan 2: Professional Plan  
- Name: Professional
- Description: 50 shipments/month
- Regular Billing: $99/month
- Billing Cycles: 12

Plan 3: Enterprise Plan
- Name: Enterprise
- Description: Unlimited shipments
- Regular Billing: $299/month
- Billing Cycles: 12

# 2. Copy Plan IDs
Example: I-2E3F4G5H6I7J8K9L0M
```

### Step 4: Frontend PayPal Integration

```html
<!-- PayPal Smart Payment Buttons -->
<script src="https://www.paypal.com/sdk/js?client-id=YOUR_CLIENT_ID&vault=true&intent=subscription"></script>

<div id="paypal-button-container-starter"></div>
<div id="paypal-button-container-professional"></div>
<div id="paypal-button-container-enterprise"></div>

<script>
paypal.Buttons({
  createSubscriptionDetails() {
    return {
      planId: 'PLAN_ID_STARTER' // Get from PayPal dashboard
    };
  },
  onApprove(data) {
    fetch('/api/payments/paypal-subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        subscriptionID: data.subscriptionID
      })
    })
    .then(res => res.json())
    .then(data => {
      alert('Subscription created: ' + data.subscriptionID);
      window.location.href = '/dashboard';
    });
  },
  onError(err) {
    alert('Payment error: ' + err);
  }
}).render('#paypal-button-container-starter');
</script>
```

---

## 📊 Payment Dashboard

**Track all payments:**

```bash
# Stripe Dashboard
https://dashboard.stripe.com

Metrics to monitor:
- Gross volume (total revenue)
- Failed charges
- Refunds
- Customer LTV
- Monthly recurring revenue
- Churn rate

# PayPal Dashboard
https://www.paypal.com/businessmanage/home

Metrics:
- Transactions
- Net profit
- Pending/completed payments
- Subscription status
```

---

## ✅ Testing Payment Processing

### Stripe Test Cards

```
Success: 4242 4242 4242 4242
Failed: 4000 0000 0000 0002
3D Secure: 4000 0025 0000 3010
Expiry: Any future date
CVC: Any 3 digits
```

### PayPal Sandbox

```bash
# Sandbox buyer account (created automatically)
Email: buyer@sandbox.paypal.com
Password: (from email)

Test transactions show in:
https://sandbox.paypal.com/businessmanage/transactions
```

---

## 🔐 Security Checklist

```
API Keys:
  [ ] Secret keys never exposed in frontend
  [ ] Keys stored in environment variables
  [ ] Keys rotated regularly
  [ ] Old keys deleted

Payments:
  [ ] SSL/HTTPS enforced
  [ ] PCI compliance verified
  [ ] Webhook signatures validated
  [ ] Card data never stored locally

Compliance:
  [ ] Terms of Service includes payment terms
  [ ] Privacy Policy covers data processing
  [ ] Refund policy published
  [ ] GDPR compliant (EU customers)
```

---

## 🚀 Go Live Checklist

```
Before Switching to Live Keys:

Testing:
  [ ] Test checkout complete
  [ ] Test subscription cancellation
  [ ] Test refund process
  [ ] Test failed payment email
  [ ] Test webhook delivery

Configuration:
  [ ] Live API keys configured
  [ ] Webhook endpoints verified
  [ ] Email templates finalized
  [ ] Success/cancel URLs correct

Legal:
  [ ] Terms of Service finalized
  [ ] Privacy Policy updated
  [ ] Refund policy written
  [ ] Billing email templates approved

Monitoring:
  [ ] Error alerts set up
  [ ] Payment monitoring enabled
  [ ] Support queue ready
  [ ] Revenue tracking dashboard live

Launch:
  [ ] Announce to beta users
  [ ] Monitor first 24 hours
  [ ] Be ready to support
  [ ] Track metrics
```

---

## 📞 Support

**Stripe Help:**
```
https://support.stripe.com
https://stripe.com/docs
```

**PayPal Help:**
```
https://developer.paypal.com/support
https://developer.paypal.com/docs
```

---

**Status**: 🟢 Ready to Deploy  
**Integration Time**: 2-4 hours  
**Cost**: Stripe (2.9% + $0.30), PayPal (2.99% + $0.30)  
**Revenue**: First payment can be collected today!

