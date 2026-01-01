# Infamous Freight - Stripe Products Quick Reference

**Date**: January 1, 2026 | **Status**: ✅ Production Ready

---

## 📊 Product Summary

```
TOTAL PRODUCTS: 45+
CATEGORIES: 7
SYNCED TO STRIPE: ✅ Yes
PAYMENT METHODS: Stripe, PayPal
BILLING OPTIONS: One-time, Subscription, Usage-based
```

---

## 🚚 Shipping Services (7 Products)

### Pricing Chart

```
LOCAL DELIVERY (0-50 mi)
├─ Base: $45.00
├─ Per-Mile: $0.50
├─ Max Weight: 5,000 lbs
└─ SLA: 24-48 hours

REGIONAL (50-500 mi)
├─ Base: $75.00
├─ Per-Mile: $0.35
├─ Max Weight: 20,000 lbs
└─ SLA: 2-5 business days

CROSS-COUNTRY (500-3000 mi)
├─ Base: $150.00
├─ Per-Mile: $0.20
├─ Max Weight: 45,000 lbs
└─ SLA: 3-7 business days

FULL TRUCK LOAD (FTL)
├─ Base: $2,500.00
├─ Per-Mile: $1.50
├─ Capacity: 53ft trailer (45k lbs)
└─ SLA: 2-7 business days

LESS THAN TRUCK (LTL)
├─ Base: $50.00
├─ Per-Pound: $0.02
├─ Max Weight: 10,000 lbs
└─ SLA: 3-5 business days

INTERNATIONAL
├─ Base: $500.00
├─ Per-Pound: $0.05
├─ Customs: Included
└─ SLA: 7-21 business days

EXPRESS OVERNIGHT
├─ Base: $200.00
├─ Per-Mile: $1.00
├─ Max Distance: 500 miles
└─ SLA: Next business day 9am
```

---

## 🔧 Specialty Add-ons (6 Products)

```
TEMPERATURE-CONTROLLED ... +$50.00
└─ Temp Range: -40°F to 70°F (FDA/USDA)

HAZMAT SHIPPING ............. +$100.00
└─ Certified: DOT/IATA/IMDG

WHITE-GLOVE DELIVERY ........ +$150.00
└─ Includes: Unpacking, positioning, setup

LIFTGATE SERVICE ............ +$25.00
└─ Capacity: 5,000 lbs

INSIDE DELIVERY ............ +$50.00
└─ To warehouse/dock with placement

CARGO INSURANCE ............ $2-5 per $1000
└─ All-risk coverage, 48hr claims
```

---

## ⭐ Value-Added Services (6 Products)

```
REAL-TIME TRACKING
├─ Per Shipment: $5.00
└─ Monthly Unlimited: $29.99

DELIVERY NOTIFICATIONS
└─ Monthly: $9.99

PROOF OF DELIVERY (POD)
├─ Per Shipment: +$10.00
└─ Includes: Photo, signature, GPS, timestamp

DYNAMIC PRICING ENGINE
├─ Monthly: $49.99
└─ Savings: Up to 25%

CONSOLIDATION SERVICE
├─ Per Order: +$25.00
└─ Average Savings: 15%

CUSTOMS CLEARANCE
└─ Per Shipment: $150.00
```

---

## 📅 Subscription Plans (4 Plans)

### Comparison Chart

```
                    STARTER    PROFESSIONAL  ENTERPRISE   PAY-PER-USE
────────────────────────────────────────────────────────────────────
Monthly Price       $99.99     $299.99       $999.99      $25.00+ per
Annual Savings      -          $600          $1,199.88    order
────────────────────────────────────────────────────────────────────
Shipments/mo        100        1,000         Unlimited    Any
Users               3          10            Unlimited    Unlimited
Support             Email      Phone+Email   24/7         Email
────────────────────────────────────────────────────────────────────
API Access          Basic      Standard      Premium      Standard
Webhooks            -          ✓            ✓            ✓
Custom Integration  -          ✓            ✓            Limited
────────────────────────────────────────────────────────────────────
Analytics           Basic      Advanced      Custom       Basic
Account Manager     -          Dedicated     Dedicated    -
SLA Guarantee       -          -             99.9%        -
────────────────────────────────────────────────────────────────────
White-Label         -          -             ✓            -
Blockchain Verify   -          -             ✓            -
```

---

## 👨‍💼 Driver & Fleet Services (3 Products)

```
DRIVER MOBILE APP
├─ Price: $4.99/driver/month
├─ Features:
│  ├─ GPS tracking
│  ├─ Route optimization
│  ├─ Real-time updates
│  ├─ Voice commands
│  └─ Proof of delivery
└─ Min Drivers: 1

INTELLIGENT DISPATCH
├─ Price: $499.99/month (all drivers)
├─ Features:
│  ├─ Auto-assign drivers
│  ├─ ML optimization
│  ├─ Traffic aware
│  ├─ Capacity planning
│  └─ Predictive maintenance
└─ Coverage: Unlimited drivers

FLEET TRACKING
├─ Price: $9.99/vehicle/month
├─ Features:
│  ├─ Real-time location
│  ├─ Maintenance alerts
│  ├─ Fuel monitoring
│  ├─ Driver behavior
│  └─ Compliance reports
└─ Min Vehicles: 1
```

---

## 📊 Analytics & Reporting (3 Products)

```
BASIC ANALYTICS
├─ Price: $9.99/month
└─ Reports: Monthly, Quarterly

ADVANCED ANALYTICS
├─ Price: $49.99/month
├─ Reports: Daily, Weekly, Monthly
└─ Features: ML insights, margin analysis

CUSTOM REPORTING
├─ Price: $99.99/month
├─ Reports: Unlimited custom
└─ Features: Data warehouse access
```

---

## 💰 Quick Pricing Examples

### Example 1: Same-Day Local
- Distance: 20 miles
- Service: Local Delivery
- **Total**: $45 + (20 × $0.50) = **$55.00**

### Example 2: Multi-State Regional
- Distance: 300 miles
- Service: Regional
- **Total**: $75 + (300 × $0.35) = **$180.00**

### Example 3: Cross-Country FTL
- Distance: 1,500 miles
- Service: FTL
- **Total**: $2,500 + (1,500 × $1.50) = **$4,750.00**

### Example 4: Temperature-Controlled LTL
- Weight: 5,000 lbs
- Service: LTL + Temp Control
- **Total**: $50 + (5000 × $0.02) + $50 = **$150.00**

### Example 5: Bulk Regional (100 shipments)
- Service: Regional ($75 base)
- Volume: 100 (10% discount)
- **Unit Price**: $75 × 0.90 = $67.50
- **Total**: $67.50 × 100 = **$6,750.00**

---

## 🔌 API Endpoints

### Get All Products
```bash
GET /billing/products
GET /billing/products?category=shipping
```

### Get Product Details
```bash
GET /billing/products/{productId}
GET /billing/products/category/{category}
```

### Get Quote
```bash
POST /billing/quote
{
  "serviceType": "regional",
  "distance": 300,
  "weight": 5000,
  "isHazmat": false
}
```

### Get Bulk Pricing
```bash
POST /billing/bulk-pricing
{
  "serviceType": "regional",
  "volume": 250
}
```

### Create Checkout
```bash
POST /billing/stripe/checkout
{
  "productId": "prod_id",
  "quantity": 1,
  "successUrl": "...",
  "cancelUrl": "..."
}
```

### Get Pricing Summary
```bash
GET /billing/stripe/pricing-summary
```

---

## 🎯 Common Use Cases

### Startup (Low Volume)
**Recommended**: Pay-Per-Use + Basic Analytics
```
Usage: 50 shipments/month @ $25 avg = $1,250/month
Analytics: $9.99/month
Total: ~$1,260/month
```

### Growing Business (Medium Volume)
**Recommended**: Professional Plan + Fleet Tracking (5 vehicles)
```
Subscription: $299.99/month
Fleet Tracking: 5 × $9.99 = $49.95/month
Total: $349.94/month (~$4,200/year)
```

### Enterprise (High Volume)
**Recommended**: Enterprise Plan + All Add-ons
```
Subscription: $999.99/month
Driver App: 50 drivers × $4.99 = $249.50/month
Dispatch System: $499.99/month
Fleet Tracking: 20 vehicles × $9.99 = $199.80/month
Total: $1,949.28/month (~$23,400/year)
```

---

## 🚀 Getting Started

### Step 1: Choose Service Type
- Select shipping service (local, regional, cross-country, etc.)
- Identify any specialty requirements (hazmat, temp, etc.)

### Step 2: Get Quote
```bash
POST /billing/quote
# Returns itemized pricing
```

### Step 3: Verify in Stripe
```bash
GET /billing/stripe/pricing-summary
# Confirms product sync
```

### Step 4: Create Checkout
```bash
POST /billing/stripe/checkout
# Gets Stripe session URL
```

### Step 5: Payment
- Redirect to Stripe checkout
- Customer completes payment
- Webhook confirms order

---

## 📞 Support Resources

| Resource | Purpose | Link |
|----------|---------|------|
| **API Docs** | Technical integration | `/api/docs/billing` |
| **Catalog** | Full product list | `/billing/products` |
| **Pricing** | Current rates | `/billing/stripe/pricing-summary` |
| **Stripe Dashboard** | Payment admin | dashboard.stripe.com |

---

## ✅ Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Products Defined | ✅ | 45+ products in catalog |
| Stripe Sync | ✅ | All products synced |
| API Endpoints | ✅ | All routes implemented |
| Pricing Logic | ✅ | Distance + weight based |
| Discounts | ✅ | Volume-based tiers |
| Subscriptions | ✅ | Monthly/annual options |
| Checkout | ✅ | Stripe integration active |
| Documentation | ✅ | Complete with examples |

---

**Status**: 🚀 PRODUCTION READY  
**Last Updated**: January 1, 2026  
**Next Review**: Monthly
