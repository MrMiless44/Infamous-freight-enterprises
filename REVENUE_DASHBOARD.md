# 💰 Revenue Dashboard

**Status**: Ready to Implement  
**Metrics**: MRR, ARR, Churn, Customer Lifetime Value, Growth Rate

---

## 📊 Dashboard Overview

**Key Metrics Display:**

```
┌─────────────────────────────────────────┐
│  MONTHLY RECURRING REVENUE              │
│  $12,450 ↑ 18% vs last month            │
│  Projected Annual: $149,400             │
├─────────────────────────────────────────┤
│  ACTIVE SUBSCRIPTIONS                   │
│  247 customers ↑ 12 new this month      │
│  Churn Rate: 2.1% (healthy < 5%)        │
├─────────────────────────────────────────┤
│  CUSTOMER LIFETIME VALUE                │
│  $2,850 avg ↑ 8% vs last month          │
│  Top customer value: $18,500             │
├─────────────────────────────────────────┤
│  FAILED PAYMENTS                        │
│  8 failed (3.2% of total)               │
│  Recovery action: 5/8 retried            │
└─────────────────────────────────────────┘
```

---

## 🔧 Dashboard Backend

### Metrics Calculation

```javascript
// api/src/services/metrics.js
const db = require('../db');

class MetricsService {
  // Monthly Recurring Revenue (MRR)
  async calculateMRR() {
    const activeSubscriptions = await db.subscriptions.findMany({
      where: { status: 'active' },
      include: { plan: true }
    });

    const mrr = activeSubscriptions.reduce((sum, sub) => {
      return sum + parseFloat(sub.plan.monthlyPrice);
    }, 0);

    return mrr;
  }

  // Annual Recurring Revenue (ARR)
  async calculateARR() {
    const mrr = await this.calculateMRR();
    return mrr * 12;
  }

  // Churn Rate (% customers lost per month)
  async calculateChurnRate() {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);

    const activeStart = await db.subscriptions.count({
      where: {
        status: 'active',
        created_at: { $lt: startOfMonth }
      }
    });

    const cancelled = await db.subscriptions.count({
      where: {
        status: 'cancelled',
        cancelled_at: {
          $gte: startOfMonth,
          $lt: now
        }
      }
    });

    return cancelled / activeStart;
  }

  // Net Revenue Retention (growth accounting)
  async calculateNRR() {
    const now = new Date();
    const lastMonth = new Date(now.setMonth(now.getMonth() - 1));

    const mrrLastMonth = await this.calculateMRRAt(lastMonth);
    const currentMRR = await this.calculateMRR();
    
    // Include downgrades/upgrades/expansions
    const upgrades = await db.subscriptions.sum('expansion_revenue', {
      where: { updated_at: { $gte: lastMonth } }
    });

    const downgrades = await db.subscriptions.sum('contraction_revenue', {
      where: { updated_at: { $gte: lastMonth } }
    });

    return ((currentMRR + upgrades - downgrades) / mrrLastMonth) * 100;
  }

  // Customer Lifetime Value (LTV)
  async calculateLTV() {
    const customers = await db.customers.findMany({
      include: { subscriptions: true }
    });

    const ltv = customers.reduce((sum, customer) => {
      const monthsPaid = customer.subscriptions.length;
      const avgValue = customer.subscriptions.reduce((s, sub) => 
        s + parseFloat(sub.plan.monthlyPrice), 0
      ) / customer.subscriptions.length;
      
      return sum + (monthsPaid * avgValue);
    }, 0) / customers.length;

    return ltv;
  }

  // Customer Acquisition Cost (CAC)
  async calculateCAC() {
    const marketingSpend = 2500; // hardcoded for demo
    const newCustomersThisMonth = await db.customers.count({
      where: {
        created_at: {
          $gte: new Date(new Date().setDate(1))
        }
      }
    });

    return marketingSpend / newCustomersThisMonth;
  }

  // CAC Payback Period (months)
  async calculateCACPayback() {
    const cac = await this.calculateCAC();
    const grossprofitMargin = 0.70; // 70% gross margin
    const monthlyArpu = await this.calculateARPU();

    return cac / (monthlyArpu * grossprofitMargin);
  }

  // Average Revenue Per User (ARPU)
  async calculateARPU() {
    const mrr = await this.calculateMRR();
    const activeCount = await db.subscriptions.count({
      where: { status: 'active' }
    });

    return mrr / activeCount;
  }

  // Get comprehensive dashboard data
  async getDashboard() {
    const [mrr, arr, churn, ltv, cac, nrr, arpu] = await Promise.all([
      this.calculateMRR(),
      this.calculateARR(),
      this.calculateChurnRate(),
      this.calculateLTV(),
      this.calculateCAC(),
      this.calculateNRR(),
      this.calculateARPU()
    ]);

    return {
      mrr: Math.round(mrr * 100) / 100,
      arr: Math.round(arr * 100) / 100,
      churnRate: Math.round(churn * 10000) / 100 + '%',
      nrr: Math.round(nrr * 100) / 100 + '%',
      ltv: Math.round(ltv * 100) / 100,
      cac: Math.round(cac * 100) / 100,
      cacPayback: (await this.calculateCACPayback()).toFixed(1) + ' months',
      arpu: Math.round(arpu * 100) / 100,
      activeSubscriptions: await db.subscriptions.count({
        where: { status: 'active' }
      }),
      failedPayments: await db.payments.count({
        where: { status: 'failed' }
      })
    };
  }

  // Get revenue trend (last 12 months)
  async getRevenueTrend() {
    const months = [];
    const revenues = [];

    for (let i = 11; i >= 0; i--) {
      const date = new Date();
      date.setMonth(date.getMonth() - i);
      
      const mrr = await this.calculateMRRAt(date);
      months.push(date.toLocaleDateString('en-US', { month: 'short', year: '2-digit' }));
      revenues.push(mrr);
    }

    return { months, revenues };
  }

  // Get customer acquisition trend
  async getAcquisitionTrend() {
    const months = [];
    const acquired = [];

    for (let i = 11; i >= 0; i--) {
      const startDate = new Date();
      startDate.setMonth(startDate.getMonth() - i);
      startDate.setDate(1);

      const endDate = new Date(startDate);
      endDate.setMonth(endDate.getMonth() + 1);

      const count = await db.customers.count({
        where: {
          created_at: { $gte: startDate, $lt: endDate }
        }
      });

      months.push(startDate.toLocaleDateString('en-US', { month: 'short', year: '2-digit' }));
      acquired.push(count);
    }

    return { months, acquired };
  }

  async calculateMRRAt(date) {
    const subscriptions = await db.subscriptions.findMany({
      where: {
        status: 'active',
        created_at: { $lte: date },
        $or: [
          { cancelled_at: null },
          { cancelled_at: { $gt: date } }
        ]
      },
      include: { plan: true }
    });

    return subscriptions.reduce((sum, sub) => 
      sum + parseFloat(sub.plan.monthlyPrice), 0
    );
  }
}

module.exports = new MetricsService();
```

### API Endpoint

```javascript
// api/src/routes/dashboard.js
const express = require('express');
const { authenticate, requireScope } = require('../middleware/security');
const metricsService = require('../services/metrics');

const router = express.Router();

// Public dashboard stats
router.get('/api/dashboard/stats', async (req, res, next) => {
  try {
    const stats = await metricsService.getDashboard();
    res.json({ success: true, data: stats });
  } catch (err) {
    next(err);
  }
});

// Authenticated: detailed analytics
router.get('/api/dashboard/analytics', authenticate, requireScope('analytics:read'), async (req, res, next) => {
  try {
    const [dashboard, revenueTrend, acquisitionTrend] = await Promise.all([
      metricsService.getDashboard(),
      metricsService.getRevenueTrend(),
      metricsService.getAcquisitionTrend()
    ]);

    res.json({
      success: true,
      data: {
        dashboard,
        revenueTrend,
        acquisitionTrend
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
```

---

## 🎨 Dashboard Frontend

### React Component

```typescript
// web/components/RevenueDashboard.tsx
import { useState, useEffect } from 'react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

export default function RevenueDashboard() {
  const [stats, setStats] = useState(null);
  const [trend, setTrend] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      const response = await fetch('/api/dashboard/analytics');
      const data = await response.json();
      setStats(data.data.dashboard);
      setTrend(data.data.revenueTrend);
      setLoading(false);
    };

    fetchData();
  }, []);

  if (loading) return <div>Loading...</div>;

  return (
    <div className="p-8 bg-gray-50">
      <h1 className="text-4xl font-bold mb-8">Revenue Dashboard</h1>

      {/* Key Metrics */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <MetricCard
          label="Monthly Recurring Revenue"
          value={`$${stats.mrr.toLocaleString()}`}
          change="+18%"
          positive
        />
        <MetricCard
          label="Active Subscriptions"
          value={stats.activeSubscriptions}
          change="+12"
          positive
        />
        <MetricCard
          label="Churn Rate"
          value={stats.churnRate}
          change="-0.3%"
          positive
        />
        <MetricCard
          label="Customer LTV"
          value={`$${stats.ltv.toLocaleString()}`}
          change="+8%"
          positive
        />
      </div>

      {/* Revenue Trend */}
      <div className="bg-white p-6 rounded-lg shadow mb-8">
        <h2 className="text-2xl font-bold mb-4">Revenue Trend (12 Months)</h2>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={trend.months.map((month, i) => ({
            month,
            revenue: trend.revenues[i]
          }))}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="month" />
            <YAxis />
            <Tooltip formatter={(value) => `$${value.toLocaleString()}`} />
            <Line type="monotone" dataKey="revenue" stroke="#8884d8" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Advanced Metrics */}
      <div className="grid grid-cols-3 gap-4">
        <MetricCard label="CAC" value={`$${stats.cac}`} />
        <MetricCard label="CAC Payback" value={stats.cacPayback} />
        <MetricCard label="NRR" value={stats.nrr} />
      </div>
    </div>
  );
}

function MetricCard({ label, value, change, positive }) {
  return (
    <div className="bg-white p-6 rounded-lg shadow">
      <p className="text-gray-600 text-sm mb-2">{label}</p>
      <p className="text-3xl font-bold">{value}</p>
      {change && (
        <p className={`text-sm mt-2 ${positive ? 'text-green-600' : 'text-red-600'}`}>
          {change} vs last month
        </p>
      )}
    </div>
  );
}
```

---

## 📈 Metrics Glossary

| Metric | Formula | Target | Meaning |
|--------|---------|--------|---------|
| **MRR** | Total recurring revenue from active subscriptions | +15% MoM | Monthly predictable revenue |
| **ARR** | MRR × 12 | $100K+ | Annual run rate |
| **Churn** | (Canceled / Starting Active) × 100 | < 5% | % customers lost per month |
| **NRR** | (MRR + Expansion - Contraction) / Prev MRR × 100 | > 100% | Organic growth rate |
| **LTV** | Average customer lifetime value | 3x CAC | Total revenue per customer |
| **CAC** | Sales & Marketing spend / New Customers | $200-500 | Cost to acquire each customer |
| **CAC Payback** | CAC / (ARPU × Gross Margin) | < 12 months | Months to recover acquisition cost |
| **ARPU** | MRR / Active Subscriptions | +5% QoQ | Revenue per active user |

---

## 🎯 Growth Milestones

```
Month 1:  MRR $2,900   (Starter plan only)
Month 3:  MRR $8,700   (Multi-tier adoption)
Month 6:  MRR $21,600  (Word of mouth growth)
Month 12: MRR $68,000  (Professional word of mouth + marketing)

Triggers for scaling:
- MRR > $10K → Hire first support person
- MRR > $25K → Hire first salesperson
- MRR > $50K → Build dedicated features team
- MRR > $100K → Series A readiness
```

---

## 🔔 Alert System

**Set up automatic alerts for:**

```javascript
// Email alerts for concerning metrics
const alerts = [
  { metric: 'churn', threshold: 0.05, action: 'email' }, // > 5% churn
  { metric: 'failed_payments', threshold: 20, action: 'sms' }, // > 20 failed
  { metric: 'mrr_decline', threshold: 0.10, action: 'slack' }, // > 10% decline
  { metric: 'nrr', threshold: 0.95, action: 'email' }, // < 95% (declining)
];

// Sent to: billing@infamousfreight.com, #billing Slack channel
```

---

## 📊 Integration with Analytics

**Send events to Google Analytics:**

```javascript
gtag('event', 'subscription_created', {
  plan: 'professional',
  value: 99,
  currency: 'USD'
});

gtag('event', 'subscription_cancelled', {
  plan: 'starter',
  lifetime_value: 290
});
```

---

## ✅ Implementation Checklist

```
Backend:
  [ ] Metrics service created
  [ ] All calculation methods implemented
  [ ] Dashboard API endpoint created
  [ ] Authentication required
  [ ] Caching for performance (1 hour)

Frontend:
  [ ] Dashboard component created
  [ ] Charts rendering correctly
  [ ] Real-time metric updates
  [ ] Mobile responsive design
  [ ] Performance optimized

Monitoring:
  [ ] Alert system configured
  [ ] Critical metrics defined
  [ ] Slack notifications working
  [ ] Email alerts configured

Testing:
  [ ] MRR calculation accurate
  [ ] Churn calculation correct
  [ ] LTV realistic
  [ ] Trend charts updating
  [ ] Performance < 500ms
```

---

**Status**: 🟢 Ready to Deploy  
**Setup Time**: 3-4 hours  
**Updates**: Real-time (cached 1 hour)  
**Impact**: Know your business health instantly

