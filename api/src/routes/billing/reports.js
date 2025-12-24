const express = require("express");
const { authenticate, requireScope, auditLog } = require("../../middleware/security");

const router = express.Router();

const MONTHLY_REVENUE = [
  { month: "2024-10", mrr: 11800, invoices: 38, churnRate: 0.04 },
  { month: "2024-11", mrr: 12150, invoices: 41, churnRate: 0.038 },
  { month: "2024-12", mrr: 12980, invoices: 45, churnRate: 0.032 },
  { month: "2025-01", mrr: 13420, invoices: 48, churnRate: 0.029 },
  { month: "2025-02", mrr: 14100, invoices: 52, churnRate: 0.026 },
];

const PAYMENT_SPLIT = {
  stripe: { count: 68, total: 71200 },
  paypal: { count: 22, total: 22400 },
  manual: { count: 6, total: 8400 },
};

const USAGE_METRICS = {
  apiCalls: 128400,
  voiceMinutes: 940,
  aiOptimizations: 312,
  storageGb: 42,
};

router.get("/", authenticate, requireScope("billing:read"), auditLog, (_req, res) => {
  const latest = MONTHLY_REVENUE[MONTHLY_REVENUE.length - 1];
  const previous = MONTHLY_REVENUE[MONTHLY_REVENUE.length - 2];

  const growth = previous ? latest.mrr - previous.mrr : 0;
  const growthRate = previous ? +(growth / previous.mrr).toFixed(4) : 0;

  const averageChurn =
    MONTHLY_REVENUE.reduce((acc, item) => acc + item.churnRate, 0) /
    MONTHLY_REVENUE.length;

  res.json({
    ok: true,
    data: {
      summary: {
        month: latest.month,
        mrr: latest.mrr,
        arr: latest.mrr * 12,
        arpu: +(latest.mrr / 110).toFixed(2),
        churnRate: +averageChurn.toFixed(4),
        growth,
        growthRate,
        updatedAt: new Date().toISOString(),
      },
      revenue: {
        monthly: MONTHLY_REVENUE,
        payments: PAYMENT_SPLIT,
      },
      usage: USAGE_METRICS,
      forecasts: {
        nextMonthMrr: Math.round(latest.mrr * (1 + Math.max(growthRate, 0.01))),
        projectedInvoices: Math.round(latest.invoices * 1.05),
        retentionScore: Math.max(0, 100 - averageChurn * 100),
      },
    },
  });
});

module.exports = router;
