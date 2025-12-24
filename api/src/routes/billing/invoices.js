const express = require("express");
const { authenticate, requireScope, auditLog } = require("../../middleware/security");

const router = express.Router();

const SAMPLE_INVOICES = [
  {
    id: "inv_1001",
    customer: "Acme Logistics",
    amount: 4900,
    currency: "USD",
    status: "paid",
    issuedAt: "2025-01-15T08:00:00Z",
    dueDate: "2025-01-30",
    paidAt: "2025-01-20T14:30:00Z",
  },
  {
    id: "inv_1002",
    customer: "Northwind Freight",
    amount: 12900,
    currency: "USD",
    status: "open",
    issuedAt: "2025-01-28T11:00:00Z",
    dueDate: "2025-02-12",
    paidAt: null,
  },
  {
    id: "inv_1003",
    customer: "Globex",
    amount: 7200,
    currency: "USD",
    status: "past_due",
    issuedAt: "2025-01-05T09:15:00Z",
    dueDate: "2025-01-20",
    paidAt: null,
  },
  {
    id: "inv_1004",
    customer: "Initech",
    amount: 18900,
    currency: "USD",
    status: "paid",
    issuedAt: "2024-12-18T10:00:00Z",
    dueDate: "2025-01-02",
    paidAt: "2024-12-28T18:00:00Z",
  },
  {
    id: "inv_1005",
    customer: "Acme Logistics",
    amount: 5600,
    currency: "USD",
    status: "open",
    issuedAt: "2025-02-01T12:00:00Z",
    dueDate: "2025-02-16",
    paidAt: null,
  },
  {
    id: "inv_1006",
    customer: "Umbrella Transport",
    amount: 3400,
    currency: "USD",
    status: "draft",
    issuedAt: "2025-02-10T08:30:00Z",
    dueDate: "2025-02-25",
    paidAt: null,
  },
  {
    id: "inv_1007",
    customer: "Wayne Freight",
    amount: 8900,
    currency: "USD",
    status: "past_due",
    issuedAt: "2024-12-30T07:20:00Z",
    dueDate: "2025-01-14",
    paidAt: null,
  },
  {
    id: "inv_1008",
    customer: "Stark Logistics",
    amount: 14400,
    currency: "USD",
    status: "paid",
    issuedAt: "2025-02-05T13:10:00Z",
    dueDate: "2025-02-20",
    paidAt: "2025-02-08T09:30:00Z",
  },
];

function parsePositiveInt(value, fallback) {
  const parsed = parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function buildSummary(invoices) {
  return invoices.reduce(
    (acc, invoice) => {
      if (invoice.status === "paid") {
        acc.paid += invoice.amount;
      } else {
        acc.outstanding += invoice.amount;
      }
      acc.total += invoice.amount;
      return acc;
    },
    { paid: 0, outstanding: 0, total: 0, currency: "USD" },
  );
}

router.get("/", authenticate, requireScope("billing:read"), auditLog, (req, res) => {
  const { status, page = "1", limit = "10" } = req.query;

  const pageNum = Math.max(1, parsePositiveInt(page, 1));
  const pageSize = Math.min(50, parsePositiveInt(limit, 10));

  const filtered = SAMPLE_INVOICES.filter((invoice) => {
    if (!status) return true;
    return invoice.status === status;
  });

  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const start = (pageNum - 1) * pageSize;
  const end = start + pageSize;
  const invoices = filtered.slice(start, end);

  res.json({
    ok: true,
    data: {
      invoices,
      pagination: {
        page: pageNum,
        limit: pageSize,
        total,
        totalPages,
      },
      summary: {
        ...buildSummary(filtered),
        lastUpdated: new Date().toISOString(),
      },
    },
  });
});

router.get("/:id", authenticate, requireScope("billing:read"), auditLog, (req, res) => {
  const invoice = SAMPLE_INVOICES.find((item) => item.id === req.params.id);

  if (!invoice) {
    return res.status(404).json({ ok: false, error: "Invoice not found" });
  }

  res.json({ ok: true, data: invoice });
});

module.exports = router;
