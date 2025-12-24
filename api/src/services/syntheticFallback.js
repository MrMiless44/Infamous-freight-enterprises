const SUPPORTED_CURRENCIES = ["USD", "EUR", "GBP", "CAD", "AUD"];

const severityWeights = {
  error: 35,
  warning: 15,
  info: 5,
};

function calculateConfidence(issues) {
  if (!issues.length) return 0.92;

  const totalPenalty = issues.reduce(
    (sum, issue) => sum + (severityWeights[issue.severity] || 10),
    0,
  );
  const normalizedPenalty = Math.min(100, totalPenalty);
  const confidence = Math.max(0.4, 1 - normalizedPenalty / 120);
  return Number(confidence.toFixed(2));
}

function auditInvoice(payload = {}, meta = {}, context = {}) {
  const invoice = payload.invoice || {};
  const ruleset = payload.ruleset || "standard_freight";
  const issues = [];

  const amount = Number(invoice.totalAmount);
  if (!Number.isFinite(amount) || amount <= 0) {
    issues.push({
      code: "invalid_total",
      field: "invoice.totalAmount",
      severity: "error",
      message: "Total amount must be a positive number.",
    });
  } else if (amount > 50000) {
    issues.push({
      code: "high_value",
      field: "invoice.totalAmount",
      severity: "warning",
      message: "High-value invoice. Verify contract and approval limits.",
    });
  }

  if (!invoice.reference) {
    issues.push({
      code: "missing_reference",
      field: "invoice.reference",
      severity: "error",
      message: "Invoice reference is required for reconciliation.",
    });
  }

  if (!invoice.carrier) {
    issues.push({
      code: "missing_carrier",
      field: "invoice.carrier",
      severity: "warning",
      message: "Carrier name is missing. Confirm the bill of lading source.",
    });
  }

  if (!invoice.currency) {
    issues.push({
      code: "missing_currency",
      field: "invoice.currency",
      severity: "error",
      message: "Currency is required to audit totals.",
    });
  } else if (!SUPPORTED_CURRENCIES.includes(invoice.currency)) {
    issues.push({
      code: "unsupported_currency",
      field: "invoice.currency",
      severity: "warning",
      message: `Currency ${invoice.currency} is not in the standard freight policy list.`,
    });
  }

  const status = issues.some((issue) => issue.severity === "error")
    ? "rejected"
    : issues.length
      ? "needs_review"
      : "approved";

  const confidence = calculateConfidence(issues);
  const recommendations = [
    "Verify bill of lading against the invoice reference.",
    "Confirm applied fuel surcharge and accessorial fees match contract terms.",
    "Cross-check carrier billing contact before releasing payment.",
  ];

  return {
    provider: "synthetic",
    source: "offline-fallback",
    command: "audit_invoice",
    ruleset,
    status,
    confidence,
    issues,
    summary:
      status === "approved"
        ? "Invoice passes standard freight checks."
        : "Invoice flagged for review under standard freight checks.",
    recommendations,
    meta: { ...meta, ...context },
    invoice: {
      carrier: invoice.carrier || null,
      reference: invoice.reference || null,
      totalAmount: Number.isFinite(amount) ? amount : null,
      currency: invoice.currency || null,
    },
  };
}

function defaultSynthetic(command, payload = {}, meta = {}, context = {}) {
  return {
    provider: "synthetic",
    source: "offline-fallback",
    command,
    summary: `Synthetic response generated locally for '${command}'.`,
    confidence: 0.72,
    echo: {
      payload,
      meta: { ...meta, ...context },
    },
    meta: { ...meta, ...context },
  };
}

function generateSyntheticResponse(
  command,
  payload = {},
  meta = {},
  context = {},
) {
  if (command === "audit_invoice") {
    return auditInvoice(payload, meta, context);
  }

  return defaultSynthetic(command, payload, meta, context);
}

module.exports = {
  auditInvoice,
  generateSyntheticResponse,
};
