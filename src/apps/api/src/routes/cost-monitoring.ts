/**
 * Cost Monitoring and Alerting Dashboard
 * Track infrastructure costs across all services
 * Prevent budget overruns with real-time alerts
 */

import { Router, Request, Response } from "express";
import { authenticate, requireScope } from "../middleware/security";

const router = Router();

/**
 * Cost tracking data structure
 */
interface CostData {
  service: string;
  amount: number;
  currency: string;
  period: "hourly" | "daily" | "monthly";
  timestamp: Date;
}

interface BudgetAlert {
  service: string;
  budgetLimit: number;
  currentSpend: number;
  percentageUsed: number;
  alertLevel: "info" | "warning" | "critical";
}

// In-memory cost tracking (in production, use database)
const costData: CostData[] = [];
const budgetLimits = new Map<string, number>();

// Default budget limits ($USD per month)
budgetLimits.set("fly-io", 100);
budgetLimits.set("vercel", 50);
budgetLimits.set("aws-s3", 20);
budgetLimits.set("database", 50);
budgetLimits.set("redis", 20);
budgetLimits.set("sentry", 30);
budgetLimits.set("datadog", 50);
budgetLimits.set("total", 400);

/**
 * Record a cost entry
 */
function recordCost(
  service: string,
  amount: number,
  period: "hourly" | "daily" | "monthly" = "daily",
): void {
  costData.push({
    service,
    amount,
    currency: "USD",
    period,
    timestamp: new Date(),
  });

  // Keep only last 30 days
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const filtered = costData.filter((c) => c.timestamp > thirtyDaysAgo);
  costData.length = 0;
  costData.push(...filtered);
}

/**
 * Calculate costs for a service
 */
function calculateServiceCost(service: string, days: number = 30): number {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  return costData
    .filter((c) => c.service === service && c.timestamp > cutoff)
    .reduce((sum, c) => {
      // Normalize to monthly
      let monthly = c.amount;
      if (c.period === "hourly") monthly = c.amount * 24 * 30;
      if (c.period === "daily") monthly = c.amount * 30;
      return sum + monthly;
    }, 0);
}

/**
 * Get budget alerts
 */
function getBudgetAlerts(): BudgetAlert[] {
  const alerts: BudgetAlert[] = [];

  for (const [service, limit] of budgetLimits.entries()) {
    const currentSpend = calculateServiceCost(service);
    const percentageUsed = (currentSpend / limit) * 100;

    let alertLevel: "info" | "warning" | "critical" = "info";
    if (percentageUsed > 90) alertLevel = "critical";
    else if (percentageUsed > 80) alertLevel = "warning";

    if (percentageUsed > 75) {
      alerts.push({
        service,
        budgetLimit: limit,
        currentSpend,
        percentageUsed,
        alertLevel,
      });
    }
  }

  return alerts.sort((a, b) => b.percentageUsed - a.percentageUsed);
}

/**
 * GET /api/costs - Get cost overview
 */
router.get(
  "/",
  authenticate,
  requireScope("costs:read"),
  (req: Request, res: Response) => {
    const days = parseInt(req.query.days as string, 10) || 30;

    // Calculate costs per service
    const services = Array.from(new Set(costData.map((c) => c.service)));
    const breakdown = services.map((service) => ({
      service,
      cost: calculateServiceCost(service, days),
      budget: budgetLimits.get(service) || 0,
    }));

    // Total cost
    const totalCost = breakdown.reduce((sum, s) => sum + s.cost, 0);
    const totalBudget = budgetLimits.get("total") || 0;

    res.json({
      success: true,
      data: {
        period: `last ${days} days`,
        totalCost: totalCost.toFixed(2),
        totalBudget,
        percentageUsed: ((totalCost / totalBudget) * 100).toFixed(1),
        breakdown,
        alerts: getBudgetAlerts(),
      },
    });
  },
);

/**
 * POST /api/costs - Record new cost entry
 */
router.post(
  "/",
  authenticate,
  requireScope("costs:write"),
  (req: Request, res: Response) => {
    const { service, amount, period } = req.body;

    if (!service || typeof amount !== "number") {
      return res.status(400).json({ error: "Service and amount required" });
    }

    recordCost(service, amount, period);

    res.status(201).json({
      success: true,
      message: "Cost recorded",
    });
  },
);

/**
 * GET /api/costs/alerts - Get budget alerts
 */
router.get(
  "/alerts",
  authenticate,
  requireScope("costs:read"),
  (req: Request, res: Response) => {
    const alerts = getBudgetAlerts();

    res.json({
      success: true,
      data: alerts,
    });
  },
);

/**
 * PUT /api/costs/budget/:service - Update budget limit
 */
router.put(
  "/budget/:service",
  authenticate,
  requireScope("costs:admin"),
  (req: Request, res: Response) => {
    const { service } = req.params;
    const { limit } = req.body;

    if (typeof limit !== "number" || limit < 0) {
      return res.status(400).json({ error: "Valid budget limit required" });
    }

    budgetLimits.set(service, limit);

    res.json({
      success: true,
      message: `Budget for ${service} set to $${limit}`,
    });
  },
);

/**
 * GET /api/costs/forecast - Forecast monthly costs
 */
router.get(
  "/forecast",
  authenticate,
  requireScope("costs:read"),
  (req: Request, res: Response) => {
    // Calculate average daily spend
    const last7Days = costData.filter(
      (c) => c.timestamp > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
    );

    const dailyAverage =
      last7Days.reduce((sum, c) => {
        let daily = c.amount;
        if (c.period === "hourly") daily = c.amount * 24;
        if (c.period === "monthly") daily = c.amount / 30;
        return sum + daily;
      }, 0) / 7;

    // Forecast for rest of month
    const now = new Date();
    const daysInMonth = new Date(
      now.getFullYear(),
      now.getMonth() + 1,
      0,
    ).getDate();
    const daysRemaining = daysInMonth - now.getDate();
    const forecastedTotal = dailyAverage * daysInMonth;

    const totalBudget = budgetLimits.get("total") || 0;

    res.json({
      success: true,
      data: {
        dailyAverage: dailyAverage.toFixed(2),
        forecastedMonthly: forecastedTotal.toFixed(2),
        budget: totalBudget,
        willExceedBudget: forecastedTotal > totalBudget,
        daysRemaining,
      },
    });
  },
);

/**
 * GET /api/costs/trends - Get spending trends
 */
router.get(
  "/trends",
  authenticate,
  requireScope("costs:read"),
  (req: Request, res: Response) => {
    const days = parseInt(req.query.days as string, 10) || 30;

    // Group by day
    const trends: Record<string, number> = {};

    for (const cost of costData) {
      const dateKey = cost.timestamp.toISOString().split("T")[0];
      trends[dateKey] = (trends[dateKey] || 0) + cost.amount;
    }

    // Convert to array and sort
    const trendData = Object.entries(trends)
      .map(([date, amount]) => ({ date, amount }))
      .sort((a, b) => a.date.localeCompare(b.date))
      .slice(-days);

    res.json({
      success: true,
      data: trendData,
    });
  },
);

/**
 * Integrate with cloud providers to fetch real costs
 */

/**
 * Fly.io cost tracking
 */
async function fetchFlyCosts(): Promise<number> {
  try {
    // In production: Use Fly.io API to get actual usage
    // const response = await fetch('https://api.fly.io/v1/billing', {
    //   headers: { 'Authorization': `Bearer ${process.env.FLY_API_TOKEN}` }
    // });
    // const data = await response.json();
    // return data.current_usage;

    // For now, estimate based on machine count and hours
    const machineCount = parseInt(process.env.FLY_MACHINE_COUNT || "3", 10);
    const pricePerMachine = 0.02; // $0.02/hour for shared-cpu-1x
    return machineCount * pricePerMachine * 24; // Daily cost
  } catch (error) {
    console.error("Error fetching Fly.io costs:", error);
    return 0;
  }
}

/**
 * AWS S3 cost tracking
 */
async function fetchS3Costs(): Promise<number> {
  try {
    // In production: Use AWS Cost Explorer API
    // const AWS = require('aws-sdk');
    // const costexplorer = new AWS.CostExplorer({ region: 'us-east-1' });
    // const params = {
    //   TimePeriod: {
    //     Start: startDate,
    //     End: endDate
    //   },
    //   Granularity: 'DAILY',
    //   Metrics: ['UnblendedCost']
    // };
    // const data = await costexplorer.getCostAndUsage(params).promise();
    // return parseFloat(data.ResultsByTime[0].Total.UnblendedCost.Amount);

    // Estimate: $0.023 per GB + requests
    const storageGB = parseFloat(process.env.S3_STORAGE_GB || "100");
    return (storageGB * 0.023) / 30; // Daily cost
  } catch (error) {
    console.error("Error fetching S3 costs:", error);
    return 0;
  }
}

/**
 * Auto-sync costs from cloud providers (run daily)
 */
export async function syncCloudCosts(): Promise<void> {
  console.log("Syncing cloud provider costs...");

  const flyCost = await fetchFlyCosts();
  if (flyCost > 0) recordCost("fly-io", flyCost, "daily");

  const s3Cost = await fetchS3Costs();
  if (s3Cost > 0) recordCost("aws-s3", s3Cost, "daily");

  console.log(
    `✓ Synced costs: Fly.io $${flyCost.toFixed(2)}, S3 $${s3Cost.toFixed(2)}`,
  );
}

/**
 * Send cost alerts via webhook
 */
async function sendCostAlert(alert: BudgetAlert): Promise<void> {
  const webhookUrl = process.env.COST_ALERT_WEBHOOK;
  if (!webhookUrl) return;

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: `💰 Cost Alert: ${alert.service}`,
        level: alert.alertLevel,
        currentSpend: `$${alert.currentSpend.toFixed(2)}`,
        budget: `$${alert.budgetLimit}`,
        percentageUsed: `${alert.percentageUsed.toFixed(1)}%`,
      }),
    });
  } catch (error) {
    console.error("Failed to send cost alert:", error);
  }
}

/**
 * Check budgets and send alerts (run hourly)
 */
export async function checkBudgets(): Promise<void> {
  const alerts = getBudgetAlerts();

  for (const alert of alerts) {
    if (alert.alertLevel === "critical") {
      await sendCostAlert(alert);
    }
  }

  if (alerts.length > 0) {
    console.log(`⚠️ ${alerts.length} budget alerts detected`);
  }
}

export default router;

/**
 * Usage:
 *
 * // In main.ts
 * import costMonitoringRouter, { syncCloudCosts, checkBudgets } from './routes/cost-monitoring';
 * app.use('/api/costs', costMonitoringRouter);
 *
 * // Schedule syncing (daily at 2 AM)
 * cron.schedule('0 2 * * *', syncCloudCosts);
 *
 * // Schedule budget checks (hourly)
 * cron.schedule('0 * * * *', checkBudgets);
 *
 * // Set budget limits
 * PUT /api/costs/budget/fly-io
 * { "limit": 150 }
 *
 * // View dashboard
 * GET /api/costs
 * {
 *   "totalCost": "245.50",
 *   "totalBudget": 400,
 *   "percentageUsed": "61.4",
 *   "breakdown": [...]
 * }
 *
 * Expected benefits:
 * - Prevent budget overruns
 * - Real-time cost visibility
 * - Automatic alerts
 * - Cost forecasting
 * - Trend analysis
 */
