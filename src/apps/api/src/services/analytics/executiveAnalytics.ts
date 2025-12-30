// Phase 4: Executive Analytics & Business Intelligence Service
// Real-time dashboards for executive decision-making

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

interface ExecutiveDashboard {
  generatedAt: Date;
  period: "24h" | "7d" | "30d" | "ytd";
  revenue: {
    total: number;
    daily: number[];
    growth: number; // percentage
    target: number;
    achievement: number; // percentage
    forecast: {
      next7Days: number;
      next30Days: number;
    };
  };
  operations: {
    shipmentsProcessed: number;
    onTimeDeliveryRate: number;
    averageDeliveryTime: number; // minutes
    driverUtilization: number; // percentage
    vehicleUtilization: number; // percentage
    costPerShipment: number;
  };
  efficiency: {
    marginPercentage: number;
    revenuePerDriver: number;
    revenuePerVehicle: number;
    costPerMile: number;
    roi: number;
  };
  growth: {
    customerCount: number;
    driverCount: number;
    vehicleCount: number;
    marketShare: number; // estimated
    trends: {
      customersGrowth: number;
      driversGrowth: number;
      shipmentsGrowth: number;
    };
  };
  alerts: {
    criticalIssues: string[];
    warnings: string[];
    opportunities: string[];
  };
}

/**
 * Calculate revenue metrics
 */
async function getRevenueMetrics(
  periodDays: number,
): Promise<ExecutiveDashboard["revenue"]> {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - periodDays);

  // Get total revenue
  const shipments = await prisma.shipment.findMany({
    where: {
      createdAt: {
        gte: startDate,
      },
      status: "completed",
    },
    select: {
      price: true,
      createdAt: true,
    },
  });

  const total = shipments.reduce((sum, s) => sum + (s.price || 0), 0);

  // Get daily breakdown
  const dailyRevenue: number[] = [];
  for (let i = 0; i < periodDays; i++) {
    const day = new Date();
    day.setDate(day.getDate() - i);
    const dayStart = new Date(day.setHours(0, 0, 0, 0));
    const dayEnd = new Date(day.setHours(23, 59, 59, 999));

    const dayTotal = shipments
      .filter((s) => s.createdAt >= dayStart && s.createdAt <= dayEnd)
      .reduce((sum, s) => sum + (s.price || 0), 0);

    dailyRevenue.push(dayTotal);
  }

  // Calculate growth vs previous period
  const previousStartDate = new Date(startDate);
  previousStartDate.setDate(previousStartDate.getDate() - periodDays);

  const previousShipments = await prisma.shipment.findMany({
    where: {
      createdAt: {
        gte: previousStartDate,
        lte: startDate,
      },
      status: "completed",
    },
    select: { price: true },
  });

  const previousTotal = previousShipments.reduce(
    (sum, s) => sum + (s.price || 0),
    0,
  );
  const growth =
    previousTotal === 0 ? 0 : ((total - previousTotal) / previousTotal) * 100;

  // Forecast (simple linear)
  const avgDaily = total / periodDays;
  const forecast = {
    next7Days: avgDaily * 7,
    next30Days: avgDaily * 30,
  };

  const target = avgDaily * periodDays * 1.2; // 20% target increase
  const achievement = (total / target) * 100;

  return {
    total,
    daily: dailyRevenue,
    growth,
    target,
    achievement,
    forecast,
  };
}

/**
 * Calculate operational metrics
 */
async function getOperationalMetrics(
  periodDays: number,
): Promise<ExecutiveDashboard["operations"]> {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - periodDays);

  // Shipments processed
  const shipments = await prisma.shipment.findMany({
    where: {
      createdAt: {
        gte: startDate,
      },
    },
    include: {
      driver: true,
      vehicle: true,
    },
  });

  const shipmentsProcessed = shipments.length;

  // On-time delivery rate
  const onTimeCount = shipments.filter((s) => {
    const scheduled = s.scheduledDeliveryTime;
    const actual = s.completedAt;
    return scheduled && actual && actual <= scheduled;
  }).length;

  const onTimeDeliveryRate =
    shipmentsProcessed === 0 ? 0 : (onTimeCount / shipmentsProcessed) * 100;

  // Average delivery time
  const deliveryTimes = shipments
    .filter((s) => s.startedAt && s.completedAt)
    .map(
      (s) => (s.completedAt!.getTime() - s.startedAt!.getTime()) / (1000 * 60),
    );

  const averageDeliveryTime =
    deliveryTimes.length === 0
      ? 0
      : deliveryTimes.reduce((a, b) => a + b, 0) / deliveryTimes.length;

  // Driver utilization
  const drivers = await prisma.driver.findMany({
    include: {
      shipments: {
        where: {
          createdAt: { gte: startDate },
        },
      },
      sessions: {
        where: {
          startTime: { gte: startDate },
        },
      },
    },
  });

  const driverUtilization =
    drivers.length === 0
      ? 0
      : (drivers.filter((d) => d.shipments.length > 0).length /
          drivers.length) *
        100;

  // Vehicle utilization
  const vehicles = await prisma.vehicle.findMany({
    include: {
      shipments: {
        where: {
          createdAt: { gte: startDate },
        },
      },
    },
  });

  const vehicleUtilization =
    vehicles.length === 0
      ? 0
      : (vehicles.filter((v) => v.shipments.length > 0).length /
          vehicles.length) *
        100;

  // Cost per shipment
  const totalOperatingCost = 5000; // Placeholder
  const costPerShipment =
    shipmentsProcessed === 0 ? 0 : totalOperatingCost / shipmentsProcessed;

  return {
    shipmentsProcessed,
    onTimeDeliveryRate,
    averageDeliveryTime,
    driverUtilization,
    vehicleUtilization,
    costPerShipment,
  };
}

/**
 * Calculate efficiency metrics
 */
async function getEfficiencyMetrics(
  periodDays: number,
  revenue: number,
  ops: ExecutiveDashboard["operations"],
): Promise<ExecutiveDashboard["efficiency"]> {
  // Margin
  const totalCost = ops.costPerShipment * ops.shipmentsProcessed;
  const marginPercentage = ((revenue - totalCost) / revenue) * 100;

  // Revenue per driver/vehicle
  const drivers = await prisma.driver.count({ where: { isActive: true } });
  const vehicles = await prisma.vehicle.count({ where: { isActive: true } });

  const revenuePerDriver = drivers === 0 ? 0 : revenue / drivers;
  const revenuePerVehicle = vehicles === 0 ? 0 : revenue / vehicles;

  // Cost per mile (estimate)
  const estimatedMiles = ops.shipmentsProcessed * 15; // avg 15 miles per shipment
  const costPerMile = estimatedMiles === 0 ? 0 : totalCost / estimatedMiles;

  // ROI
  const investmentAmount = 500000; // Placeholder
  const roi = ((revenue - totalCost) / investmentAmount) * 100;

  return {
    marginPercentage,
    revenuePerDriver,
    revenuePerVehicle,
    costPerMile,
    roi,
  };
}

/**
 * Calculate growth metrics
 */
async function getGrowthMetrics(
  periodDays: number,
): Promise<ExecutiveDashboard["growth"]> {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - periodDays);
  const previousStartDate = new Date(startDate);
  previousStartDate.setDate(previousStartDate.getDate() - periodDays);

  // Current period
  const customers = await prisma.customer.count({
    where: { createdAt: { gte: startDate } },
  });
  const drivers = await prisma.driver.count({
    where: { createdAt: { gte: startDate } },
  });
  const vehicles = await prisma.vehicle.count({
    where: { createdAt: { gte: startDate } },
  });

  // Previous period
  const previousCustomers = await prisma.customer.count({
    where: { createdAt: { gte: previousStartDate, lt: startDate } },
  });
  const previousDrivers = await prisma.driver.count({
    where: { createdAt: { gte: previousStartDate, lt: startDate } },
  });
  const previousVehicles = await prisma.vehicle.count({
    where: { createdAt: { gte: previousStartDate, lt: startDate } },
  });

  // Growth rates
  const customersGrowth =
    previousCustomers === 0
      ? 0
      : ((customers - previousCustomers) / previousCustomers) * 100;
  const driversGrowth =
    previousDrivers === 0
      ? 0
      : ((drivers - previousDrivers) / previousDrivers) * 100;

  const shipmentsGrowth = 12; // Placeholder

  // Market share (estimated)
  const totalMarketShipments = 100000; // Placeholder
  const ourShipments = await prisma.shipment.count({
    where: { createdAt: { gte: startDate } },
  });
  const marketShare = (ourShipments / totalMarketShipments) * 100;

  return {
    customerCount: customers,
    driverCount: drivers,
    vehicleCount: vehicles,
    marketShare,
    trends: {
      customersGrowth,
      driversGrowth,
      shipmentsGrowth,
    },
  };
}

/**
 * Generate alerts
 */
function generateAlerts(
  revenue: ExecutiveDashboard["revenue"],
  ops: ExecutiveDashboard["operations"],
  eff: ExecutiveDashboard["efficiency"],
): ExecutiveDashboard["alerts"] {
  const criticalIssues: string[] = [];
  const warnings: string[] = [];
  const opportunities: string[] = [];

  // Critical issues
  if (ops.onTimeDeliveryRate < 85) {
    criticalIssues.push(
      `On-time delivery rate at ${ops.onTimeDeliveryRate.toFixed(1)}% (target: 95%)`,
    );
  }
  if (eff.marginPercentage < 10) {
    criticalIssues.push(
      `Operating margin at ${eff.marginPercentage.toFixed(1)}% (target: 15%)`,
    );
  }
  if (ops.driverUtilization < 50) {
    criticalIssues.push(
      `Driver utilization at ${ops.driverUtilization.toFixed(1)}% (target: 80%)`,
    );
  }

  // Warnings
  if (revenue.growth < 0) {
    warnings.push(`Revenue declining at ${revenue.growth.toFixed(1)}% YoY`);
  }
  if (ops.averageDeliveryTime > 60) {
    warnings.push(
      `Average delivery time at ${ops.averageDeliveryTime.toFixed(0)} minutes (target: <45)`,
    );
  }

  // Opportunities
  if (ops.driverUtilization < 75) {
    opportunities.push(
      `Increase driver utilization for ${((75 - ops.driverUtilization) * revenue.total * 0.001).toFixed(0)} revenue potential`,
    );
  }
  if (eff.costPerMile > 2) {
    opportunities.push("Route optimization could reduce costs by 10-15%");
  }

  return { criticalIssues, warnings, opportunities };
}

/**
 * Generate executive dashboard
 */
export async function generateExecutiveDashboard(
  period: "24h" | "7d" | "30d" | "ytd" = "30d",
): Promise<ExecutiveDashboard> {
  const periodDays =
    period === "24h" ? 1 : period === "7d" ? 7 : period === "30d" ? 30 : 365;

  // Get all metrics in parallel
  const [revenue, ops] = await Promise.all([
    getRevenueMetrics(periodDays),
    getOperationalMetrics(periodDays),
  ]);

  const eff = await getEfficiencyMetrics(periodDays, revenue.total, ops);
  const growth = await getGrowthMetrics(periodDays);
  const alerts = generateAlerts(revenue, ops, eff);

  return {
    generatedAt: new Date(),
    period,
    revenue,
    operations: ops,
    efficiency: eff,
    growth,
    alerts,
  };
}

/**
 * Export dashboard data
 */
export async function exportDashboard(
  format: "json" | "csv" | "pdf" = "json",
  period: "24h" | "7d" | "30d" | "ytd" = "30d",
): Promise<string> {
  const dashboard = await generateExecutiveDashboard(period);

  if (format === "json") {
    return JSON.stringify(dashboard, null, 2);
  }

  if (format === "csv") {
    // Convert to CSV format
    const rows: string[] = [];
    rows.push("Metric,Value,Target,Status");
    rows.push(
      `Revenue,$${dashboard.revenue.total.toFixed(2)},$${dashboard.revenue.target.toFixed(2)},${dashboard.revenue.achievement > 100 ? "Green" : "Red"}`,
    );
    rows.push(
      `On-Time Delivery,${dashboard.operations.onTimeDeliveryRate.toFixed(1)}%,95%,${dashboard.operations.onTimeDeliveryRate >= 95 ? "Green" : "Red"}`,
    );
    return rows.join("\n");
  }

  // PDF format would require additional library
  return JSON.stringify(dashboard);
}

/**
 * Subscribe to real-time updates
 */
export async function subscribeToUpdates(
  callback: (dashboard: ExecutiveDashboard) => void,
  intervalMinutes: number = 15,
): Promise<() => void> {
  const interval = setInterval(
    async () => {
      const dashboard = await generateExecutiveDashboard();
      callback(dashboard);
    },
    intervalMinutes * 60 * 1000,
  );

  // Return unsubscribe function
  return () => clearInterval(interval);
}

export default {
  generateExecutiveDashboard,
  exportDashboard,
  subscribeToUpdates,
};
