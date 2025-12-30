/**
 * Phase 3 Feature 6: Business Metrics Dashboard
 * Real-time KPI aggregation and forecasting for executives
 *
 * Expected Impact:
 * - 20% improvement in operational efficiency
 * - Data-driven decision making
 * - Predictive insights for resource planning
 */

export interface MetricData {
  metricType: string;
  value: number;
  previousValue?: number;
  changePercent?: number;
  period: "daily" | "weekly" | "monthly" | "quarterly" | "yearly";
  metadata?: any;
}

export interface DashboardMetrics {
  revenue: MetricData;
  efficiency: MetricData;
  customerSatisfaction: MetricData;
  driverRetention: MetricData;
  deliveryPerformance: MetricData;
  costPerDelivery: MetricData;
  utilization: MetricData;
}

export interface Forecast {
  metricType: string;
  predictions: Array<{
    date: Date;
    predictedValue: number;
    confidence: number;
  }>;
}

export class BusinessMetricsEngine {
  /**
   * Calculate revenue metrics
   */
  calculateRevenueMetrics(loads: any[]): MetricData {
    const currentRevenue = loads.reduce((sum, load) => sum + load.rate, 0);
    const previousRevenue = loads
      .filter(
        (load) =>
          load.completedAt < new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      )
      .reduce((sum, load) => sum + load.rate, 0);

    const changePercent =
      previousRevenue > 0
        ? ((currentRevenue - previousRevenue) / previousRevenue) * 100
        : 0;

    return {
      metricType: "revenue",
      value: currentRevenue,
      previousValue: previousRevenue,
      changePercent: Math.round(changePercent * 100) / 100,
      period: "monthly",
      metadata: {
        loadCount: loads.length,
        avgRevenuePerLoad: loads.length > 0 ? currentRevenue / loads.length : 0,
      },
    };
  }

  /**
   * Calculate operational efficiency
   */
  calculateEfficiency(loads: any[]): MetricData {
    const completedLoads = loads.filter((load) => load.status === "DELIVERED");
    const onTimeLoads = completedLoads.filter(
      (load) =>
        new Date(load.actualDeliveryTime) <= new Date(load.deliveryTime),
    );

    const efficiencyRate =
      completedLoads.length > 0
        ? (onTimeLoads.length / completedLoads.length) * 100
        : 0;

    return {
      metricType: "efficiency",
      value: Math.round(efficiencyRate * 100) / 100,
      period: "monthly",
      metadata: {
        totalCompleted: completedLoads.length,
        onTime: onTimeLoads.length,
        delayed: completedLoads.length - onTimeLoads.length,
      },
    };
  }

  /**
   * Calculate customer satisfaction score
   */
  calculateCustomerSatisfaction(loads: any[]): MetricData {
    const ratedLoads = loads.filter((load) => load.rating != null);
    const avgRating =
      ratedLoads.length > 0
        ? ratedLoads.reduce((sum, load) => sum + load.rating, 0) /
          ratedLoads.length
        : 0;

    const satisfactionScore = (avgRating / 5) * 100;

    const ratingDistribution = {
      5: ratedLoads.filter((l) => l.rating === 5).length,
      4: ratedLoads.filter((l) => l.rating === 4).length,
      3: ratedLoads.filter((l) => l.rating === 3).length,
      2: ratedLoads.filter((l) => l.rating === 2).length,
      1: ratedLoads.filter((l) => l.rating === 1).length,
    };

    return {
      metricType: "customer-satisfaction",
      value: Math.round(satisfactionScore * 100) / 100,
      period: "monthly",
      metadata: {
        avgRating: Math.round(avgRating * 100) / 100,
        totalRatings: ratedLoads.length,
        ratingDistribution,
      },
    };
  }

  /**
   * Calculate driver retention rate
   */
  calculateDriverRetention(drivers: any[]): MetricData {
    const activeDrivers = drivers.filter((d) => d.isAvailable);
    const totalDrivers = drivers.length;
    const retentionRate =
      totalDrivers > 0 ? (activeDrivers.length / totalDrivers) * 100 : 0;

    return {
      metricType: "driver-retention",
      value: Math.round(retentionRate * 100) / 100,
      period: "monthly",
      metadata: {
        activeDrivers: activeDrivers.length,
        totalDrivers,
        inactiveDrivers: totalDrivers - activeDrivers.length,
      },
    };
  }

  /**
   * Calculate delivery performance metrics
   */
  calculateDeliveryPerformance(loads: any[]): MetricData {
    const completedLoads = loads.filter((load) => load.status === "DELIVERED");
    const totalLoads = loads.length;
    const completionRate =
      totalLoads > 0 ? (completedLoads.length / totalLoads) * 100 : 0;

    return {
      metricType: "delivery-performance",
      value: Math.round(completionRate * 100) / 100,
      period: "monthly",
      metadata: {
        completed: completedLoads.length,
        inProgress: loads.filter((l) => l.status === "IN_TRANSIT").length,
        pending: loads.filter((l) => l.status === "PENDING").length,
        cancelled: loads.filter((l) => l.status === "CANCELLED").length,
      },
    };
  }

  /**
   * Calculate cost per delivery
   */
  calculateCostPerDelivery(loads: any[], expenses: any[]): MetricData {
    const totalExpenses = expenses.reduce(
      (sum, expense) => sum + expense.amount,
      0,
    );
    const completedLoads = loads.filter(
      (load) => load.status === "DELIVERED",
    ).length;
    const costPerDelivery =
      completedLoads > 0 ? totalExpenses / completedLoads : 0;

    return {
      metricType: "cost-per-delivery",
      value: Math.round(costPerDelivery * 100) / 100,
      period: "monthly",
      metadata: {
        totalExpenses,
        completedDeliveries: completedLoads,
        expenseBreakdown: {
          fuel: expenses
            .filter((e) => e.category === "fuel")
            .reduce((s, e) => s + e.amount, 0),
          maintenance: expenses
            .filter((e) => e.category === "maintenance")
            .reduce((s, e) => s + e.amount, 0),
          labor: expenses
            .filter((e) => e.category === "labor")
            .reduce((s, e) => s + e.amount, 0),
        },
      },
    };
  }

  /**
   * Calculate fleet utilization rate
   */
  calculateUtilization(vehicles: any[], loads: any[]): MetricData {
    const activeVehicles = vehicles.filter((v) => v.status === "IN_USE").length;
    const totalVehicles = vehicles.length;
    const utilizationRate =
      totalVehicles > 0 ? (activeVehicles / totalVehicles) * 100 : 0;

    return {
      metricType: "fleet-utilization",
      value: Math.round(utilizationRate * 100) / 100,
      period: "monthly",
      metadata: {
        inUse: activeVehicles,
        available: vehicles.filter((v) => v.status === "AVAILABLE").length,
        maintenance: vehicles.filter((v) => v.status === "MAINTENANCE").length,
        total: totalVehicles,
      },
    };
  }

  /**
   * Generate comprehensive dashboard metrics
   */
  generateDashboard(data: {
    loads: any[];
    drivers: any[];
    vehicles: any[];
    expenses: any[];
  }): DashboardMetrics {
    return {
      revenue: this.calculateRevenueMetrics(data.loads),
      efficiency: this.calculateEfficiency(data.loads),
      customerSatisfaction: this.calculateCustomerSatisfaction(data.loads),
      driverRetention: this.calculateDriverRetention(data.drivers),
      deliveryPerformance: this.calculateDeliveryPerformance(data.loads),
      costPerDelivery: this.calculateCostPerDelivery(data.loads, data.expenses),
      utilization: this.calculateUtilization(data.vehicles, data.loads),
    };
  }

  /**
   * Simple linear regression forecasting
   */
  forecastMetric(
    historicalData: Array<{ date: Date; value: number }>,
  ): Forecast {
    if (historicalData.length < 2) {
      throw new Error("Insufficient historical data for forecasting");
    }

    // Convert dates to timestamps for regression
    const dataPoints = historicalData.map((d) => ({
      x: d.date.getTime(),
      y: d.value,
    }));

    // Calculate linear regression
    const n = dataPoints.length;
    const sumX = dataPoints.reduce((sum, d) => sum + d.x, 0);
    const sumY = dataPoints.reduce((sum, d) => sum + d.y, 0);
    const sumXY = dataPoints.reduce((sum, d) => sum + d.x * d.y, 0);
    const sumX2 = dataPoints.reduce((sum, d) => sum + d.x * d.x, 0);

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;

    // Generate 30-day forecast
    const lastDate = historicalData[historicalData.length - 1].date;
    const predictions = [];

    for (let i = 1; i <= 30; i++) {
      const futureDate = new Date(lastDate.getTime() + i * 24 * 60 * 60 * 1000);
      const predictedValue = slope * futureDate.getTime() + intercept;

      // Calculate confidence (decreases with distance)
      const confidence = Math.max(0.5, 0.95 - i * 0.015);

      predictions.push({
        date: futureDate,
        predictedValue: Math.max(0, predictedValue),
        confidence: Math.round(confidence * 100) / 100,
      });
    }

    return {
      metricType: "forecast",
      predictions,
    };
  }

  /**
   * Detect anomalies in metrics
   */
  detectAnomalies(
    currentValue: number,
    historicalValues: number[],
  ): { isAnomaly: boolean; severity: "low" | "medium" | "high" } | null {
    if (historicalValues.length < 5) return null;

    const mean =
      historicalValues.reduce((sum, v) => sum + v, 0) / historicalValues.length;
    const variance =
      historicalValues.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) /
      historicalValues.length;
    const stdDev = Math.sqrt(variance);

    const zScore = Math.abs((currentValue - mean) / stdDev);

    if (zScore > 3) {
      return { isAnomaly: true, severity: "high" };
    } else if (zScore > 2) {
      return { isAnomaly: true, severity: "medium" };
    } else if (zScore > 1.5) {
      return { isAnomaly: true, severity: "low" };
    }

    return { isAnomaly: false, severity: "low" };
  }

  /**
   * Generate executive summary
   */
  generateExecutiveSummary(dashboard: DashboardMetrics): {
    highlights: string[];
    concerns: string[];
    recommendations: string[];
  } {
    const highlights: string[] = [];
    const concerns: string[] = [];
    const recommendations: string[] = [];

    // Revenue analysis
    if (
      dashboard.revenue.changePercent &&
      dashboard.revenue.changePercent > 10
    ) {
      highlights.push(
        `Revenue up ${dashboard.revenue.changePercent.toFixed(1)}% - Strong growth momentum`,
      );
    } else if (
      dashboard.revenue.changePercent &&
      dashboard.revenue.changePercent < -10
    ) {
      concerns.push(
        `Revenue down ${Math.abs(dashboard.revenue.changePercent).toFixed(1)}% - Requires attention`,
      );
      recommendations.push(
        "Review pricing strategy and market expansion opportunities",
      );
    }

    // Efficiency analysis
    if (dashboard.efficiency.value >= 90) {
      highlights.push(
        `${dashboard.efficiency.value.toFixed(1)}% on-time delivery rate - Excellent performance`,
      );
    } else if (dashboard.efficiency.value < 75) {
      concerns.push(
        `On-time delivery at ${dashboard.efficiency.value.toFixed(1)}% - Below target`,
      );
      recommendations.push(
        "Implement route optimization and driver training programs",
      );
    }

    // Customer satisfaction
    if (dashboard.customerSatisfaction.value >= 85) {
      highlights.push(
        `Customer satisfaction at ${dashboard.customerSatisfaction.value.toFixed(1)}% - Meeting expectations`,
      );
    } else {
      concerns.push(
        `Customer satisfaction needs improvement (${dashboard.customerSatisfaction.value.toFixed(1)}%)`,
      );
      recommendations.push(
        "Enhance customer communication and service quality",
      );
    }

    // Utilization
    if (dashboard.utilization.value < 60) {
      concerns.push(
        `Fleet utilization at ${dashboard.utilization.value.toFixed(1)}% - Capacity underused`,
      );
      recommendations.push(
        "Optimize load assignment and consider fleet rightsizing",
      );
    }

    return { highlights, concerns, recommendations };
  }
}

export const businessMetricsEngine = new BusinessMetricsEngine();
