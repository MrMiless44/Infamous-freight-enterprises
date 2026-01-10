/**
 * Business Analytics Tracking Service
 *
 * Tracks key business metrics:
 * - Customer acquisition
 * - Revenue metrics
 * - Product usage
 * - Conversion funnels
 * - Churn indicators
 */

class AnalyticsService {
  constructor() {
    this.events = [];
    this.metrics = new Map();
  }

  /**
   * Track customer signup
   */
  async trackSignup(userId, metadata = {}) {
    await this.trackEvent("customer_signup", {
      userId,
      plan: metadata.plan || "starter",
      source: metadata.source || "direct",
      referrer: metadata.referrer,
      timestamp: new Date(),
    });

    // Update CAC metrics
    await this.updateMetric("total_signups", 1);
    await this.updateMetric(`signups_${metadata.plan}`, 1);
  }

  /**
   * Track subscription created
   */
  async trackSubscriptionCreated(userId, subscription) {
    await this.trackEvent("subscription_created", {
      userId,
      subscriptionId: subscription.id,
      plan: subscription.plan,
      amount: subscription.amount,
      interval: subscription.interval,
      timestamp: new Date(),
    });

    // Update MRR
    const monthlyAmount =
      subscription.interval === "yearly"
        ? subscription.amount / 12
        : subscription.amount;
    await this.updateMetric("mrr", monthlyAmount);
    await this.updateMetric(`mrr_${subscription.plan}`, monthlyAmount);
  }

  /**
   * Track subscription canceled
   */
  async trackSubscriptionCanceled(userId, subscription, reason) {
    await this.trackEvent("subscription_canceled", {
      userId,
      subscriptionId: subscription.id,
      plan: subscription.plan,
      reason,
      lifetimeValue: subscription.lifetimeValue,
      daysSubscribed: subscription.daysSubscribed,
      timestamp: new Date(),
    });

    // Update churn metrics
    await this.updateMetric("churn_count", 1);
    await this.updateMetric("churn_mrr", -subscription.monthlyAmount);
  }

  /**
   * Track shipment created
   */
  async trackShipmentCreated(userId, shipment) {
    await this.trackEvent("shipment_created", {
      userId,
      shipmentId: shipment.id,
      origin: shipment.origin,
      destination: shipment.destination,
      distance: shipment.distance,
      weight: shipment.weight,
      revenue: shipment.cost,
      timestamp: new Date(),
    });

    await this.updateMetric("total_shipments", 1);
    await this.updateMetric("shipment_revenue", shipment.cost);
  }

  /**
   * Track feature usage
   */
  async trackFeatureUsage(userId, feature, metadata = {}) {
    await this.trackEvent("feature_used", {
      userId,
      feature,
      ...metadata,
      timestamp: new Date(),
    });

    await this.updateMetric(`feature_usage_${feature}`, 1);
  }

  /**
   * Track conversion funnel step
   */
  async trackFunnelStep(userId, funnel, step, metadata = {}) {
    await this.trackEvent("funnel_step", {
      userId,
      funnel,
      step,
      ...metadata,
      timestamp: new Date(),
    });

    await this.updateMetric(`funnel_${funnel}_${step}`, 1);
  }

  /**
   * Calculate key business metrics
   */
  async getBusinessMetrics(timeRange = "30d") {
    // In production, query from database
    return {
      // Revenue Metrics
      mrr: (await this.getMetric("mrr")) || 0,
      arr: ((await this.getMetric("mrr")) || 0) * 12,

      // Customer Metrics
      totalCustomers: (await this.getMetric("total_signups")) || 0,
      newCustomers: await this.getMetricInRange("customer_signup", timeRange),
      churnedCustomers: await this.getMetricInRange(
        "subscription_canceled",
        timeRange,
      ),
      churnRate: await this.calculateChurnRate(timeRange),

      // Product Metrics
      totalShipments: (await this.getMetric("total_shipments")) || 0,
      shipmentsPerCustomer:
        ((await this.getMetric("total_shipments")) || 0) /
        ((await this.getMetric("total_signups")) || 1),

      // Unit Economics
      ltv: await this.calculateLTV(),
      cac: await this.calculateCAC(timeRange),
      ltvCacRatio:
        (await this.calculateLTV()) /
        ((await this.calculateCAC(timeRange)) || 1),

      // Conversion Metrics
      signupConversion: await this.calculateConversionRate(
        "signup_funnel",
        "landing",
        "completed",
        timeRange,
      ),
      paidConversion: await this.calculateConversionRate(
        "paid_funnel",
        "trial",
        "paid",
        timeRange,
      ),
    };
  }

  /**
   * Track event (internal)
   */
  async trackEvent(event, data) {
    const eventData = {
      event,
      ...data,
      timestamp: new Date(),
    };

    // In production, write to database
    // await prisma.analyticsEvent.create({ data: eventData });

    // Send to external analytics (Mixpanel/Amplitude)
    if (process.env.MIXPANEL_TOKEN) {
      // await mixpanel.track(event, data);
    }

    console.log("[Analytics Event]", eventData);
    this.events.push(eventData);
  }

  /**
   * Update metric (internal)
   */
  async updateMetric(key, value) {
    const current = this.metrics.get(key) || 0;
    this.metrics.set(key, current + value);

    // In production, write to time-series database
    // await prometheus.gauge(key).set(current + value);
  }

  /**
   * Get metric value
   */
  async getMetric(key) {
    return this.metrics.get(key) || 0;
  }

  /**
   * Get metric count in time range
   */
  async getMetricInRange(eventType, timeRange) {
    // In production, query database
    const cutoff = this.getTimeRangeCutoff(timeRange);
    return this.events.filter(
      (e) => e.event === eventType && e.timestamp >= cutoff,
    ).length;
  }

  /**
   * Calculate churn rate
   */
  async calculateChurnRate(timeRange) {
    const churned = await this.getMetricInRange(
      "subscription_canceled",
      timeRange,
    );
    const total = (await this.getMetric("total_signups")) || 1;
    return (churned / total) * 100;
  }

  /**
   * Calculate LTV (Lifetime Value)
   */
  async calculateLTV() {
    const avgMRR =
      (await this.getMetric("mrr")) /
      ((await this.getMetric("total_signups")) || 1);
    const avgLifetimeMonths = 24; // Industry average
    const grossMargin = 0.75;
    return avgMRR * avgLifetimeMonths * grossMargin;
  }

  /**
   * Calculate CAC (Customer Acquisition Cost)
   */
  async calculateCAC(timeRange) {
    // In production, pull from marketing spend data
    const marketingSpend = 5000; // Mock: monthly marketing spend
    const newCustomers = await this.getMetricInRange(
      "customer_signup",
      timeRange,
    );
    return newCustomers > 0 ? marketingSpend / newCustomers : 0;
  }

  /**
   * Calculate conversion rate
   */
  async calculateConversionRate(funnel, fromStep, toStep, timeRange) {
    const fromCount = await this.getMetricInRange(`funnel_step`, timeRange);
    const toCount = await this.getMetricInRange(`funnel_step`, timeRange);
    return fromCount > 0 ? (toCount / fromCount) * 100 : 0;
  }

  /**
   * Get time range cutoff date
   */
  getTimeRangeCutoff(timeRange) {
    const now = new Date();
    const days = parseInt(timeRange.replace("d", ""));
    return new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
  }
}

// Singleton instance
const analyticsService = new AnalyticsService();

module.exports = analyticsService;
