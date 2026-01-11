// Backend API for Real-Time Revenue Metrics
// Provides live revenue data for dashboard with caching

const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const { limiters, authenticate, requireScope, auditLog } = require('../middleware/security');

const prisma = new PrismaClient();

// In-memory cache for metrics (use Redis in production)
let metricsCache = {
    data: null,
    timestamp: null,
    ttl: 60000, // 1 minute cache
};

/**
 * GET /api/metrics/revenue/live
 * Returns real-time revenue metrics
 */
router.get('/live', limiters.general, authenticate, requireScope('metrics:read'), auditLog, async (req, res, next) => {
    try {
        // Check cache
        if (metricsCache.data && Date.now() - metricsCache.timestamp < metricsCache.ttl) {
            return res.json({
                ...metricsCache.data,
                cached: true,
                lastUpdated: new Date(metricsCache.timestamp).toISOString(),
            });
        }

        // Calculate fresh metrics
        const metrics = await calculateLiveMetrics();
        const mrrHistory = await getMRRHistory(12);
        const tierDistribution = await getTierDistribution();
        const alerts = await getRecentAlerts();

        const response = {
            current: metrics,
            mrrHistory,
            tierDistribution,
            alerts,
            cached: false,
            lastUpdated: new Date().toISOString(),
        };

        // Update cache
        metricsCache = {
            data: response,
            timestamp: Date.now(),
            ttl: 60000,
        };

        res.json(response);
    } catch (error) {
        next(error);
    }
});

/**
 * Calculate all live metrics
 */
async function calculateLiveMetrics() {
    const now = new Date();
    const startOfDay = new Date(now.setHours(0, 0, 0, 0));
    const startOfWeek = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    // Parallel queries for better performance
    const [
        activeSubscriptions,
        customerCount,
        newCustomersToday,
        newCustomersThisWeek,
        newCustomersThisMonth,
        revenueToday,
        revenueThisWeek,
        revenueThisMonth,
        cancelledThisMonth,
        activeAtMonthStart,
    ] = await Promise.all([
        // Active subscriptions for MRR
        prisma.subscription.findMany({
            where: { status: 'active' },
            select: { monthlyValue: true, tier: true },
        }),

        // Total active customers
        prisma.customer.count({
            where: { status: 'active' },
        }),

        // New customers today
        prisma.customer.count({
            where: { createdAt: { gte: startOfDay } },
        }),

        // New customers this week
        prisma.customer.count({
            where: { createdAt: { gte: startOfWeek } },
        }),

        // New customers this month
        prisma.customer.count({
            where: { createdAt: { gte: startOfMonth } },
        }),

        // Revenue today
        prisma.payment.aggregate({
            where: {
                createdAt: { gte: startOfDay },
                status: 'succeeded',
            },
            _sum: { amount: true },
        }),

        // Revenue this week
        prisma.payment.aggregate({
            where: {
                createdAt: { gte: startOfWeek },
                status: 'succeeded',
            },
            _sum: { amount: true },
        }),

        // Revenue this month
        prisma.payment.aggregate({
            where: {
                createdAt: { gte: startOfMonth },
                status: 'succeeded',
            },
            _sum: { amount: true },
        }),

        // Churn calculation - cancelled this month
        prisma.subscription.count({
            where: {
                status: 'cancelled',
                cancelledAt: { gte: startOfMonth },
            },
        }),

        // Active at start of month for churn rate
        prisma.subscription.count({
            where: {
                createdAt: { lt: startOfMonth },
                OR: [
                    { status: 'active' },
                    { status: 'cancelled', cancelledAt: { gte: startOfMonth } },
                ],
            },
        }),
    ]);

    // Calculate MRR
    const mrr = activeSubscriptions.reduce((sum, sub) => sum + (sub.monthlyValue || 0), 0);

    // Calculate ARR
    const arr = mrr * 12;

    // Calculate churn rate
    const churn = activeAtMonthStart > 0 ? cancelledThisMonth / activeAtMonthStart : 0;

    // Calculate LTV (simplified)
    const avgRevenuePerCustomer = customerCount > 0 ? mrr / customerCount : 0;
    const avgLifetimeMonths = churn > 0 ? 1 / churn : 24; // Default 24 months if no churn
    const ltv = avgRevenuePerCustomer * avgLifetimeMonths;

    // Calculate CAC (Customer Acquisition Cost) - placeholder
    const cac = 150; // Replace with actual marketing spend / new customers

    // Calculate NRR (Net Revenue Retention) - placeholder
    const nrr = 1.05; // 105% - Replace with actual calculation

    return {
        mrr,
        arr,
        churn,
        ltv,
        customerCount,
        newCustomersToday,
        newCustomersThisWeek,
        newCustomersThisMonth,
        revenueToday: revenueToday._sum.amount || 0,
        revenueThisWeek: revenueThisWeek._sum.amount || 0,
        revenueThisMonth: revenueThisMonth._sum.amount || 0,
        avgRevenuePerCustomer,
        cac,
        nrr,
    };
}

/**
 * Get MRR history for last N months
 */
async function getMRRHistory(months = 12) {
    const history = [];

    for (let i = months - 1; i >= 0; i--) {
        const date = new Date();
        date.setMonth(date.getMonth() - i);
        const monthStart = new Date(date.getFullYear(), date.getMonth(), 1);
        const monthEnd = new Date(date.getFullYear(), date.getMonth() + 1, 0);
        const monthName = date.toLocaleString('default', { month: 'short' });

        // MRR at end of month
        const subscriptions = await prisma.subscription.findMany({
            where: {
                status: 'active',
                createdAt: { lte: monthEnd },
            },
            select: { monthlyValue: true, createdAt: true },
        });

        const mrr = subscriptions.reduce((sum, sub) => sum + (sub.monthlyValue || 0), 0);

        // New MRR this month
        const newSubs = subscriptions.filter(
            sub => sub.createdAt >= monthStart && sub.createdAt <= monthEnd
        );
        const newMRR = newSubs.reduce((sum, sub) => sum + (sub.monthlyValue || 0), 0);

        // Churned MRR this month
        const churned = await prisma.subscription.aggregate({
            where: {
                status: 'cancelled',
                cancelledAt: { gte: monthStart, lte: monthEnd },
            },
            _sum: { monthlyValue: true },
        });
        const churnedMRR = churned._sum.monthlyValue || 0;

        history.push({
            month: monthName,
            mrr,
            newMRR,
            churnedMRR,
        });
    }

    return history;
}

/**
 * Get revenue distribution by tier
 */
async function getTierDistribution() {
    const tiers = await prisma.subscription.groupBy({
        by: ['tier'],
        where: { status: 'active' },
        _count: true,
        _sum: { monthlyValue: true },
    });

    return tiers.map(tier => ({
        tier: tier.tier || 'Unknown',
        count: tier._count,
        revenue: tier._sum.monthlyValue || 0,
    }));
}

/**
 * Get recent revenue alerts
 */
async function getRecentAlerts() {
    // If you have a revenueAlert table
    if (prisma.revenueAlert) {
        const alerts = await prisma.revenueAlert.findMany({
            where: {
                createdAt: {
                    gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // Last 7 days
                },
            },
            orderBy: { createdAt: 'desc' },
            take: 5,
        });

        return alerts.map(alert => ({
            id: alert.id,
            severity: alert.severity,
            title: alert.title,
            message: alert.message,
            timestamp: alert.createdAt.toISOString(),
        }));
    }

    // Placeholder alerts if table doesn't exist
    return [];
}

/**
 * POST /api/metrics/revenue/clear-cache
 * Clear metrics cache (admin only)
 */
router.post('/clear-cache', limiters.general, authenticate, requireScope('admin'), auditLog, async (req, res) => {
    metricsCache = {
        data: null,
        timestamp: null,
        ttl: 60000,
    };

    res.json({ success: true, message: 'Cache cleared' });
});

/**
 * GET /api/metrics/revenue/export
 * Export metrics as CSV
 */
router.get('/export', limiters.general, authenticate, requireScope('metrics:export'), auditLog, async (req, res, next) => {
    try {
        const metrics = await calculateLiveMetrics();
        const mrrHistory = await getMRRHistory(12);

        // Generate CSV
        const csv = [
            'Metric,Value',
            `MRR,${metrics.mrr}`,
            `ARR,${metrics.arr}`,
            `Churn Rate,${metrics.churn}`,
            `LTV,${metrics.ltv}`,
            `Customer Count,${metrics.customerCount}`,
            '',
            'Month,MRR,New MRR,Churned MRR',
            ...mrrHistory.map(h => `${h.month},${h.mrr},${h.newMRR},${h.churnedMRR}`),
        ].join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=revenue-metrics.csv');
        res.send(csv);
    } catch (error) {
        next(error);
    }
});

module.exports = router;
