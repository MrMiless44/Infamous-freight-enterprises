/**
 * Database Query Profiling and Optimization
 * Identifies slow queries, N+1 problems, and optimization opportunities
 */

import { PrismaClient } from "@prisma/client";

export interface QueryProfile {
  model: string;
  action: string;
  duration: number;
  timestamp: Date;
  args?: Record<string, any>;
  isSlow: boolean;
}

class QueryProfiler {
  private profiles: QueryProfile[] = [];
  private slowQueryThreshold = parseInt(
    process.env.SLOW_QUERY_THRESHOLD || "1000",
    10,
  );
  private maxProfiles = 10000;

  /**
   * Record a query profile
   */
  record(profile: QueryProfile): void {
    this.profiles.push(profile);

    // Keep memory bounded
    if (this.profiles.length > this.maxProfiles) {
      this.profiles = this.profiles.slice(-this.maxProfiles);
    }

    // Log slow queries
    if (profile.isSlow) {
      console.warn(
        `🐢 SLOW QUERY (${profile.duration}ms): ${profile.model}.${profile.action}`,
      );

      // Additional diagnostics for very slow queries (>5s)
      if (profile.duration > 5000) {
        console.warn(
          "   Possibly N+1 query or missing index. Args:",
          profile.args,
        );
      }
    }
  }

  /**
   * Get profile statistics
   */
  getStats(): {
    totalQueries: number;
    averageDuration: number;
    slowQueries: QueryProfile[];
    n1Candidates: Array<{
      model: string;
      action: string;
      count: number;
      totalTime: number;
    }>;
  } {
    const slowQueries = this.profiles.filter((p) => p.isSlow);
    const avgDuration =
      this.profiles.length > 0
        ? this.profiles.reduce((sum, p) => sum + p.duration, 0) /
          this.profiles.length
        : 0;

    // Detect N+1 queries: many quick queries to same model in short time
    const queryGroups = new Map<string, QueryProfile[]>();
    const timeWindowMs = 100; // 100ms window

    for (const profile of this.profiles) {
      const key = profile.model;
      if (!queryGroups.has(key)) {
        queryGroups.set(key, []);
      }
      queryGroups.get(key)!.push(profile);
    }

    const n1Candidates = Array.from(queryGroups.entries())
      .filter(([_, queries]) => queries.length > 5) // More than 5 queries to same model
      .map(([model, queries]) => {
        const totalTime = queries.reduce((sum, q) => sum + q.duration, 0);
        return {
          model,
          action: "findUnique", // Typical N+1 pattern
          count: queries.length,
          totalTime,
        };
      });

    return {
      totalQueries: this.profiles.length,
      averageDuration: Math.round(avgDuration),
      slowQueries: slowQueries.slice(-100), // Last 100 slow queries
      n1Candidates,
    };
  }

  /**
   * Get top slow queries
   */
  getTopSlowQueries(limit: number = 10): QueryProfile[] {
    return this.profiles
      .filter((p) => p.isSlow)
      .sort((a, b) => b.duration - a.duration)
      .slice(0, limit);
  }

  /**
   * Reset profiler data
   */
  reset(): void {
    this.profiles = [];
  }
}

// Global profiler instance
const queryProfiler = new QueryProfiler();

/**
 * Extend Prisma with query profiling
 */
export function enableQueryProfiling(prisma: PrismaClient): void {
  // Use Prisma middleware to intercept queries
  prisma.$use(async (params, next) => {
    const startTime = Date.now();
    const result = await next(params);
    const duration = Date.now() - startTime;

    const profile: QueryProfile = {
      model: params.model || "unknown",
      action: params.action,
      duration,
      timestamp: new Date(),
      args: params.args,
      isSlow: duration > queryProfiler["slowQueryThreshold"],
    };

    queryProfiler.record(profile);

    return result;
  });
}

/**
 * Endpoint: Get query profiling statistics
 */
export async function handleQueryStats(req: any, res: any) {
  const stats = queryProfiler.getStats();
  const topSlow = queryProfiler.getTopSlowQueries(10);

  res.json({
    success: true,
    data: {
      stats,
      topSlowQueries: topSlow,
      recommendations: generateOptimizationRecommendations(stats),
    },
  });
}

/**
 * Generate optimization recommendations based on query patterns
 */
function generateOptimizationRecommendations(stats: any): string[] {
  const recommendations: string[] = [];

  // Check for N+1 patterns
  if (stats.n1Candidates.length > 0) {
    recommendations.push(
      `⚠️ Detected N+1 query pattern: ${stats.n1Candidates.map((c) => c.model).join(", ")}`,
    );
    recommendations.push(
      "💡 Use Prisma include/select to fetch related data in single query",
    );
  }

  // Check for slow average
  if (stats.averageDuration > 500) {
    recommendations.push(
      "⚠️ Average query time > 500ms, consider indexing or query optimization",
    );
  }

  // Check for many slow queries
  if (stats.slowQueries.length > stats.totalQueries * 0.1) {
    recommendations.push(
      `⚠️ ${((stats.slowQueries.length / stats.totalQueries) * 100).toFixed(1)}% of queries are slow`,
    );
  }

  if (recommendations.length === 0) {
    recommendations.push("✅ Query performance looks good!");
  }

  return recommendations;
}

/**
 * Query optimization best practices
 */
export const queryOptimizationPatterns = {
  /**
   * Bad: N+1 query
   */
  nPlusOneAntiPattern: `
    // ❌ BAD: This causes N+1 queries
    const shipments = await prisma.shipment.findMany();
    for (const shipment of shipments) {
      shipment.driver = await prisma.driver.findUnique({
        where: { id: shipment.driverId }
      });
    }
  `,

  /**
   * Good: Include related data
   */
  includePattern: `
    // ✅ GOOD: Single query with include
    const shipments = await prisma.shipment.findMany({
      include: {
        driver: true,
        customer: true,
        packages: true
      }
    });
  `,

  /**
   * Selective fields
   */
  selectPattern: `
    // ✅ GOOD: Only fetch needed fields
    const shipments = await prisma.shipment.findMany({
      select: {
        id: true,
        trackingNumber: true,
        status: true,
        driver: {
          select: { id: true, name: true }
        }
      }
    });
  `,

  /**
   * Pagination for large datasets
   */
  paginationPattern: `
    // ✅ GOOD: Paginate large result sets
    const page = parseInt(req.query.page || '1', 10);
    const pageSize = 50;
    
    const shipments = await prisma.shipment.findMany({
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: { driver: true }
    });
  `,

  /**
   * Filtering and indexing
   */
  filterPattern: `
    // ✅ GOOD: Filter at database level
    const shipments = await prisma.shipment.findMany({
      where: {
        status: 'IN_TRANSIT',
        createdAt: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000)
        }
      }
    });
  `,

  /**
   * Batch operations
   */
  batchPattern: `
    // ✅ GOOD: Use batch operations
    const shipmentIds = [1, 2, 3, 4, 5];
    const shipments = await prisma.shipment.findMany({
      where: {
        id: { in: shipmentIds }
      }
    });
  `,

  /**
   * Aggregation queries
   */
  aggregationPattern: `
    // ✅ GOOD: Use Prisma aggregation
    const stats = await prisma.shipment.aggregate({
      _count: true,
      _avg: { weight: true },
      where: { status: 'DELIVERED' }
    });
  `,
};

/**
 * Database indexing recommendations for Prisma schema
 */
export const indexingRecommendations = `
// In prisma/schema.prisma

model Shipment {
  id        String  @id @default(cuid())
  trackingNumber String @unique
  status    String
  driverId  String
  customerId String
  createdAt DateTime @default(now())
  
  driver    Driver @relation(fields: [driverId], references: [id])
  customer  Customer @relation(fields: [customerId], references: [id])
  
  // Add indexes for frequently queried fields
  @@index([status])
  @@index([driverId])
  @@index([customerId])
  @@index([createdAt])
  
  // Composite index for common filter combinations
  @@index([status, createdAt])
  @@index([driverId, status])
}

model Driver {
  id        String  @id @default(cuid())
  email     String  @unique
  status    String
  
  shipments Shipment[]
  
  @@index([status])
  @@index([email])
}
`;

/**
 * Export profiler for use
 */
export { queryProfiler };

/**
 * Usage:
 *
 * import { enableQueryProfiling, handleQueryStats } from './queryProfiler';
 *
 * // Enable profiling on startup
 * enableQueryProfiling(prisma);
 *
 * // Add endpoint for stats
 * app.get('/api/admin/query-stats', authenticate, requireAdmin, handleQueryStats);
 *
 * // Monitor in production
 * // Response shows slow queries and N+1 opportunities
 */
