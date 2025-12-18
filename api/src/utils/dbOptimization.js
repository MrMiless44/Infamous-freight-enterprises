/**
 * Database performance optimization utilities
 * Includes query optimization recommendations and index management
 */

const { prisma } = require("../db/prisma");

/**
 * Optimize shipment queries with related data
 * Prevents N+1 query problems
 */
const getShipmentsOptimized = async (filters = {}, options = {}) => {
  const {
    page = 1,
    limit = 20,
    sortBy = "createdAt",
    sortOrder = "desc",
  } = options;

  const skip = (page - 1) * limit;

  return prisma.shipment.findMany({
    where: filters,
    include: {
      driver: {
        select: {
          id: true,
          name: true,
          email: true,
        },
      },
    },
    skip,
    take: limit,
    orderBy: {
      [sortBy]: sortOrder,
    },
  });
};

/**
 * Get total count for pagination
 */
const getShipmentsCount = async (filters = {}) => {
  return prisma.shipment.count({
    where: filters,
  });
};

/**
 * Index recommendations for better performance
 * These should be run once in production
 */
const indexRecommendations = `
-- Shipments table indexes (recommended)
CREATE INDEX IF NOT EXISTS idx_shipments_status ON shipments(status);
CREATE INDEX IF NOT EXISTS idx_shipments_driver_id ON shipments("driverId");
CREATE INDEX IF NOT EXISTS idx_shipments_created_at ON shipments("createdAt" DESC);
CREATE INDEX IF NOT EXISTS idx_shipments_status_driver ON shipments(status, "driverId");

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users("createdAt" DESC);

-- AI Events table indexes
CREATE INDEX IF NOT EXISTS idx_ai_events_user_id ON "AiEvent"("userId");
CREATE INDEX IF NOT EXISTS idx_ai_events_created_at ON "AiEvent"("createdAt" DESC);
`;

/**
 * Query performance analysis utility
 * Run EXPLAIN on slow queries to identify bottlenecks
 */
const explainQuery = async (sql) => {
  try {
    const result = await prisma.$queryRawUnsafe(`EXPLAIN ANALYZE ${sql}`);
    return result;
  } catch (err) {
    return { error: err.message };
  }
};

module.exports = {
  getShipmentsOptimized,
  getShipmentsCount,
  indexRecommendations,
  explainQuery,
};
