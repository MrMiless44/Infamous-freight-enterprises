-- Database Performance Optimization Indexes
-- Run these once in production to optimize query performance
-- Usage: psql $DATABASE_URL < scripts/db-indexes.sql

-- Shipments table indexes
CREATE INDEX IF NOT EXISTS idx_shipments_status ON shipments(status);
CREATE INDEX IF NOT EXISTS idx_shipments_driver_id ON shipments("driverId");
CREATE INDEX IF NOT EXISTS idx_shipments_created_at ON shipments("createdAt" DESC);
CREATE INDEX IF NOT EXISTS idx_shipments_status_driver ON shipments(status, "driverId");
CREATE INDEX IF NOT EXISTS idx_shipments_updated_at ON shipments("updatedAt" DESC);

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users("createdAt" DESC);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- AI Events table indexes
CREATE INDEX IF NOT EXISTS idx_ai_events_user_id ON "AiEvent"("userId");
CREATE INDEX IF NOT EXISTS idx_ai_events_created_at ON "AiEvent"("createdAt" DESC);
CREATE INDEX IF NOT EXISTS idx_ai_events_command ON "AiEvent"(command);

-- Analyze query plans for optimization
ANALYZE shipments;
ANALYZE users;
ANALYZE "AiEvent";

-- Show index usage statistics
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
