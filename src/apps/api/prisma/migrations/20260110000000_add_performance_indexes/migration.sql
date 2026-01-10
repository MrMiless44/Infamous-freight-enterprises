-- CreateIndex: Add performance indexes for common queries
-- Migration: 20260110000000_add_performance_indexes

-- Shipments table indexes
CREATE INDEX IF NOT EXISTS "idx_shipments_status_created" ON "Shipment"("status", "createdAt" DESC);
CREATE INDEX IF NOT EXISTS "idx_shipments_driver_status" ON "Shipment"("driverId", "status") WHERE "driverId" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "idx_shipments_customer_created" ON "Shipment"("customerId", "createdAt" DESC) WHERE "customerId" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "idx_shipments_delivery_date" ON "Shipment"("estimatedDelivery") WHERE "estimatedDelivery" IS NOT NULL;

-- Drivers table indexes
CREATE INDEX IF NOT EXISTS "idx_drivers_availability" ON "Driver"("isAvailable", "lastActive" DESC);
CREATE INDEX IF NOT EXISTS "idx_drivers_status" ON "Driver"("status");
CREATE INDEX IF NOT EXISTS "idx_drivers_location" ON "Driver"("currentLat", "currentLng") WHERE "currentLat" IS NOT NULL AND "currentLng" IS NOT NULL;

-- Users table indexes
CREATE INDEX IF NOT EXISTS "idx_users_email" ON "User"("email");
CREATE INDEX IF NOT EXISTS "idx_users_role" ON "User"("role");
CREATE INDEX IF NOT EXISTS "idx_users_created" ON "User"("createdAt" DESC);

-- AiEvent table indexes (for observability)
CREATE INDEX IF NOT EXISTS "idx_ai_events_role_timestamp" ON "AiEvent"("role", "timestamp" DESC);
CREATE INDEX IF NOT EXISTS "idx_ai_events_confidence" ON "AiEvent"("confidence") WHERE "confidence" < 0.85;
CREATE INDEX IF NOT EXISTS "idx_ai_events_requires_review" ON "AiEvent"("requiresHumanReview") WHERE "requiresHumanReview" = true;

-- Composite indexes for common join patterns
CREATE INDEX IF NOT EXISTS "idx_shipments_driver_status_date" ON "Shipment"("driverId", "status", "createdAt" DESC) WHERE "driverId" IS NOT NULL;

-- Partial indexes for performance on filtered queries
CREATE INDEX IF NOT EXISTS "idx_shipments_active" ON "Shipment"("status", "createdAt" DESC) 
  WHERE "status" IN ('pending', 'in-transit', 'out-for-delivery');
CREATE INDEX IF NOT EXISTS "idx_drivers_active" ON "Driver"("isAvailable", "hoursToday") 
  WHERE "isAvailable" = true AND "hoursToday" < 11;

-- Comment on indexes
COMMENT ON INDEX "idx_shipments_status_created" IS 'Optimizes shipment list queries with status filtering and date sorting';
COMMENT ON INDEX "idx_drivers_availability" IS 'Optimizes driver assignment queries based on availability';
COMMENT ON INDEX "idx_ai_events_role_timestamp" IS 'Optimizes AI observability queries by role and time';
