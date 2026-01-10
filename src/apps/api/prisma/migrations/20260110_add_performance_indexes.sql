-- Add Performance Indexes
-- Migration created: 2026-01-10

-- Shipments by status (frequent filter)
CREATE INDEX IF NOT EXISTS idx_shipments_status ON "Shipment"(status);

-- Shipments by driver (JOIN optimization)  
CREATE INDEX IF NOT EXISTS idx_shipments_driver_id ON "Shipment"("driverId");

-- Shipments by creation date (timeline queries)
CREATE INDEX IF NOT EXISTS idx_shipments_created_at ON "Shipment"("createdAt");

-- Composite index for driver availability queries
CREATE INDEX IF NOT EXISTS idx_shipments_driver_status 
  ON "Shipment"("driverId", status) 
  WHERE status IN ('pending', 'in_transit');

-- Driver availability lookups
CREATE INDEX IF NOT EXISTS idx_drivers_available 
  ON "Driver"(available) 
  WHERE available = true;

-- Audit log queries (compliance)
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON "AuditLog"("createdAt");

-- User lookups by email (login performance)
CREATE INDEX IF NOT EXISTS idx_users_email ON "User"(email);

-- Subscription queries for billing
CREATE INDEX IF NOT EXISTS idx_subscriptions_customer_id ON "Subscription"("customerId");
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON "Subscription"(status);

-- Invoice queries
CREATE INDEX IF NOT EXISTS idx_invoices_subscription_id ON "Invoice"("subscriptionId");
CREATE INDEX IF NOT EXISTS idx_invoices_organization_id ON "Invoice"("organizationId");
CREATE INDEX IF NOT EXISTS idx_invoices_status ON "Invoice"(status);

-- Analyze tables for query planner
ANALYZE "Shipment";
ANALYZE "Driver";
ANALYZE "User";
ANALYZE "AuditLog";
ANALYZE "Subscription";
ANALYZE "Invoice";

-- Verification query (run after 24 hours to check usage)
-- SELECT 
--   schemaname,
--   tablename,
--   indexname,
--   idx_scan as scans,
--   idx_tup_read as tuples_read
-- FROM pg_stat_user_indexes
-- ORDER BY idx_scan DESC;
