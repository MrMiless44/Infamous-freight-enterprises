-- ============================================================================
-- PAYMENT & BILLING TABLES FOR INFAMOUS FREIGHT MONETIZATION
-- ============================================================================
-- Run these migrations in order: 001 → 002 → 003 → 004 → 005
-- PostgreSQL with Prisma ORM

-- ============================================================================
-- 001_create_customers_table.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS customers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Basic info
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255),
  
  -- Stripe linking
  stripe_customer_id VARCHAR(255) UNIQUE,
  stripe_sync_at TIMESTAMP,
  stripe_data JSONB,
  
  -- PayPal linking
  paypal_customer_id VARCHAR(255),
  
  -- Status
  status VARCHAR(50) DEFAULT 'active',
  deleted_at TIMESTAMP,
  
  -- Timestamps
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  CONSTRAINT valid_status CHECK (status IN ('active', 'inactive', 'deleted'))
);

CREATE INDEX idx_customers_email ON customers(email);
CREATE INDEX idx_customers_stripe_id ON customers(stripe_customer_id);
CREATE INDEX idx_customers_status ON customers(status);


-- ============================================================================
-- 002_create_subscriptions_table.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Relationships
  customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  
  -- Stripe linking
  stripe_subscription_id VARCHAR(255) UNIQUE NOT NULL,
  stripe_price_id VARCHAR(255) NOT NULL,
  
  -- Subscription details
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  auto_renew BOOLEAN DEFAULT true,
  
  -- Billing periods
  current_period_start TIMESTAMP,
  current_period_end TIMESTAMP,
  
  -- Cancellation
  cancelled_at TIMESTAMP,
  cancel_reason VARCHAR(255),
  
  -- Timestamps
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  CONSTRAINT valid_subscription_status CHECK (
    status IN ('incomplete', 'incomplete_expired', 'trialing', 'active', 'past_due', 'cancelled', 'paused')
  )
);

CREATE INDEX idx_subscriptions_customer ON subscriptions(customer_id);
CREATE INDEX idx_subscriptions_stripe_id ON subscriptions(stripe_subscription_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);
CREATE INDEX idx_subscriptions_period ON subscriptions(current_period_start, current_period_end);


-- ============================================================================
-- 003_create_invoices_table.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Relationships
  customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
  
  -- Stripe linking
  stripe_invoice_id VARCHAR(255) UNIQUE NOT NULL,
  
  -- Invoice numbers
  invoice_number VARCHAR(50) UNIQUE,
  
  -- Amounts
  amount_subtotal DECIMAL(10, 2) DEFAULT 0,
  amount_tax DECIMAL(10, 2) DEFAULT 0,
  amount_total DECIMAL(10, 2) NOT NULL,
  amount_paid DECIMAL(10, 2) DEFAULT 0,
  amount_refunded DECIMAL(10, 2) DEFAULT 0,
  
  -- Currency
  currency VARCHAR(3) DEFAULT 'USD',
  
  -- Billing period
  period_start DATE,
  period_end DATE,
  
  -- Payment tracking
  status VARCHAR(50) NOT NULL DEFAULT 'draft',
  due_at TIMESTAMP,
  paid_at TIMESTAMP,
  
  -- PDF & storage
  pdf_url VARCHAR(500),
  
  -- Timestamps
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  CONSTRAINT valid_invoice_status CHECK (
    status IN ('draft', 'sent', 'open', 'paid', 'void', 'uncollectible', 'failed', 'refunded')
  )
);

CREATE INDEX idx_invoices_customer ON invoices(customer_id);
CREATE INDEX idx_invoices_subscription ON invoices(subscription_id);
CREATE INDEX idx_invoices_stripe_id ON invoices(stripe_invoice_id);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_invoices_paid_at ON invoices(paid_at);
CREATE INDEX idx_invoices_period ON invoices(period_start, period_end);


-- ============================================================================
-- 004_create_usage_table.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS usage (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Relationships
  customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
  
  -- Usage tracking
  metric_name VARCHAR(100) NOT NULL,
  metric_value INTEGER DEFAULT 0,
  
  -- Billing period
  period_month DATE NOT NULL,
  
  -- For metered billing
  quantity_used INTEGER DEFAULT 0,
  quantity_limit INTEGER,
  overage_units INTEGER DEFAULT 0,
  overage_cost DECIMAL(10, 2) DEFAULT 0,
  
  -- Timestamps
  recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  CONSTRAINT valid_metric_name CHECK (
    metric_name IN ('api_calls', 'shipments', 'users', 'storage_gb', 'support_tickets')
  )
);

CREATE INDEX idx_usage_customer ON usage(customer_id);
CREATE INDEX idx_usage_subscription ON usage(subscription_id);
CREATE INDEX idx_usage_metric ON usage(metric_name);
CREATE INDEX idx_usage_period ON usage(period_month);


-- ============================================================================
-- 005_create_payments_table.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Relationships
  customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  invoice_id UUID REFERENCES invoices(id) ON DELETE SET NULL,
  
  -- Stripe linking
  stripe_charge_id VARCHAR(255),
  stripe_payment_intent_id VARCHAR(255),
  
  -- Payment details
  amount DECIMAL(10, 2) NOT NULL,
  currency VARCHAR(3) DEFAULT 'USD',
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  
  -- Payment method
  payment_method VARCHAR(50),
  card_last4 VARCHAR(4),
  card_brand VARCHAR(50),
  
  -- Failure tracking
  failure_code VARCHAR(100),
  failure_message TEXT,
  
  -- Timestamps
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  processed_at TIMESTAMP,
  
  CONSTRAINT valid_payment_status CHECK (
    status IN ('pending', 'succeeded', 'failed', 'refunded', 'cancelled')
  )
);

CREATE INDEX idx_payments_customer ON payments(customer_id);
CREATE INDEX idx_payments_invoice ON payments(invoice_id);
CREATE INDEX idx_payments_stripe_charge ON payments(stripe_charge_id);
CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_payments_created ON payments(created_at);


-- ============================================================================
-- 006_create_metrics_table.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Metric date
  metric_date DATE NOT NULL,
  
  -- MRR and ARR
  mrr DECIMAL(12, 2) DEFAULT 0,
  arr DECIMAL(12, 2) DEFAULT 0,
  
  -- Customer metrics
  active_subscriptions INTEGER DEFAULT 0,
  new_subscriptions INTEGER DEFAULT 0,
  cancelled_subscriptions INTEGER DEFAULT 0,
  paused_subscriptions INTEGER DEFAULT 0,
  
  -- Revenue metrics
  total_revenue DECIMAL(12, 2) DEFAULT 0,
  failed_payments INTEGER DEFAULT 0,
  churn_rate DECIMAL(5, 4) DEFAULT 0,
  nrr DECIMAL(5, 4) DEFAULT 100,
  
  -- Customer metrics
  avg_ltv DECIMAL(10, 2) DEFAULT 0,
  avg_cac DECIMAL(10, 2) DEFAULT 0,
  avg_cac_payback_months DECIMAL(5, 2) DEFAULT 0,
  
  -- Timestamps
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  UNIQUE(metric_date)
);

CREATE INDEX idx_metrics_date ON metrics(metric_date);


-- ============================================================================
-- DATA VERIFICATION QUERIES
-- ============================================================================

-- View: Customer Subscription Summary
CREATE OR REPLACE VIEW customer_subscriptions AS
SELECT 
  c.id,
  c.email,
  c.name,
  COUNT(s.id) as subscription_count,
  STRING_AGG(DISTINCT s.status, ', ') as subscription_statuses,
  MAX(s.current_period_end) as next_renewal,
  COUNT(CASE WHEN s.status = 'active' THEN 1 END) as active_count
FROM customers c
LEFT JOIN subscriptions s ON c.id = s.customer_id
GROUP BY c.id, c.email, c.name;

-- View: Monthly Revenue Summary
CREATE OR REPLACE VIEW monthly_revenue AS
SELECT 
  DATE_TRUNC('month', i.created_at)::date as month,
  COUNT(DISTINCT i.customer_id) as unique_customers,
  COUNT(i.id) as total_invoices,
  SUM(i.amount_total) as total_revenue,
  SUM(CASE WHEN i.status = 'paid' THEN i.amount_paid ELSE 0 END) as paid_revenue,
  SUM(CASE WHEN i.status = 'failed' THEN 1 ELSE 0 END) as failed_count
FROM invoices i
GROUP BY DATE_TRUNC('month', i.created_at);

-- View: Churn Analysis
CREATE OR REPLACE VIEW churn_analysis AS
SELECT 
  DATE_TRUNC('month', s.cancelled_at)::date as month,
  COUNT(s.id) as cancelled_subscriptions,
  ROUND(
    COUNT(s.id)::numeric / NULLIF((
      SELECT COUNT(DISTINCT s2.id)
      FROM subscriptions s2
      WHERE s2.created_at < DATE_TRUNC('month', s.cancelled_at)
    ), 0) * 100, 2
  ) as churn_rate
FROM subscriptions s
WHERE s.cancelled_at IS NOT NULL
GROUP BY DATE_TRUNC('month', s.cancelled_at);
