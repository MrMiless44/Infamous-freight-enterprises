-- Phase 4: PostgreSQL Multi-Region Replication Setup
-- Primary-Replica configuration for global database deployment

-- ============================================================================
-- PRIMARY DATABASE CONFIGURATION (US-EAST-1)
-- ============================================================================

-- Enable logical replication on primary
ALTER SYSTEM SET wal_level = 'logical';
ALTER SYSTEM SET max_wal_senders = 10;
ALTER SYSTEM SET max_replication_slots = 10;
ALTER SYSTEM SET max_logical_replication_workers = 10;
ALTER SYSTEM SET synchronous_commit = 'remote_apply';

-- Reload configuration
SELECT pg_reload_conf();

-- Create replication user
CREATE USER replicator WITH REPLICATION PASSWORD 'SECURE_PASSWORD_HERE';
GRANT CONNECT ON DATABASE "infamous_freight" TO replicator;
GRANT USAGE ON SCHEMA public TO replicator;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO replicator;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO replicator;

-- Create publication for all tables
CREATE PUBLICATION infamous_freight_pub FOR ALL TABLES;

-- Verify publication
SELECT * FROM pg_publication;

-- Create replication slots for each replica
SELECT pg_create_logical_replication_slot('eu_central_1_slot', 'pgoutput');
SELECT pg_create_logical_replication_slot('ap_southeast_1_slot', 'pgoutput');

-- Monitor replication lag
CREATE OR REPLACE FUNCTION check_replication_lag()
RETURNS TABLE (
    slot_name text,
    confirmed_flush_lsn pg_lsn,
    lag_bytes bigint,
    lag_seconds numeric
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.slot_name,
        s.confirmed_flush_lsn,
        pg_wal_lsn_diff(pg_current_wal_lsn(), s.confirmed_flush_lsn) as lag_bytes,
        EXTRACT(EPOCH FROM (now() - s.confirmed_flush_lsn::text::timestamp)) as lag_seconds
    FROM pg_replication_slots s
    WHERE s.active = true;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- REPLICA CONFIGURATION (EU-CENTRAL-1)
-- ============================================================================

-- On EU replica, create subscription
CREATE SUBSCRIPTION eu_central_1_sub
    CONNECTION 'host=us-east-1.infamous-freight.com port=5432 dbname=infamous_freight user=replicator password=SECURE_PASSWORD_HERE'
    PUBLICATION infamous_freight_pub
    WITH (
        copy_data = true,
        create_slot = false,
        slot_name = 'eu_central_1_slot',
        synchronous_commit = 'remote_apply'
    );

-- Enable read queries on replica
ALTER SYSTEM SET hot_standby = on;
ALTER SYSTEM SET max_standby_streaming_delay = '30s';

-- ============================================================================
-- REPLICA CONFIGURATION (AP-SOUTHEAST-1)
-- ============================================================================

-- On Asia replica, create subscription
CREATE SUBSCRIPTION ap_southeast_1_sub
    CONNECTION 'host=us-east-1.infamous-freight.com port=5432 dbname=infamous_freight user=replicator password=SECURE_PASSWORD_HERE'
    PUBLICATION infamous_freight_pub
    WITH (
        copy_data = true,
        create_slot = false,
        slot_name = 'ap_southeast_1_slot',
        synchronous_commit = 'remote_apply'
    );

-- Enable read queries on replica
ALTER SYSTEM SET hot_standby = on;
ALTER SYSTEM SET max_standby_streaming_delay = '30s';

-- ============================================================================
-- MONITORING VIEWS
-- ============================================================================

-- Create monitoring view for replication status
CREATE OR REPLACE VIEW replication_status AS
SELECT 
    s.slot_name,
    s.active,
    s.restart_lsn,
    s.confirmed_flush_lsn,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), s.confirmed_flush_lsn)) as replication_lag_size,
    CASE 
        WHEN s.active THEN 'connected'
        ELSE 'disconnected'
    END as connection_status,
    sr.client_addr,
    sr.state,
    sr.sync_state,
    EXTRACT(EPOCH FROM (now() - sr.reply_time)) as last_msg_seconds_ago
FROM pg_replication_slots s
LEFT JOIN pg_stat_replication sr ON s.slot_name = sr.application_name;

-- Create alerts table for replication issues
CREATE TABLE IF NOT EXISTS replication_alerts (
    id SERIAL PRIMARY KEY,
    alert_time TIMESTAMPTZ DEFAULT NOW(),
    region TEXT NOT NULL,
    severity TEXT CHECK (severity IN ('info', 'warning', 'critical')),
    message TEXT NOT NULL,
    lag_bytes BIGINT,
    resolved BOOLEAN DEFAULT false,
    resolved_at TIMESTAMPTZ
);

-- Create index on replication alerts
CREATE INDEX idx_replication_alerts_unresolved ON replication_alerts(resolved, alert_time DESC) WHERE resolved = false;

-- Function to check and alert on replication lag
CREATE OR REPLACE FUNCTION monitor_replication_lag()
RETURNS void AS $$
DECLARE
    lag_record RECORD;
    warning_threshold BIGINT := 104857600; -- 100MB
    critical_threshold BIGINT := 1073741824; -- 1GB
BEGIN
    FOR lag_record IN SELECT * FROM check_replication_lag() LOOP
        -- Critical alert: lag > 1GB or > 60 seconds
        IF lag_record.lag_bytes > critical_threshold OR lag_record.lag_seconds > 60 THEN
            INSERT INTO replication_alerts (region, severity, message, lag_bytes)
            VALUES (
                lag_record.slot_name,
                'critical',
                format('Replication lag critical: %s bytes (%s seconds)',
                    lag_record.lag_bytes, lag_record.lag_seconds),
                lag_record.lag_bytes
            );
        
        -- Warning alert: lag > 100MB or > 30 seconds
        ELSIF lag_record.lag_bytes > warning_threshold OR lag_record.lag_seconds > 30 THEN
            INSERT INTO replication_alerts (region, severity, message, lag_bytes)
            VALUES (
                lag_record.slot_name,
                'warning',
                format('Replication lag warning: %s bytes (%s seconds)',
                    lag_record.lag_bytes, lag_record.lag_seconds),
                lag_record.lag_bytes
            );
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Schedule monitoring (requires pg_cron extension)
-- SELECT cron.schedule('monitor-replication', '* * * * *', 'SELECT monitor_replication_lag()');

-- ============================================================================
-- READ REPLICA ROUTING
-- ============================================================================

-- Create function to route reads to nearest replica
CREATE OR REPLACE FUNCTION get_read_replica_host(client_region TEXT)
RETURNS TEXT AS $$
BEGIN
    CASE client_region
        WHEN 'us-east' THEN
            RETURN 'us-east-1.infamous-freight.com';
        WHEN 'eu-central' THEN
            RETURN 'eu-central-1.infamous-freight.com';
        WHEN 'ap-southeast' THEN
            RETURN 'ap-southeast-1.infamous-freight.com';
        ELSE
            -- Default to primary
            RETURN 'us-east-1.infamous-freight.com';
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- FAILOVER PROCEDURES
-- ============================================================================

-- Promote replica to primary (run on replica)
CREATE OR REPLACE FUNCTION promote_replica_to_primary()
RETURNS void AS $$
BEGIN
    -- Disable subscription
    ALTER SUBSCRIPTION ALL DISABLE;
    
    -- Drop subscription (careful!)
    -- ALTER SUBSCRIPTION ALL DROP;
    
    -- Enable writes
    ALTER SYSTEM RESET synchronous_standby_names;
    SELECT pg_reload_conf();
    
    -- Create publication for reverse replication
    CREATE PUBLICATION IF NOT EXISTS infamous_freight_pub FOR ALL TABLES;
    
    RAISE NOTICE 'Replica promoted to primary. Configure old primary as replica.';
END;
$$ LANGUAGE plpgsql;

-- Demote primary to replica (run on old primary)
CREATE OR REPLACE FUNCTION demote_primary_to_replica(new_primary_host TEXT)
RETURNS void AS $$
BEGIN
    -- Drop publication
    DROP PUBLICATION IF EXISTS infamous_freight_pub CASCADE;
    
    -- Create subscription to new primary
    EXECUTE format(
        'CREATE SUBSCRIPTION %I CONNECTION ''host=%s port=5432 dbname=infamous_freight user=replicator password=SECURE_PASSWORD_HERE'' PUBLICATION infamous_freight_pub',
        'sub_to_new_primary',
        new_primary_host
    );
    
    RAISE NOTICE 'Old primary demoted to replica. Replicating from %', new_primary_host;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- BACKUP CONFIGURATION
-- ============================================================================

-- Create backup metadata table
CREATE TABLE IF NOT EXISTS backup_metadata (
    id SERIAL PRIMARY KEY,
    backup_time TIMESTAMPTZ DEFAULT NOW(),
    backup_type TEXT CHECK (backup_type IN ('full', 'incremental', 'wal')),
    region TEXT NOT NULL,
    size_bytes BIGINT,
    location TEXT NOT NULL,
    checksum TEXT,
    status TEXT CHECK (status IN ('in_progress', 'completed', 'failed')),
    completion_time TIMESTAMPTZ,
    error_message TEXT
);

-- Create index on backup metadata
CREATE INDEX idx_backup_metadata_time ON backup_metadata(backup_time DESC);
CREATE INDEX idx_backup_metadata_type ON backup_metadata(backup_type, status);

-- Function to log backup completion
CREATE OR REPLACE FUNCTION log_backup_completion(
    p_backup_type TEXT,
    p_region TEXT,
    p_size_bytes BIGINT,
    p_location TEXT,
    p_checksum TEXT
)
RETURNS void AS $$
BEGIN
    INSERT INTO backup_metadata (backup_type, region, size_bytes, location, checksum, status, completion_time)
    VALUES (p_backup_type, p_region, p_size_bytes, p_location, p_checksum, 'completed', NOW());
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PERFORMANCE OPTIMIZATION FOR REPLICATION
-- ============================================================================

-- Optimize for replication performance
ALTER SYSTEM SET shared_buffers = '4GB';
ALTER SYSTEM SET effective_cache_size = '12GB';
ALTER SYSTEM SET maintenance_work_mem = '1GB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET min_wal_size = '2GB';
ALTER SYSTEM SET max_wal_size = '8GB';

-- Enable parallel query execution
ALTER SYSTEM SET max_parallel_workers_per_gather = 4;
ALTER SYSTEM SET max_parallel_workers = 8;
ALTER SYSTEM SET max_worker_processes = 8;

-- Reload configuration
SELECT pg_reload_conf();

-- ============================================================================
-- VERIFY REPLICATION SETUP
-- ============================================================================

-- Query to verify replication is working
SELECT 
    application_name,
    client_addr,
    state,
    sync_state,
    pg_size_pretty(pg_wal_lsn_diff(sent_lsn, write_lsn)) as write_lag,
    pg_size_pretty(pg_wal_lsn_diff(sent_lsn, flush_lsn)) as flush_lag,
    pg_size_pretty(pg_wal_lsn_diff(sent_lsn, replay_lsn)) as replay_lag,
    write_lag as write_lag_duration,
    flush_lag as flush_lag_duration,
    replay_lag as replay_lag_duration
FROM pg_stat_replication;

-- Query to check subscription status (run on replicas)
SELECT 
    subname,
    subenabled,
    subconninfo,
    subslotname,
    subsynccommit
FROM pg_subscription;

-- Query to check replication slots
SELECT 
    slot_name,
    plugin,
    slot_type,
    database,
    active,
    restart_lsn,
    confirmed_flush_lsn,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn)) as lag_size
FROM pg_replication_slots;

-- ============================================================================
-- EXPECTED REPLICATION PERFORMANCE
-- ============================================================================

/*
Expected Performance Metrics:
- Replication lag: <100ms (US-EU), <150ms (US-Asia)
- Data consistency: Eventually consistent (< 1 second)
- Throughput: 10,000+ transactions/sec
- Availability: 99.99% uptime
- RPO: 15 minutes (Recovery Point Objective)
- RTO: 30 minutes (Recovery Time Objective)

Monitoring Commands:
- Check lag: SELECT * FROM replication_status;
- Check alerts: SELECT * FROM replication_alerts WHERE resolved = false;
- Verify replication: SELECT * FROM pg_stat_replication;
- Monitor performance: SELECT * FROM pg_stat_database;
*/
