-- Audit Service Database Schema (TimescaleDB)

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Audit events table (will be converted to hypertable)
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    event_type TEXT NOT NULL,
    actor_id UUID,
    actor_email TEXT,
    target_type TEXT,
    target_id UUID,
    company_id UUID NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL, -- success, failure
    ip_address INET,
    user_agent TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, timestamp)
);

-- Convert to hypertable for time-series optimization
-- Partition by timestamp with 1-day chunks
SELECT create_hypertable('audit_events', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Create indexes for common query patterns
-- Compound indexes for time-based queries
CREATE INDEX IF NOT EXISTS idx_audit_company_time
    ON audit_events (company_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_actor_time
    ON audit_events (actor_id, timestamp DESC)
    WHERE actor_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_type_time
    ON audit_events (event_type, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_action_time
    ON audit_events (action, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_target
    ON audit_events (target_type, target_id, timestamp DESC)
    WHERE target_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_result
    ON audit_events (result, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_email
    ON audit_events (actor_email, timestamp DESC)
    WHERE actor_email IS NOT NULL;

-- GiST index for metadata JSONB queries
CREATE INDEX IF NOT EXISTS idx_audit_metadata
    ON audit_events USING GIN (metadata);

-- Add data retention policy (keep data for 90 days, then drop)
SELECT add_retention_policy('audit_events',
    INTERVAL '90 days',
    if_not_exists => TRUE
);

-- Add compression policy (compress data older than 7 days)
SELECT add_compression_policy('audit_events',
    INTERVAL '7 days',
    if_not_exists => TRUE
);

-- Create continuous aggregates for common metrics

-- Daily event counts by company
CREATE MATERIALIZED VIEW IF NOT EXISTS audit_daily_company_stats
WITH (timescaledb.continuous) AS
SELECT
    company_id,
    time_bucket('1 day', timestamp) AS day,
    COUNT(*) AS total_events,
    COUNT(*) FILTER (WHERE result = 'success') AS success_count,
    COUNT(*) FILTER (WHERE result = 'failure') AS failure_count
FROM audit_events
GROUP BY company_id, day
WITH NO DATA;

-- Refresh policy for continuous aggregate
SELECT add_continuous_aggregate_policy('audit_daily_company_stats',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- Daily event counts by actor
CREATE MATERIALIZED VIEW IF NOT EXISTS audit_daily_actor_stats
WITH (timescaledb.continuous) AS
SELECT
    actor_id,
    actor_email,
    company_id,
    time_bucket('1 day', timestamp) AS day,
    COUNT(*) AS total_events,
    COUNT(DISTINCT action) AS unique_actions,
    COUNT(*) FILTER (WHERE result = 'success') AS success_count,
    COUNT(*) FILTER (WHERE result = 'failure') AS failure_count
FROM audit_events
WHERE actor_id IS NOT NULL
GROUP BY actor_id, actor_email, company_id, day
WITH NO DATA;

-- Refresh policy for actor stats
SELECT add_continuous_aggregate_policy('audit_daily_actor_stats',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- Event type statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS audit_daily_event_type_stats
WITH (timescaledb.continuous) AS
SELECT
    company_id,
    event_type,
    time_bucket('1 day', timestamp) AS day,
    COUNT(*) AS event_count
FROM audit_events
GROUP BY company_id, event_type, day
WITH NO DATA;

-- Refresh policy for event type stats
SELECT add_continuous_aggregate_policy('audit_daily_event_type_stats',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- Comments
COMMENT ON TABLE audit_events IS 'Stores all audit events with TimescaleDB optimizations';
COMMENT ON COLUMN audit_events.metadata IS 'Additional event-specific data stored as JSON';
COMMENT ON MATERIALIZED VIEW audit_daily_company_stats IS 'Daily aggregated statistics per company';
COMMENT ON MATERIALIZED VIEW audit_daily_actor_stats IS 'Daily aggregated statistics per actor';
COMMENT ON MATERIALIZED VIEW audit_daily_event_type_stats IS 'Daily aggregated statistics per event type';