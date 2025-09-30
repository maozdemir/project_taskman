-- Drop continuous aggregates
DROP MATERIALIZED VIEW IF EXISTS audit_daily_event_type_stats CASCADE;
DROP MATERIALIZED VIEW IF EXISTS audit_daily_actor_stats CASCADE;
DROP MATERIALIZED VIEW IF EXISTS audit_daily_company_stats CASCADE;

-- Drop table (this will also remove hypertable, compression, and retention policies)
DROP TABLE IF EXISTS audit_events CASCADE;

-- Note: Not dropping extensions as they might be used by other schemas
-- DROP EXTENSION IF EXISTS timescaledb CASCADE;
-- DROP EXTENSION IF EXISTS "uuid-ossp";