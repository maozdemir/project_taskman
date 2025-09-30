-- Drop triggers
DROP TRIGGER IF EXISTS update_sessions_updated_at ON sessions;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS sessions;

-- Drop extension (optional, might be used by other schemas)
-- DROP EXTENSION IF EXISTS "uuid-ossp";