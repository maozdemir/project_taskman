-- Drop triggers
DROP TRIGGER IF EXISTS enforce_user_limit ON users;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_companies_updated_at ON companies;

-- Drop functions
DROP FUNCTION IF EXISTS check_user_limit();
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes (will be dropped automatically with tables, but explicit is better)
DROP INDEX IF EXISTS idx_users_search;
DROP INDEX IF EXISTS idx_users_company_active;
DROP INDEX IF EXISTS idx_users_active;
DROP INDEX IF EXISTS idx_users_company_username;
DROP INDEX IF EXISTS idx_users_company_email;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_company_id;
DROP INDEX IF EXISTS idx_companies_active;
DROP INDEX IF EXISTS idx_companies_slug;

-- Drop tables
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS companies;
