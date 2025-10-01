-- Drop triggers
DROP TRIGGER IF EXISTS protect_system_role_flag ON roles;
DROP TRIGGER IF EXISTS protect_system_roles ON roles;
DROP TRIGGER IF EXISTS update_roles_updated_at ON roles;

-- Drop functions
DROP FUNCTION IF EXISTS prevent_system_role_flag_change();
DROP FUNCTION IF EXISTS prevent_system_role_deletion();
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_roles_permissions;
DROP INDEX IF EXISTS idx_user_roles_expires;
DROP INDEX IF EXISTS idx_user_roles_user_company;
DROP INDEX IF EXISTS idx_user_roles_company;
DROP INDEX IF EXISTS idx_user_roles_role;
DROP INDEX IF EXISTS idx_user_roles_user;
DROP INDEX IF EXISTS idx_roles_company_priority;
DROP INDEX IF EXISTS idx_roles_priority;
DROP INDEX IF EXISTS idx_roles_system;
DROP INDEX IF EXISTS idx_roles_company;

-- Drop tables
DROP TABLE IF EXISTS permission_templates;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
