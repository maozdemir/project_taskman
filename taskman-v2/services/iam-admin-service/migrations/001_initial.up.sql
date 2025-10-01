-- IAM Admin Service Database Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Roles table (per company)
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE, -- admin, user (cannot be deleted)
    priority INT DEFAULT 0, -- Higher priority = more powerful (admin = 100)
    permissions JSONB DEFAULT '[]'::jsonb, -- Array of permission strings
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_company_role_name UNIQUE(company_id, name)
);

-- User-Role assignments
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    company_id UUID NOT NULL,
    assigned_by UUID NOT NULL, -- user_id who assigned
    assigned_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP, -- Optional expiration
    CONSTRAINT unique_user_role UNIQUE(user_id, role_id)
);

-- Permission templates (optional - for easier role creation)
CREATE TABLE IF NOT EXISTS permission_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    category VARCHAR(50), -- e.g., 'tasks', 'users', 'admin'
    permissions JSONB NOT NULL, -- Array of permission strings
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for roles
CREATE INDEX idx_roles_company ON roles(company_id);
CREATE INDEX idx_roles_system ON roles(is_system_role) WHERE is_system_role = TRUE;
CREATE INDEX idx_roles_priority ON roles(priority DESC);
CREATE INDEX idx_roles_company_priority ON roles(company_id, priority DESC);

-- Indexes for user_roles
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);
CREATE INDEX idx_user_roles_company ON user_roles(company_id);
CREATE INDEX idx_user_roles_user_company ON user_roles(user_id, company_id);
CREATE INDEX idx_user_roles_expires ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- GIN index for permission search
CREATE INDEX idx_roles_permissions ON roles USING GIN (permissions);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to automatically update updated_at
CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to prevent deletion of system roles
CREATE OR REPLACE FUNCTION prevent_system_role_deletion()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.is_system_role = TRUE THEN
        RAISE EXCEPTION 'Cannot delete system role: %', OLD.name;
    END IF;
    RETURN OLD;
END;
$$ language 'plpgsql';

-- Trigger to prevent system role deletion
CREATE TRIGGER protect_system_roles
    BEFORE DELETE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION prevent_system_role_deletion();

-- Function to prevent modification of system role flag
CREATE OR REPLACE FUNCTION prevent_system_role_flag_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.is_system_role != NEW.is_system_role THEN
        RAISE EXCEPTION 'Cannot change is_system_role flag';
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to prevent system role flag modification
CREATE TRIGGER protect_system_role_flag
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION prevent_system_role_flag_change();

-- Insert default permission templates
INSERT INTO permission_templates (name, description, category, permissions) VALUES
('Admin Full Access', 'Full administrative access with all permissions', 'admin', '["*:*"]'::jsonb),
('Task Manager', 'Full access to task management', 'tasks', '["tasks:*", "projects:*"]'::jsonb),
('Task User', 'Basic task access (own tasks only)', 'tasks', '["tasks:read:own", "tasks:create", "tasks:update:own", "tasks:delete:own"]'::jsonb),
('User Manager', 'Manage users within company', 'users', '["users:*", "roles:read"]'::jsonb),
('User Viewer', 'View users and their details', 'users', '["users:read"]'::jsonb),
('Role Manager', 'Manage roles and permissions', 'admin', '["roles:*", "permissions:*"]'::jsonb),
('Audit Viewer', 'View audit logs and reports', 'admin', '["audit:read", "reports:read"]'::jsonb),
('Company Admin', 'Manage company settings', 'admin', '["company:*", "settings:*"]'::jsonb);

-- Comments
COMMENT ON TABLE roles IS 'Roles are scoped to companies. System roles (admin, user) cannot be deleted';
COMMENT ON COLUMN roles.priority IS 'Admin role has priority 100, regular roles 0-50. Higher priority = more powerful';
COMMENT ON COLUMN roles.permissions IS 'Array of permission strings like ["*:*"], ["tasks:*"], ["users:read"]';
COMMENT ON TABLE user_roles IS 'Users can have multiple roles within their company';
COMMENT ON COLUMN user_roles.expires_at IS 'Optional expiration for temporary role assignments';
COMMENT ON TABLE permission_templates IS 'Predefined permission sets for easier role creation';
