-- User Service Database Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Companies table (Multi-Tenancy)
CREATE TABLE IF NOT EXISTS companies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    subscription_tier VARCHAR(50) DEFAULT 'free', -- free, pro, enterprise
    max_users INT DEFAULT 10,
    is_active BOOLEAN DEFAULT TRUE,
    settings JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for companies
CREATE INDEX idx_companies_slug ON companies(slug);
CREATE INDEX idx_companies_active ON companies(is_active) WHERE is_active = TRUE;

-- Users table (belongs to a company)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    avatar_url TEXT,
    department VARCHAR(100),
    location VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    email_verified BOOLEAN DEFAULT FALSE,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_company_email UNIQUE(company_id, email),
    CONSTRAINT unique_company_username UNIQUE(company_id, username)
);

-- Indexes for users
CREATE INDEX idx_users_company_id ON users(company_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_company_email ON users(company_id, email);
CREATE INDEX idx_users_company_username ON users(company_id, username);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_users_company_active ON users(company_id, is_active) WHERE is_active = TRUE;

-- Full-text search index for user search
CREATE INDEX idx_users_search ON users USING gin(
    to_tsvector('english', coalesce(first_name, '') || ' ' || coalesce(last_name, '') || ' ' || coalesce(email, '') || ' ' || coalesce(username, ''))
);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers to automatically update updated_at
CREATE TRIGGER update_companies_updated_at
    BEFORE UPDATE ON companies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to check user limit before insert
CREATE OR REPLACE FUNCTION check_user_limit()
RETURNS TRIGGER AS $$
DECLARE
    current_count INT;
    max_limit INT;
BEGIN
    SELECT COUNT(*), c.max_users INTO current_count, max_limit
    FROM users u
    JOIN companies c ON c.id = NEW.company_id
    WHERE u.company_id = NEW.company_id AND u.is_active = TRUE
    GROUP BY c.max_users;

    IF current_count >= max_limit THEN
        RAISE EXCEPTION 'User limit reached for company. Max users: %', max_limit;
    END IF;

    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to enforce user limit
CREATE TRIGGER enforce_user_limit
    BEFORE INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION check_user_limit();

-- Comments
COMMENT ON TABLE companies IS 'Multi-tenant companies - each company is isolated';
COMMENT ON TABLE users IS 'Users belong to companies - email uniqueness is per-company';
COMMENT ON COLUMN companies.slug IS 'URL-friendly company identifier';
COMMENT ON COLUMN companies.max_users IS 'Maximum number of users allowed based on subscription tier';
COMMENT ON COLUMN users.email IS 'Email must be unique within company (not globally)';
COMMENT ON COLUMN users.username IS 'Username must be unique within company (not globally)';
