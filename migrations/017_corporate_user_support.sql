--
-- Migration 017: Corporate User Support
-- Adds columns to support enterprise/corporate users across all industries
--
-- Created: 2025-11-15
-- Purpose: Enable full corporate user profiles with company information
--

BEGIN;

-- Add corporate user fields to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS company VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS job_title VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS department VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS country VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS industry VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS company_size VARCHAR(50);

-- Add verification token column if email_verification_tokens table doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'email_verification_tokens') THEN
        ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token VARCHAR(255);
        CREATE INDEX IF NOT EXISTS idx_users_email_token ON users(email_verification_token);
    END IF;
END $$;

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_users_company ON users(company) WHERE company IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_industry ON users(industry) WHERE industry IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email_verified);
CREATE INDEX IF NOT EXISTS idx_users_full_name ON users(full_name) WHERE full_name IS NOT NULL;

-- Add comments for documentation
COMMENT ON COLUMN users.full_name IS 'User''s full legal name';
COMMENT ON COLUMN users.company IS 'Company/organization name for corporate users';
COMMENT ON COLUMN users.job_title IS 'User''s job title/role within organization';
COMMENT ON COLUMN users.department IS 'Department within organization';
COMMENT ON COLUMN users.phone IS 'Contact phone number';
COMMENT ON COLUMN users.country IS 'Country of residence or primary business location';
COMMENT ON COLUMN users.industry IS 'Industry sector (technology, healthcare, finance, etc.)';
COMMENT ON COLUMN users.company_size IS 'Size of company (1-10, 11-50, 51-200, 201-1000, 1000+)';
COMMENT ON COLUMN users.email_verified IS 'Whether email address has been verified';

-- Create a view for corporate users for easier querying
CREATE OR REPLACE VIEW corporate_users AS
SELECT
    u.id,
    u.email,
    u.username,
    u.full_name,
    u.company,
    u.job_title,
    u.department,
    u.industry,
    u.company_size,
    u.country,
    u.is_active,
    u.created_at,
    u.last_login,
    COUNT(DISTINCT ud.id) as domain_count,
    us.tier_name
FROM users u
LEFT JOIN user_domains ud ON u.id = ud.user_id
LEFT JOIN user_subscriptions us ON u.id = us.user_id
WHERE u.company IS NOT NULL
GROUP BY u.id, u.email, u.username, u.full_name, u.company, u.job_title,
         u.department, u.industry, u.company_size, u.country, u.is_active,
         u.created_at, u.last_login, us.tier_name;

COMMENT ON VIEW corporate_users IS 'View of all corporate/enterprise users with subscription and usage stats';

-- Log migration
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'schema_migrations') THEN
        INSERT INTO schema_migrations (version, description, applied_at)
        VALUES ('017', 'Corporate User Support - added company fields for enterprise users', NOW())
        ON CONFLICT (version) DO NOTHING;
    END IF;
END $$;

COMMIT;

-- Verification queries (for manual testing)
-- SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_name = 'users' AND column_name IN ('full_name', 'company', 'job_title', 'industry');
-- SELECT * FROM corporate_users LIMIT 5;
