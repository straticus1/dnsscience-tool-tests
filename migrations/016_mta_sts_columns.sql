-- Migration: Add MTA-STS support to email_security_records
-- Date: 2025-11-15
-- Purpose: Enable MTA-STS (Mail Transfer Agent Strict Transport Security) policy collection
--
-- MTA-STS is a security standard that enables mail servers to declare their ability to
-- receive TLS-encrypted email and to specify whether sending servers should refuse to
-- deliver mail that cannot be delivered securely.
--
-- MTA-STS involves two components:
-- 1. DNS TXT record at _mta-sts.<domain> (contains policy version ID)
-- 2. HTTPS policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt

BEGIN;

-- Add MTA-STS detection flag
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS has_mta_sts BOOLEAN DEFAULT false;

-- Add full policy text (for audit/analysis)
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS mta_sts_policy TEXT;

-- Add parsed mode field (enforce, testing, or none)
-- enforce: Sending MTAs must not deliver mail if secure connection fails
-- testing: Sending MTAs should attempt secure connection but can fallback
-- none: MTA-STS is not active
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS mta_sts_mode VARCHAR(20);

-- Add max_age field (how long policy should be cached in seconds)
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS mta_sts_max_age INTEGER;

-- Create index for queries filtering by MTA-STS presence
-- Partial index only includes rows where MTA-STS is enabled
CREATE INDEX IF NOT EXISTS idx_email_security_mta_sts
ON email_security_records(has_mta_sts)
WHERE has_mta_sts = true;

-- Create index for querying by mode (useful for security audits)
CREATE INDEX IF NOT EXISTS idx_email_security_mta_sts_mode
ON email_security_records(mta_sts_mode)
WHERE mta_sts_mode IS NOT NULL;

-- Add helpful comments for documentation
COMMENT ON COLUMN email_security_records.has_mta_sts IS
'Whether domain has MTA-STS policy configured (both DNS record and HTTPS policy present)';

COMMENT ON COLUMN email_security_records.mta_sts_policy IS
'Full text of the MTA-STS policy file retrieved from .well-known/mta-sts.txt';

COMMENT ON COLUMN email_security_records.mta_sts_mode IS
'MTA-STS enforcement mode: enforce (strict), testing (report-only), or none (disabled)';

COMMENT ON COLUMN email_security_records.mta_sts_max_age IS
'MTA-STS policy cache duration in seconds (how long sending MTAs should cache the policy)';

COMMIT;

-- Verification query (run after migration)
-- SELECT
--     COUNT(*) as total_records,
--     COUNT(CASE WHEN has_mta_sts THEN 1 END) as with_mta_sts,
--     COUNT(CASE WHEN mta_sts_mode = 'enforce' THEN 1 END) as enforce_mode,
--     COUNT(CASE WHEN mta_sts_mode = 'testing' THEN 1 END) as testing_mode,
--     ROUND(100.0 * COUNT(CASE WHEN has_mta_sts THEN 1 END) / COUNT(*), 2) as mta_sts_percentage
-- FROM email_security_records;
