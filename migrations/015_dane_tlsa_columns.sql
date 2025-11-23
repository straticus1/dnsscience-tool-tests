-- Migration: Add DANE/TLSA support to email_security_records
-- Date: 2025-11-15
-- Purpose: Enable DANE/TLSA record collection for email security monitoring
--
-- DANE (DNS-based Authentication of Named Entities) allows mail servers to
-- advertise which certificates are valid via TLSA records in DNS.
-- This provides an additional layer of email security beyond SPF/DKIM/DMARC.

BEGIN;

-- Add DANE detection flag
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS has_dane BOOLEAN DEFAULT false;

-- Add TLSA records storage (JSON array format)
-- Each record contains: port, usage, selector, matching_type, cert_data
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS tlsa_records JSONB DEFAULT '[]'::jsonb;

-- Add count for quick statistics
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS tlsa_count INTEGER DEFAULT 0;

-- Create index for queries filtering by DANE presence
-- Partial index only includes rows where DANE is enabled (saves space)
CREATE INDEX IF NOT EXISTS idx_email_security_dane
ON email_security_records(has_dane)
WHERE has_dane = true;

-- Add helpful comments for documentation
COMMENT ON COLUMN email_security_records.has_dane IS
'Whether domain has DANE TLSA records configured for email security';

COMMENT ON COLUMN email_security_records.tlsa_records IS
'Array of TLSA records with structure: [{port: 25|443, usage: 0-3, selector: 0-1, matching_type: 0-2, cert_data: hex_string}]';

COMMENT ON COLUMN email_security_records.tlsa_count IS
'Total number of TLSA records found across all ports (typically 25 and 443)';

COMMIT;

-- Verification query (run after migration)
-- SELECT
--     COUNT(*) as total_records,
--     COUNT(CASE WHEN has_dane THEN 1 END) as with_dane,
--     ROUND(100.0 * COUNT(CASE WHEN has_dane THEN 1 END) / COUNT(*), 2) as dane_percentage
-- FROM email_security_records;
