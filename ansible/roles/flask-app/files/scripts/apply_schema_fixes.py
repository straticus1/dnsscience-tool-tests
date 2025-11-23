#!/usr/bin/env python3
"""Apply schema fixes to RDS database"""

import psycopg2
import sys

DB_CONFIG = {
    'host': 'dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com',
    'port': 5432,
    'database': 'dnsscience',
    'user': 'dnsscience',
    'password': 'lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK'
}

# Schema fixes to apply
SCHEMA_FIXES = [
    # Fix 1: Add 'notes' column to cisa_kev_vulnerabilities
    """
    ALTER TABLE cisa_kev_vulnerabilities
    ADD COLUMN IF NOT EXISTS notes TEXT;
    """,

    # Update existing data
    """
    UPDATE cisa_kev_vulnerabilities
    SET notes = cisa_notes
    WHERE notes IS NULL AND cisa_notes IS NOT NULL;
    """,

    # Fix 2: Ensure discovered_domains table exists
    """
    CREATE TABLE IF NOT EXISTS discovered_domains (
        id SERIAL PRIMARY KEY,
        domain_name VARCHAR(255) UNIQUE NOT NULL,
        tld VARCHAR(63) NOT NULL,
        source VARCHAR(100) NOT NULL,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        times_seen INTEGER DEFAULT 1,
        queued_for_enrichment BOOLEAN DEFAULT FALSE,
        enriched BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,

    # Indexes for discovered_domains
    """
    CREATE INDEX IF NOT EXISTS idx_discovered_domains_name ON discovered_domains(domain_name);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_discovered_domains_tld ON discovered_domains(tld);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_discovered_domains_source ON discovered_domains(source);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_discovered_domains_queued ON discovered_domains(queued_for_enrichment) WHERE queued_for_enrichment = TRUE;
    """,

    # Fix 3: Ensure ssl_scan_results table exists
    """
    CREATE TABLE IF NOT EXISTS ssl_scan_results (
        id SERIAL PRIMARY KEY,
        domain_name VARCHAR(255) NOT NULL,
        port INTEGER NOT NULL,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        grade VARCHAR(3),
        certificate_data JSONB,
        expires_at TIMESTAMP,
        is_expired BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,

    # Indexes for ssl_scan_results
    """
    CREATE INDEX IF NOT EXISTS idx_ssl_scan_domain ON ssl_scan_results(domain_name);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_ssl_scan_port ON ssl_scan_results(port);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_ssl_scan_grade ON ssl_scan_results(grade);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_ssl_scan_expired ON ssl_scan_results(is_expired);
    """,

    # Fix 4: Ensure threat_intelligence table exists
    """
    CREATE TABLE IF NOT EXISTS threat_intelligence (
        id SERIAL PRIMARY KEY,
        feed_name VARCHAR(100) NOT NULL,
        indicator_type VARCHAR(50) NOT NULL,
        indicator_value TEXT NOT NULL,
        severity VARCHAR(20) DEFAULT 'medium',
        metadata JSONB,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        times_seen INTEGER DEFAULT 1,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(feed_name, indicator_value)
    );
    """,

    # Indexes for threat_intelligence
    """
    CREATE INDEX IF NOT EXISTS idx_threat_intel_feed ON threat_intelligence(feed_name);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intelligence(indicator_type);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_threat_intel_value ON threat_intelligence(indicator_value);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_threat_intel_severity ON threat_intelligence(severity);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_threat_intel_active ON threat_intelligence(is_active) WHERE is_active = TRUE;
    """,

    # Fix 5: Ensure threat_intel_iocs table exists
    """
    CREATE TABLE IF NOT EXISTS threat_intel_iocs (
        id SERIAL PRIMARY KEY,
        indicator_value TEXT NOT NULL,
        indicator_type VARCHAR(50) NOT NULL,
        threat_type VARCHAR(100),
        malware_family VARCHAR(255),
        confidence_level INTEGER DEFAULT 50,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        source VARCHAR(100) NOT NULL,
        tags TEXT,
        metadata JSONB,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(indicator_value, source)
    );
    """,

    # Indexes for threat_intel_iocs
    """
    CREATE INDEX IF NOT EXISTS idx_threat_iocs_value ON threat_intel_iocs(indicator_value);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_threat_iocs_type ON threat_intel_iocs(indicator_type);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_threat_iocs_source ON threat_intel_iocs(source);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_threat_iocs_active ON threat_intel_iocs(is_active) WHERE is_active = TRUE;
    """,

    # Fix 6: Add missing columns to domains table
    """
    ALTER TABLE domains ADD COLUMN IF NOT EXISTS last_ssl_scan TIMESTAMP;
    """,
    """
    ALTER TABLE domains ADD COLUMN IF NOT EXISTS ssl_enabled BOOLEAN DEFAULT FALSE;
    """,
    """
    ALTER TABLE domains ADD COLUMN IF NOT EXISTS ssl_grade VARCHAR(3);
    """,
    """
    ALTER TABLE domains ADD COLUMN IF NOT EXISTS ssl_expiry_date TIMESTAMP;
    """,
    """
    ALTER TABLE domains ADD COLUMN IF NOT EXISTS ssl_expired BOOLEAN DEFAULT FALSE;
    """,
    """
    ALTER TABLE domains ADD COLUMN IF NOT EXISTS ssl_issuer JSONB;
    """,
    """
    ALTER TABLE domains ADD COLUMN IF NOT EXISTS last_enriched TIMESTAMP;
    """,
    """
    ALTER TABLE domains ADD COLUMN IF NOT EXISTS last_threat_check TIMESTAMP;
    """,
    """
    ALTER TABLE domains ADD COLUMN IF NOT EXISTS threat_level VARCHAR(20);
    """
]

def main():
    print("Connecting to RDS database...")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        cursor = conn.cursor()
        print("Connected successfully!")

        total_fixes = len(SCHEMA_FIXES)
        successful = 0
        failed = 0

        for i, fix in enumerate(SCHEMA_FIXES, 1):
            try:
                print(f"\nApplying fix {i}/{total_fixes}...")
                cursor.execute(fix)
                print(f"  ✓ Success")
                successful += 1
            except Exception as e:
                print(f"  ✗ Failed: {e}")
                failed += 1

        print(f"\n{'='*60}")
        print(f"Schema Fixes Complete!")
        print(f"{'='*60}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Total: {total_fixes}")

        cursor.close()
        conn.close()

        return 0 if failed == 0 else 1

    except Exception as e:
        print(f"ERROR: Failed to connect to database: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
