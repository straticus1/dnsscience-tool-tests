#!/usr/bin/env python3
"""
Complete Database Setup Script for DNS Science
Runs all schema files to set up the complete database
"""
import os
import sys
import psycopg2

# Database connection info
DB_HOST = "dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com"
DB_PORT = 5432
DB_NAME = "dnsscience"
DB_USER = "dnsscience"
DB_PASS = "lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK"

# Schema SQL files to execute (in order)
SCHEMA_FILES = [
    # Core schemas
    ("sql-files/schema_postgres.sql", "Core PostgreSQL schema"),
    ("sql-files/schema_threat_intel.sql", "Threat Intelligence tables"),
    ("sql-files/schema_enrichment.sql", "Domain enrichment tables"),
    ("sql-files/schema_geoip_mapping.sql", "GeoIP mapping tables"),
    ("sql-files/schema_reverse_dns.sql", "Reverse DNS tables"),
    ("sql-files/schema_web3_domains.sql", "Web3/blockchain domain tables"),
    ("sql-files/schema_stix_taxii.sql", "STIX/TAXII threat exchange"),

    # Auth and user management
    ("sql-files/schema_auth.sql", "Authentication tables"),
    ("sql-files/schema_subscriptions.sql", "User subscriptions"),
    ("sql-files/schema_audit_logs.sql", "Audit logging"),
    ("sql-files/schema_user_features.sql", "User features"),

    # Reporting and analytics
    ("sql-files/schema_reports.sql", "Reporting tables"),

    # Custom fixes
    ("schema_fixes.sql", "Schema fixes and indexes"),
    ("schema_zeek_suricata.sql", "Zeek and Suricata integration"),
]

# Additional SQL to run after schemas
ADDITIONAL_SQL = """
-- Discovered domains table for domain discovery daemon
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

CREATE INDEX IF NOT EXISTS idx_discovered_domains_domain_name ON discovered_domains(domain_name);
CREATE INDEX IF NOT EXISTS idx_discovered_domains_tld ON discovered_domains(tld);
CREATE INDEX IF NOT EXISTS idx_discovered_domains_source ON discovered_domains(source);
CREATE INDEX IF NOT EXISTS idx_discovered_domains_queued ON discovered_domains(queued_for_enrichment);
CREATE INDEX IF NOT EXISTS idx_discovered_domains_enriched ON discovered_domains(enriched);

-- Abuse.ch ThreatFox table for threatinteld daemon
CREATE TABLE IF NOT EXISTS abusech_threatfox (
    id SERIAL PRIMARY KEY,
    ioc_id VARCHAR(50) UNIQUE NOT NULL,
    ioc_type VARCHAR(50),
    ioc_value TEXT,
    threat_type VARCHAR(100),
    malware_family VARCHAR(100),
    confidence_level INTEGER,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    reference_urls TEXT[],
    tags TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threatfox_ioc_value ON abusech_threatfox(ioc_value);
CREATE INDEX IF NOT EXISTS idx_threatfox_malware ON abusech_threatfox(malware_family);
CREATE INDEX IF NOT EXISTS idx_threatfox_type ON abusech_threatfox(ioc_type);

-- SSL/TLS monitoring queue
CREATE TABLE IF NOT EXISTS ssl_scan_queue (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    port INTEGER DEFAULT 443,
    priority INTEGER DEFAULT 5,
    queued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scanned_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_ssl_queue_status ON ssl_scan_queue(status);
CREATE INDEX IF NOT EXISTS idx_ssl_queue_priority ON ssl_scan_queue(priority, queued_at);

-- Enrichment queue
CREATE TABLE IF NOT EXISTS enrichment_queue (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id),
    domain_name VARCHAR(255),
    enrichment_type VARCHAR(50),
    priority INTEGER DEFAULT 5,
    queued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending',
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrich_queue_status ON enrichment_queue(status);
CREATE INDEX IF NOT EXISTS idx_enrich_queue_priority ON enrichment_queue(priority, queued_at);
CREATE INDEX IF NOT EXISTS idx_enrich_queue_type ON enrichment_queue(enrichment_type);
"""

def connect_db():
    """Connect to database"""
    print(f"Connecting to {DB_HOST}...")
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

def execute_sql_file(conn, filepath, description):
    """Execute SQL from file"""
    print(f"\n{'='*80}")
    print(f"Executing: {description}")
    print(f"File: {filepath}")
    print(f"{'='*80}")

    if not os.path.exists(filepath):
        print(f"⚠ Warning: File not found: {filepath}")
        return False

    try:
        with open(filepath, 'r') as f:
            sql = f.read()

        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
        cur.close()

        print(f"✓ Successfully executed {filepath}")
        return True

    except Exception as e:
        print(f"✗ Error executing {filepath}: {str(e)[:200]}")
        conn.rollback()
        return False

def execute_sql(conn, sql, description):
    """Execute SQL directly"""
    print(f"\n{'='*80}")
    print(f"Executing: {description}")
    print(f"{'='*80}")

    try:
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
        cur.close()

        print(f"✓ Successfully executed: {description}")
        return True

    except Exception as e:
        print(f"✗ Error: {str(e)[:200]}")
        conn.rollback()
        return False

def get_table_counts(conn):
    """Get counts of all tables"""
    print(f"\n{'='*80}")
    print("DATABASE TABLE COUNTS")
    print(f"{'='*80}")

    cur = conn.cursor()

    # Get all tables
    cur.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
        ORDER BY table_name
    """)

    tables = [row[0] for row in cur.fetchall()]

    for table in tables:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            count = cur.fetchone()[0]
            print(f"  {table:.<50} {count:>10,}")
        except:
            print(f"  {table:.<50} {'ERROR':>10}")

    cur.close()
    print(f"{'='*80}\n")

def main():
    """Main setup function"""
    print("\n" + "="*80)
    print("DNS SCIENCE - COMPLETE DATABASE SETUP")
    print("="*80 + "\n")

    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print(f"Working directory: {os.getcwd()}\n")

    # Connect to database
    try:
        conn = connect_db()
        print("✓ Connected to database\n")
    except Exception as e:
        print(f"✗ Failed to connect: {e}")
        sys.exit(1)

    # Execute schema files
    success_count = 0
    fail_count = 0

    for filepath, description in SCHEMA_FILES:
        if execute_sql_file(conn, filepath, description):
            success_count += 1
        else:
            fail_count += 1

    # Execute additional SQL
    if execute_sql(conn, ADDITIONAL_SQL, "Additional daemon tables"):
        success_count += 1
    else:
        fail_count += 1

    # Show results
    print(f"\n{'='*80}")
    print("SETUP RESULTS")
    print(f"{'='*80}")
    print(f"✓ Successful: {success_count}")
    print(f"✗ Failed: {fail_count}")
    print(f"{'='*80}\n")

    # Show table counts
    get_table_counts(conn)

    # Close connection
    conn.close()
    print("✓ Database setup complete!\n")

if __name__ == "__main__":
    main()
