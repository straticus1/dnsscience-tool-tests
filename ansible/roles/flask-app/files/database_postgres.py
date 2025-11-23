"""PostgreSQL database support for internet-scale operations

For scale beyond ~100K domains, PostgreSQL is recommended over SQLite.

Setup:
1. Install PostgreSQL
2. Create database: createdb dnsscience
3. Set environment variable: export DATABASE_URL="postgresql://user:pass@localhost/dnsscience"
4. Run: python database_postgres.py init
"""
import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime

class PostgresDatabase:
    """PostgreSQL database operations for scale"""

    def __init__(self, connection_string=None):
        self.connection_string = connection_string or os.environ.get(
            'DATABASE_URL',
            'postgresql://localhost/dnsscience'
        )

    def get_connection(self):
        """Get database connection"""
        return psycopg2.connect(self.connection_string, cursor_factory=RealDictCursor)

    def init_database(self):
        """Initialize PostgreSQL database with schema"""
        schema = """
        -- Domains table
        CREATE TABLE IF NOT EXISTS domains (
            id SERIAL PRIMARY KEY,
            domain_name TEXT UNIQUE NOT NULL,
            first_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_checked TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Scan history table
        CREATE TABLE IF NOT EXISTS scan_history (
            id SERIAL PRIMARY KEY,
            domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            -- DNSSEC
            dnssec_enabled BOOLEAN,
            dnssec_valid BOOLEAN,
            dnssec_details TEXT,

            -- SPF
            spf_record TEXT,
            spf_valid BOOLEAN,
            spf_details TEXT,

            -- DKIM
            dkim_selectors JSONB,  -- Use JSONB for better querying
            dkim_valid BOOLEAN,
            dkim_details TEXT,

            -- MTA-STS
            mta_sts_enabled BOOLEAN,
            mta_sts_policy TEXT,
            mta_sts_details TEXT,

            -- SMTP STARTTLS
            smtp_starttls_25 BOOLEAN,
            smtp_starttls_587 BOOLEAN,
            smtp_details TEXT,

            -- Overall status
            scan_status TEXT,
            error_message TEXT
        );

        -- Indexes for performance
        CREATE INDEX IF NOT EXISTS idx_domain_name ON domains(domain_name);
        CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_history(scan_timestamp);
        CREATE INDEX IF NOT EXISTS idx_domain_scan ON scan_history(domain_id, scan_timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_dnssec ON scan_history(dnssec_enabled, dnssec_valid);
        CREATE INDEX IF NOT EXISTS idx_spf ON scan_history(spf_valid);
        CREATE INDEX IF NOT EXISTS idx_dkim ON scan_history(dkim_valid);
        CREATE INDEX IF NOT EXISTS idx_mta_sts ON scan_history(mta_sts_enabled);

        -- View for latest scans
        CREATE OR REPLACE VIEW latest_scans AS
        SELECT DISTINCT ON (d.domain_name)
            d.domain_name,
            d.last_checked,
            sh.*
        FROM domains d
        LEFT JOIN scan_history sh ON d.id = sh.domain_id
        ORDER BY d.domain_name, sh.scan_timestamp DESC;
        """

        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(schema)
            conn.commit()
            print("✓ PostgreSQL database initialized")
        except Exception as e:
            conn.rollback()
            print(f"Error initializing database: {e}")
            raise
        finally:
            cursor.close()
            conn.close()

    def add_domain(self, domain_name):
        """Add a domain, return domain_id"""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO domains (domain_name)
                VALUES (%s)
                ON CONFLICT (domain_name) DO UPDATE
                SET domain_name = EXCLUDED.domain_name
                RETURNING id
            """, (domain_name.lower(),))

            domain_id = cursor.fetchone()['id']
            conn.commit()
            return domain_id

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    def save_scan_result(self, domain_name, scan_data):
        """Save scan result to history"""
        domain_id = self.add_domain(domain_name)

        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO scan_history (
                    domain_id, dnssec_enabled, dnssec_valid, dnssec_details,
                    spf_record, spf_valid, spf_details,
                    dkim_selectors, dkim_valid, dkim_details,
                    mta_sts_enabled, mta_sts_policy, mta_sts_details,
                    smtp_starttls_25, smtp_starttls_587, smtp_details,
                    scan_status, error_message
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """, (
                domain_id,
                scan_data.get('dnssec_enabled'),
                scan_data.get('dnssec_valid'),
                scan_data.get('dnssec_details'),
                scan_data.get('spf_record'),
                scan_data.get('spf_valid'),
                scan_data.get('spf_details'),
                json.dumps(scan_data.get('dkim_selectors', [])),
                scan_data.get('dkim_valid'),
                scan_data.get('dkim_details'),
                scan_data.get('mta_sts_enabled'),
                scan_data.get('mta_sts_policy'),
                scan_data.get('mta_sts_details'),
                scan_data.get('smtp_starttls_25'),
                scan_data.get('smtp_starttls_587'),
                scan_data.get('smtp_details'),
                scan_data.get('scan_status', 'completed'),
                scan_data.get('error_message')
            ))

            cursor.execute("""
                UPDATE domains
                SET last_checked = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (domain_id,))

            conn.commit()

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    def get_latest_scan(self, domain_name):
        """Get the latest scan result for a domain"""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT * FROM latest_scans WHERE domain_name = %s
            """, (domain_name.lower(),))

            result = cursor.fetchone()
            return dict(result) if result else None

        finally:
            cursor.close()
            conn.close()

    def get_scan_history(self, domain_name, limit=100):
        """Get scan history for a domain"""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT sh.* FROM scan_history sh
                JOIN domains d ON sh.domain_id = d.id
                WHERE d.domain_name = %s
                ORDER BY sh.scan_timestamp DESC
                LIMIT %s
            """, (domain_name.lower(), limit))

            results = cursor.fetchall()
            return [dict(row) for row in results]

        finally:
            cursor.close()
            conn.close()

    def search_domains(self, query):
        """Search domains by name"""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT * FROM domains
                WHERE domain_name LIKE %s
                ORDER BY last_checked DESC
            """, (f"%{query}%",))

            results = cursor.fetchall()
            return [dict(row) for row in results]

        finally:
            cursor.close()
            conn.close()

    def get_all_domains(self, limit=1000, offset=0):
        """Get all tracked domains with pagination"""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT * FROM domains
                ORDER BY last_checked DESC NULLS LAST
                LIMIT %s OFFSET %s
            """, (limit, offset))

            results = cursor.fetchall()
            return [dict(row) for row in results]

        finally:
            cursor.close()
            conn.close()

    def get_statistics(self):
        """Get comprehensive statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT
                    COUNT(*) as total_domains,
                    COUNT(*) FILTER (WHERE last_checked IS NOT NULL) as scanned_domains,
                    COUNT(*) FILTER (WHERE last_checked IS NULL) as pending_domains
                FROM domains
            """)
            domain_stats = dict(cursor.fetchone())

            cursor.execute("""
                SELECT
                    COUNT(*) FILTER (WHERE dnssec_enabled = true) as dnssec_enabled,
                    COUNT(*) FILTER (WHERE dnssec_valid = true) as dnssec_valid,
                    COUNT(*) FILTER (WHERE spf_valid = true) as spf_valid,
                    COUNT(*) FILTER (WHERE dkim_valid = true) as dkim_valid,
                    COUNT(*) FILTER (WHERE mta_sts_enabled = true) as mta_sts_enabled,
                    COUNT(*) FILTER (WHERE smtp_starttls_25 = true) as starttls_25,
                    COUNT(*) FILTER (WHERE smtp_starttls_587 = true) as starttls_587
                FROM latest_scans
            """)
            security_stats = dict(cursor.fetchone())

            return {**domain_stats, **security_stats}

        finally:
            cursor.close()
            conn.close()


def main():
    """PostgreSQL database management CLI"""
    import argparse

    parser = argparse.ArgumentParser(description='PostgreSQL Database Management')
    parser.add_argument('command', choices=['init', 'stats'], help='Command to run')
    parser.add_argument('--database-url', help='PostgreSQL connection string')

    args = parser.parse_args()

    db = PostgresDatabase(connection_string=args.database_url)

    if args.command == 'init':
        print("Initializing PostgreSQL database...")
        db.init_database()

    elif args.command == 'stats':
        stats = db.get_statistics()
        print("\n📊 Database Statistics")
        print("=" * 50)
        print(f"Total domains:      {stats['total_domains']:,}")
        print(f"Scanned domains:    {stats['scanned_domains']:,}")
        print(f"Pending domains:    {stats['pending_domains']:,}")
        print(f"\nSecurity Features:")
        print(f"DNSSEC enabled:     {stats.get('dnssec_enabled', 0):,}")
        print(f"DNSSEC valid:       {stats.get('dnssec_valid', 0):,}")
        print(f"SPF valid:          {stats.get('spf_valid', 0):,}")
        print(f"DKIM valid:         {stats.get('dkim_valid', 0):,}")
        print(f"MTA-STS enabled:    {stats.get('mta_sts_enabled', 0):,}")
        print(f"STARTTLS (25):      {stats.get('starttls_25', 0):,}")
        print(f"STARTTLS (587):     {stats.get('starttls_587', 0):,}")


if __name__ == '__main__':
    main()
