#!/usr/bin/env python3
"""
DNS Science - COMPREHENSIVE DATABASE FIX
Fixes ALL database issues for perfect production deployment

This script:
1. Creates GeoIP tables (geoip_blocks and geoip_locations)
2. Adds missing columns to existing tables
3. Creates indexes for performance
4. Verifies all daemon-required columns exist
5. Sets up database maintenance infrastructure
"""

import psycopg2
import psycopg2.extras
import os
import sys

def load_env_file():
    """Load environment variables from .env file"""
    # Try multiple paths
    paths = [
        '/var/www/dnsscience/.env.production',
        '/var/www/dnsscience/.env',
        '/home/ubuntu/dnsscience/.env',
        '.env'
    ]

    for filepath in paths:
        if os.path.exists(filepath):
            print(f"Loading environment from: {filepath}")
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        # Remove quotes if present
                        value = value.strip().strip('"').strip("'")
                        os.environ[key] = value
            return
    print("WARNING: No .env file found in standard locations")

def get_db_connection():
    """Get database connection using environment variables"""
    # Load from file if environment variables not set
    if not os.getenv('DB_PASSWORD') and not os.getenv('DB_PASS'):
        load_env_file()

    # Support both DB_PASSWORD and DB_PASS
    password = os.getenv('DB_PASSWORD') or os.getenv('DB_PASS')

    return psycopg2.connect(
        host=os.getenv('DB_HOST', '127.0.0.1'),
        port=int(os.getenv('DB_PORT', '6432')),
        database=os.getenv('DB_NAME', 'dnsscience'),
        user=os.getenv('DB_USER', 'dnsscience'),
        password=password
    )

def create_geoip_tables(conn):
    """Create GeoIP tables for IP geolocation"""
    print("\n=== Creating GeoIP Tables ===")
    cursor = conn.cursor()

    # Drop existing tables if they exist (clean slate)
    cursor.execute("DROP TABLE IF EXISTS geoip_blocks CASCADE")
    cursor.execute("DROP TABLE IF EXISTS geoip_locations CASCADE")

    # Create geoip_locations table
    cursor.execute("""
        CREATE TABLE geoip_locations (
            geoname_id INTEGER PRIMARY KEY,
            locale_code VARCHAR(10) DEFAULT 'en',
            continent_code VARCHAR(2),
            continent_name VARCHAR(100),
            country_iso_code VARCHAR(2),
            country_name VARCHAR(100),
            subdivision_1_iso_code VARCHAR(3),
            subdivision_1_name VARCHAR(100),
            subdivision_2_iso_code VARCHAR(3),
            subdivision_2_name VARCHAR(100),
            city_name VARCHAR(100),
            metro_code INTEGER,
            time_zone VARCHAR(50),
            is_in_european_union BOOLEAN DEFAULT false,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  ✓ Created geoip_locations table")

    # Create geoip_blocks table
    cursor.execute("""
        CREATE TABLE geoip_blocks (
            id SERIAL PRIMARY KEY,
            network CIDR NOT NULL,
            geoname_id INTEGER REFERENCES geoip_locations(geoname_id),
            registered_country_geoname_id INTEGER,
            represented_country_geoname_id INTEGER,
            is_anonymous_proxy BOOLEAN DEFAULT false,
            is_satellite_provider BOOLEAN DEFAULT false,
            postal_code VARCHAR(20),
            latitude NUMERIC(10,7),
            longitude NUMERIC(10,7),
            accuracy_radius INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(network)
        )
    """)
    print("  ✓ Created geoip_blocks table")

    # Create indexes for performance
    print("\n=== Creating GeoIP Indexes ===")
    indexes = [
        ("idx_geoip_blocks_network", "geoip_blocks", "USING GIST (network inet_ops)"),
        ("idx_geoip_blocks_geoname", "geoip_blocks", "(geoname_id)"),
        ("idx_geoip_locations_country", "geoip_locations", "(country_iso_code)"),
        ("idx_geoip_locations_city", "geoip_locations", "(city_name)"),
        ("idx_geoip_locations_continent", "geoip_locations", "(continent_code)"),
    ]

    for idx_name, table_name, idx_def in indexes:
        cursor.execute(f"CREATE INDEX {idx_name} ON {table_name} {idx_def}")
        print(f"  ✓ Created index: {idx_name}")

    conn.commit()
    cursor.close()
    print("\n✓ GeoIP tables created successfully!")

def add_missing_columns(conn):
    """Add any missing columns that daemons reference"""
    print("\n=== Adding Missing Columns ===")
    cursor = conn.cursor()

    # Check and add columns to ip_reputation table
    print("\nChecking ip_reputation table...")
    cursor.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'ip_reputation'
    """)
    existing_columns = {row[0] for row in cursor.fetchall()}

    required_columns = {
        'last_checked': 'TIMESTAMP',
        'updated_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
        'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
    }

    for col_name, col_type in required_columns.items():
        if col_name not in existing_columns:
            cursor.execute(f"""
                ALTER TABLE ip_reputation
                ADD COLUMN {col_name} {col_type}
            """)
            print(f"  ✓ Added column: ip_reputation.{col_name}")
        else:
            print(f"  - Column exists: ip_reputation.{col_name}")

    # Check and add columns to domains table
    print("\nChecking domains table...")
    cursor.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'domains'
    """)
    existing_columns = {row[0] for row in cursor.fetchall()}

    domain_columns = {
        'last_checked': 'TIMESTAMP',
        'geo_location': 'VARCHAR(255)',
        'reputation_score': 'INTEGER DEFAULT 50',
    }

    for col_name, col_type in domain_columns.items():
        if col_name not in existing_columns:
            cursor.execute(f"""
                ALTER TABLE domains
                ADD COLUMN {col_name} {col_type}
            """)
            print(f"  ✓ Added column: domains.{col_name}")
        else:
            print(f"  - Column exists: domains.{col_name}")

    conn.commit()
    cursor.close()
    print("\n✓ All required columns verified/added!")

def create_performance_indexes(conn):
    """Create additional indexes for better daemon performance"""
    print("\n=== Creating Performance Indexes ===")
    cursor = conn.cursor()

    # Check existing indexes
    cursor.execute("""
        SELECT indexname
        FROM pg_indexes
        WHERE schemaname = 'public'
    """)
    existing_indexes = {row[0] for row in cursor.fetchall()}

    # Performance indexes
    performance_indexes = [
        ("idx_domains_last_checked", "domains", "(last_checked) WHERE is_active = TRUE"),
        ("idx_domains_active", "domains", "(is_active, last_checked)"),
        ("idx_ip_reputation_last_checked", "ip_reputation", "(last_checked)"),
        ("idx_ip_reputation_domain", "ip_reputation", "(domain_id, last_checked)"),
    ]

    for idx_name, table_name, idx_def in performance_indexes:
        if idx_name not in existing_indexes:
            try:
                cursor.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table_name} {idx_def}")
                print(f"  ✓ Created index: {idx_name}")
            except Exception as e:
                print(f"  - Skipped {idx_name}: {str(e)[:50]}")
        else:
            print(f"  - Index exists: {idx_name}")

    conn.commit()
    cursor.close()
    print("\n✓ Performance indexes created!")

def verify_table_structure(conn):
    """Verify all critical tables exist and have required columns"""
    print("\n=== Verifying Table Structure ===")
    cursor = conn.cursor()

    critical_tables = [
        ('domains', ['id', 'domain_name', 'is_active', 'last_checked']),
        ('ip_reputation', ['domain_id', 'ip_address', 'reputation_score', 'last_checked']),
        ('geoip_blocks', ['network', 'geoname_id', 'latitude', 'longitude']),
        ('geoip_locations', ['geoname_id', 'country_iso_code', 'city_name']),
    ]

    all_good = True
    for table_name, required_cols in critical_tables:
        cursor.execute(f"""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = '{table_name}'
            ORDER BY ordinal_position
        """)
        existing_cols = [row[0] for row in cursor.fetchall()]

        if not existing_cols:
            print(f"  ✗ Table missing: {table_name}")
            all_good = False
            continue

        missing_cols = [col for col in required_cols if col not in existing_cols]
        if missing_cols:
            print(f"  ✗ {table_name}: Missing columns: {', '.join(missing_cols)}")
            all_good = False
        else:
            print(f"  ✓ {table_name}: All required columns present ({len(existing_cols)} total)")

    cursor.close()

    if all_good:
        print("\n✓ All table structures verified!")
    else:
        print("\n✗ Some table structure issues detected")

    return all_good

def create_initial_geoip_data(conn):
    """Create initial sample GeoIP data for testing"""
    print("\n=== Creating Initial GeoIP Data ===")
    cursor = conn.cursor()

    # Insert some common location data
    sample_locations = [
        (4180439, 'en', 'NA', 'North America', 'US', 'United States', 'VA', 'Virginia', None, None, 'Ashburn', 511, 'America/New_York', False),
        (2643743, 'en', 'EU', 'Europe', 'GB', 'United Kingdom', 'ENG', 'England', None, None, 'London', None, 'Europe/London', True),
        (5375480, 'en', 'NA', 'North America', 'US', 'United States', 'CA', 'California', None, None, 'Mountain View', 807, 'America/Los_Angeles', False),
        (1850147, 'en', 'AS', 'Asia', 'JP', 'Japan', '13', 'Tokyo', None, None, 'Tokyo', None, 'Asia/Tokyo', False),
        (2988507, 'en', 'EU', 'Europe', 'FR', 'France', 'IDF', 'Île-de-France', None, None, 'Paris', None, 'Europe/Paris', True),
    ]

    for location in sample_locations:
        cursor.execute("""
            INSERT INTO geoip_locations
            (geoname_id, locale_code, continent_code, continent_name, country_iso_code,
             country_name, subdivision_1_iso_code, subdivision_1_name, subdivision_2_iso_code,
             subdivision_2_name, city_name, metro_code, time_zone, is_in_european_union)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (geoname_id) DO NOTHING
        """, location)

    # Insert some sample IP blocks
    sample_blocks = [
        ('8.8.8.0/24', 5375480, 6252001, None, False, False, None, 37.3860, -122.0838, 1000),  # Google DNS
        ('1.1.1.0/24', 4180439, 6252001, None, False, False, None, 39.0481, -77.4728, 1000),   # Cloudflare
    ]

    for block in sample_blocks:
        cursor.execute("""
            INSERT INTO geoip_blocks
            (network, geoname_id, registered_country_geoname_id, represented_country_geoname_id,
             is_anonymous_proxy, is_satellite_provider, postal_code, latitude, longitude, accuracy_radius)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (network) DO NOTHING
        """, block)

    conn.commit()
    cursor.close()

    # Verify data
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM geoip_locations")
    loc_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM geoip_blocks")
    block_count = cursor.fetchone()[0]
    cursor.close()

    print(f"  ✓ Created {loc_count} location entries")
    print(f"  ✓ Created {block_count} IP block entries")
    print("\n✓ Initial GeoIP data created!")

def main():
    """Main execution"""
    print("\n" + "="*70)
    print("DNS SCIENCE - COMPREHENSIVE DATABASE FIX")
    print("="*70)

    try:
        # Connect to database
        print("\nConnecting to database...")
        conn = get_db_connection()
        print("✓ Database connected!")

        # Run all fixes
        create_geoip_tables(conn)
        add_missing_columns(conn)
        create_performance_indexes(conn)
        create_initial_geoip_data(conn)

        # Final verification
        if verify_table_structure(conn):
            print("\n" + "="*70)
            print("SUCCESS! All database fixes applied successfully!")
            print("="*70)
            return 0
        else:
            print("\nWARNING: Some issues detected. Review output above.")
            return 1

    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    sys.exit(main())
