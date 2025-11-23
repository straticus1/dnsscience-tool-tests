#!/usr/bin/env python3
"""
DNS Science Database Initialization Script
Initializes PostgreSQL database with all schemas and creates test users
"""

import psycopg2
import os
import sys
from pathlib import Path
import hashlib
import secrets
from datetime import datetime, timedelta

# Database connection parameters
DB_HOST = os.environ.get('DB_HOST', 'dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com')
DB_PORT = os.environ.get('DB_PORT', '5432')
DB_NAME = os.environ.get('DB_NAME', 'dnsscience')
DB_USER = os.environ.get('DB_USER', 'dnsscience')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK')

# Schema files in order of execution
SCHEMA_FILES = [
    'schema_postgres.sql',         # Core schema (users, domains, scans, certificates)
    'schema_subscriptions.sql',    # Subscription tiers and billing
    'schema_audit_logs.sql',       # Audit logging
    'schema_auth.sql',             # Multi-provider authentication
    'schema_enrichment.sql',       # HIBP, CT logs, compliance
    'schema_threat_intel.sql',     # CISA KEV, Abuse.ch, Shadowserver, MISP
    'schema_reverse_dns.sql',      # IPv4/IPv6 PTR lookups
    'schema_reports.sql',          # Report generation and scheduling
    'schema_stix_taxii.sql',       # Threat intelligence exchange
    'schema_geoip_mapping.sql',    # GeoIP threat mapping
]

# Test user accounts for each subscription tier
TEST_USERS = [
    {
        'username': 'freetier_test',
        'email': 'freetier@dnsscience-testing.io',
        'password': 'FreeTier2025!Test',
        'tier': 'free',
        'tier_id': 1,
    },
    {
        'username': 'essentials_test',
        'email': 'essentials@dnsscience-testing.io',
        'password': 'Essentials2025!Test',
        'tier': 'essentials',
        'tier_id': 2,
    },
    {
        'username': 'professional_test',
        'email': 'professional@dnsscience-testing.io',
        'password': 'Professional2025!Test',
        'tier': 'professional',
        'tier_id': 3,
    },
    {
        'username': 'commercial_test',
        'email': 'commercial@dnsscience-testing.io',
        'password': 'Commercial2025!Test',
        'tier': 'commercial',
        'tier_id': 4,
    },
    {
        'username': 'research_test',
        'email': 'research@dnsscience-testing.io',
        'password': 'Research2025!Test',
        'tier': 'research',
        'tier_id': 5,
    },
    {
        'username': 'enterprise_test',
        'email': 'enterprise@dnsscience-testing.io',
        'password': 'Enterprise2025!Test',
        'tier': 'enterprise',
        'tier_id': 6,
    },
]


def connect_to_database():
    """Connect to PostgreSQL database"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=10
        )
        print(f"✓ Connected to PostgreSQL database: {DB_NAME}")
        return conn
    except Exception as e:
        print(f"✗ Failed to connect to database: {e}")
        sys.exit(1)


def execute_sql_file(conn, filepath):
    """Execute a SQL file"""
    try:
        with open(filepath, 'r') as f:
            sql = f.read()

        cursor = conn.cursor()
        cursor.execute(sql)
        conn.commit()
        cursor.close()

        print(f"  ✓ Executed: {os.path.basename(filepath)}")
        return True
    except Exception as e:
        print(f"  ✗ Error executing {filepath}: {e}")
        conn.rollback()
        return False


def hash_password(password):
    """Simple password hashing (in production, use bcrypt or argon2)"""
    # For testing purposes, using SHA-256. In production, use bcrypt/argon2
    salt = 'dnsscience_salt_2025'  # In production, use random salt per user
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()


def generate_api_key():
    """Generate a secure API key"""
    return f"ds_{secrets.token_urlsafe(32)}"


def create_test_users(conn):
    """Create test user accounts for each subscription tier"""
    cursor = conn.cursor()
    created_users = []

    print("\n📝 Creating test user accounts...")

    for user_data in TEST_USERS:
        try:
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE username = %s", (user_data['username'],))
            existing = cursor.fetchone()

            if existing:
                print(f"  ⚠ User {user_data['username']} already exists, skipping...")
                user_id = existing[0]
            else:
                # Create user
                password_hash = hash_password(user_data['password'])

                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, is_active, created_at)
                    VALUES (%s, %s, %s, true, NOW())
                    RETURNING id
                """, (user_data['username'], user_data['email'], password_hash))

                user_id = cursor.fetchone()[0]
                print(f"  ✓ Created user: {user_data['username']}")

            # Generate API key
            api_key = generate_api_key()
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            api_key_prefix = api_key[:10]

            # Check if API key exists
            cursor.execute("SELECT id FROM api_keys WHERE user_id = %s AND is_active = true", (user_id,))
            existing_key = cursor.fetchone()

            if not existing_key:
                cursor.execute("""
                    INSERT INTO api_keys (user_id, key_hash, key_prefix, name, is_active, created_at, rate_limit_per_hour)
                    VALUES (%s, %s, %s, %s, true, NOW(), 10000)
                    RETURNING id
                """, (user_id, api_key_hash, api_key_prefix, f"{user_data['tier']} tier test key"))

                print(f"  ✓ Generated API key for {user_data['username']}: {api_key}")
            else:
                print(f"  ⚠ API key already exists for {user_data['username']}")
                api_key = "EXISTING_KEY_CHECK_DATABASE"

            # Create subscription if subscriptions table exists
            try:
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_name = 'subscriptions'
                    )
                """)
                if cursor.fetchone()[0]:
                    # Check if subscription exists
                    cursor.execute("SELECT id FROM subscriptions WHERE user_id = %s AND is_active = true", (user_id,))
                    existing_sub = cursor.fetchone()

                    if not existing_sub:
                        cursor.execute("""
                            INSERT INTO subscriptions (user_id, tier_id, status, current_period_start, current_period_end)
                            VALUES (%s, %s, 'active', NOW(), NOW() + INTERVAL '30 days')
                        """, (user_id, user_data['tier_id']))
                        print(f"  ✓ Created {user_data['tier']} subscription")
            except Exception as e:
                print(f"  ⚠ Note: Could not create subscription (table may not exist yet): {e}")

            created_users.append({
                **user_data,
                'api_key': api_key,
                'user_id': user_id
            })

        except Exception as e:
            print(f"  ✗ Error creating user {user_data['username']}: {e}")
            conn.rollback()
            continue

    conn.commit()
    cursor.close()
    return created_users


def print_test_credentials(users):
    """Print test credentials for documentation"""
    print("\n" + "="*80)
    print("TEST USER CREDENTIALS")
    print("="*80)

    for user in users:
        print(f"\n{user['tier'].upper()} TIER:")
        print(f"  Username:  {user['username']}")
        print(f"  Email:     {user['email']}")
        print(f"  Password:  {user['password']}")
        print(f"  API Key:   {user['api_key']}")
        print(f"  Tier ID:   {user['tier_id']}")

    print("\n" + "="*80)


def main():
    """Main initialization function"""
    print("=" * 80)
    print("DNS SCIENCE DATABASE INITIALIZATION")
    print("=" * 80)
    print(f"Database: {DB_NAME}@{DB_HOST}:{DB_PORT}")
    print(f"User: {DB_USER}")
    print("=" * 80)

    # Connect to database
    conn = connect_to_database()

    # Get schema directory
    schema_dir = Path(__file__).parent.parent / 'schemas'
    if not schema_dir.exists():
        # Try alternative path
        schema_dir = Path('/opt/dnsscience/schemas')

    if not schema_dir.exists():
        print(f"\n✗ Schema directory not found: {schema_dir}")
        sys.exit(1)

    print(f"\n📂 Schema directory: {schema_dir}")

    # Execute schema files in order
    print("\n📋 Executing schema files...")
    success_count = 0

    for schema_file in SCHEMA_FILES:
        filepath = schema_dir / schema_file
        if filepath.exists():
            if execute_sql_file(conn, filepath):
                success_count += 1
        else:
            print(f"  ⚠ Schema file not found: {schema_file}")

    print(f"\n✓ Successfully executed {success_count}/{len(SCHEMA_FILES)} schema files")

    # Create test users
    test_users = create_test_users(conn)

    # Print credentials
    print_test_credentials(test_users)

    # Save credentials to file
    output_file = '/opt/dnsscience/test_credentials.txt'
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            f.write("DNS SCIENCE TEST CREDENTIALS\n")
            f.write("=" * 80 + "\n\n")
            for user in test_users:
                f.write(f"{user['tier'].upper()} TIER:\n")
                f.write(f"  Username:  {user['username']}\n")
                f.write(f"  Email:     {user['email']}\n")
                f.write(f"  Password:  {user['password']}\n")
                f.write(f"  API Key:   {user['api_key']}\n")
                f.write(f"  Tier ID:   {user['tier_id']}\n\n")
        print(f"\n✓ Credentials saved to: {output_file}")
    except Exception as e:
        print(f"\n⚠ Could not save credentials to file: {e}")

    # Close connection
    conn.close()
    print("\n✓ Database initialization complete!")
    print("=" * 80)


if __name__ == '__main__':
    main()
