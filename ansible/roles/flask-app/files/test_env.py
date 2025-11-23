#!/usr/bin/env python3
"""Test environment variable loading"""
import os
import sys
from pathlib import Path

# Add to path
sys.path.insert(0, '/var/www/dnsscience')
os.chdir('/var/www/dnsscience')

# Load .env.production
from dotenv import load_dotenv
env_file = Path('/var/www/dnsscience/.env.production')
if env_file.exists():
    print(f"✓ Found .env.production at {env_file}")
    load_dotenv(env_file)
else:
    print(f"✗ .env.production NOT found at {env_file}")

# Check critical variables
print("\n=== Environment Variables ===")
print(f"DB_HOST: {os.getenv('DB_HOST')}")
print(f"DB_PORT: {os.getenv('DB_PORT')}")
print(f"DB_NAME: {os.getenv('DB_NAME')}")
print(f"DB_USER: {os.getenv('DB_USER')}")
print(f"DB_PASS: {'*' * len(os.getenv('DB_PASS', '')) if os.getenv('DB_PASS') else 'NOT SET'}")

# Test database connection
print("\n=== Testing Database Connection ===")
try:
    from database import Database
    db = Database()
    print("✓ Database class initialized successfully")

    conn = db.get_connection()
    print("✓ Got database connection from pool")

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM domains")
    count = cursor.fetchone()[0]
    cursor.close()
    db.return_connection(conn)

    print(f"✓ Successfully queried database: {count} domains")

except Exception as e:
    print(f"✗ Database error: {e}")
    import traceback
    traceback.print_exc()

# Test stats query
print("\n=== Testing Stats Query ===")
try:
    from database import Database
    db = Database()
    stats = db.get_live_statistics()
    print(f"Total domains: {stats.get('total_domains', 0)}")
    print(f"SSL certificates: {stats.get('ssl_certificates', 0)}")
    print(f"Email records: {stats.get('email_records', 0)}")
except Exception as e:
    print(f"✗ Stats query error: {e}")
    import traceback
    traceback.print_exc()
