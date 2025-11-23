#!/usr/bin/env python3
"""Check database schema for daemon compatibility"""

import sys
sys.path.insert(0, "/var/www/dnsscience")
from config import Config
import psycopg2

conn = psycopg2.connect(
    host=Config.DB_HOST,
    port=Config.DB_PORT,
    database=Config.DB_NAME,
    user=Config.DB_USER,
    password=Config.DB_PASS
)
cur = conn.cursor()

# Check ssl_certificates table
print("=== ssl_certificates table ===")
cur.execute("""
    SELECT column_name, data_type
    FROM information_schema.columns
    WHERE table_name = 'ssl_certificates'
    ORDER BY ordinal_position
""")
for row in cur.fetchall():
    print(f"{row[0]}: {row[1]}")

# Check email_security_records table
print("\n=== email_security_records table ===")
cur.execute("""
    SELECT column_name, data_type
    FROM information_schema.columns
    WHERE table_name = 'email_security_records'
    ORDER BY ordinal_position
""")
for row in cur.fetchall():
    print(f"{row[0]}: {row[1]}")

# Check if domains table has ssl_expiry_date
print("\n=== domains table (SSL columns) ===")
cur.execute("""
    SELECT column_name, data_type
    FROM information_schema.columns
    WHERE table_name = 'domains'
    AND column_name LIKE '%ssl%'
    ORDER BY ordinal_position
""")
for row in cur.fetchall():
    print(f"{row[0]}: {row[1]}")

# Check for certificate_history table
print("\n=== certificate_history table exists? ===")
cur.execute("""
    SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_name = 'certificate_history'
    )
""")
print(f"Exists: {cur.fetchone()[0]}")

# Check for ssl_alerts table
print("\n=== ssl_alerts table exists? ===")
cur.execute("""
    SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_name = 'ssl_alerts'
    )
""")
print(f"Exists: {cur.fetchone()[0]}")

# Check for ssl_scan_results table
print("\n=== ssl_scan_results table exists? ===")
cur.execute("""
    SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_name = 'ssl_scan_results'
    )
""")
print(f"Exists: {cur.fetchone()[0]}")

# Count existing records
print("\n=== Current record counts ===")
cur.execute("SELECT COUNT(*) FROM ssl_certificates")
print(f"ssl_certificates: {cur.fetchone()[0]}")

cur.execute("SELECT COUNT(*) FROM email_security_records")
print(f"email_security_records: {cur.fetchone()[0]}")

conn.close()
