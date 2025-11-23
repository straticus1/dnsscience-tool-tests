#!/usr/bin/env python3
"""Add unique constraint to ssl_certificates table"""

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

# Add unique constraint on ssl_certificates
try:
    cur.execute('ALTER TABLE ssl_certificates ADD CONSTRAINT ssl_certificates_domain_port_unique UNIQUE (domain_name, port)')
    conn.commit()
    print('Added unique constraint on ssl_certificates (domain_name, port)')
except Exception as e:
    print(f'Error adding constraint: {e}')
    conn.rollback()

# Check current count
cur.execute('SELECT COUNT(*) FROM ssl_certificates')
print(f'Current SSL certificates: {cur.fetchone()[0]}')

cur.execute('SELECT COUNT(*) FROM email_security_records')
print(f'Current email security records: {cur.fetchone()[0]}')

conn.close()
