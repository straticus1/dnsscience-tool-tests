#!/usr/bin/env python3
"""Monitor daemon data collection"""

import sys
sys.path.insert(0, "/var/www/dnsscience")
from config import Config
import psycopg2
import time

# Wait for daemons to collect data
print("Waiting 30 seconds for data collection...")
time.sleep(30)

conn = psycopg2.connect(
    host=Config.DB_HOST,
    port=Config.DB_PORT,
    database=Config.DB_NAME,
    user=Config.DB_USER,
    password=Config.DB_PASS
)
cur = conn.cursor()

print('\n=== Current Data Collection Status ===')
cur.execute('SELECT COUNT(*) FROM ssl_certificates')
ssl_count = cur.fetchone()[0]
print(f'SSL Certificates: {ssl_count}')

cur.execute('SELECT COUNT(*) FROM email_security_records')
email_count = cur.fetchone()[0]
print(f'Email Security Records: {email_count}')

# Get latest SSL certificates
print('\n=== Latest SSL Certificates (last 5) ===')
cur.execute('SELECT domain_name, issuer_cn, expires_at, last_checked FROM ssl_certificates ORDER BY last_checked DESC LIMIT 5')
for row in cur.fetchall():
    print(f'{row[0]}: issuer={row[1]}, expires={row[2]}, checked={row[3]}')

# Get latest email security records
print('\n=== Latest Email Security Records (last 5) ===')
cur.execute('''
    SELECT d.domain_name, e.has_mx, e.has_spf, e.has_dmarc, e.has_dkim, e.last_checked
    FROM email_security_records e
    JOIN domains d ON e.domain_id = d.id
    ORDER BY e.last_checked DESC LIMIT 5
''')
for row in cur.fetchall():
    print(f'{row[0]}: MX={row[1]}, SPF={row[2]}, DMARC={row[3]}, DKIM={row[4]}, checked={row[5]}')

conn.close()
print('\n=== Monitoring Complete ===')
