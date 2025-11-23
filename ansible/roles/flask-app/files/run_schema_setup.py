#!/usr/bin/env python3
import psycopg2

# Database connection
conn = psycopg2.connect(
    host="dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com",
    port=5432,
    database="dnsscience",
    user="dnsscience",
    password="lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK"
)

cur = conn.cursor()

# Execute SQL
sql = open('/var/www/dnsscience/create_all_tables.sql', 'r').read()
cur.execute(sql)
conn.commit()

print("✓ All tables created successfully!")

# Get table count
cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")
count = cur.fetchone()[0]
print(f"Total tables: {count}")

# Check discovered_domains count
cur.execute("SELECT COUNT(*) FROM discovered_domains")
discovered = cur.fetchone()[0]
print(f"Discovered domains: {discovered:,}")

cur.close()
conn.close()
