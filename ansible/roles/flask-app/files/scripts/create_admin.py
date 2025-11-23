#!/usr/bin/env python3
"""Create admin user for DNS Science"""
import sys
sys.path.insert(0, '/var/www/dnsscience')

from database import Database
import bcrypt

# Create database connection
db = Database()

# Hash for "password123"
password_hash = bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Create admin user
conn = db.get_connection()
try:
    with conn.cursor() as cursor:
        cursor.execute("""
            INSERT INTO users (email, username, password_hash, is_premium, is_admin, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON CONFLICT (email) DO UPDATE
            SET password_hash = EXCLUDED.password_hash,
                is_premium = true,
                is_admin = true
        """, ('admin@dnsscience.io', 'admin', password_hash, True, True))

        conn.commit()

        print("✓ Admin user created successfully")
        print("  Email: admin@dnsscience.io")
        print("  Password: password123")
        print("  Premium: Yes")
        print("  Admin: Yes")

except Exception as e:
    conn.rollback()
    print(f"✗ Error creating admin user: {e}")
    sys.exit(1)
finally:
    db.return_connection(conn)
