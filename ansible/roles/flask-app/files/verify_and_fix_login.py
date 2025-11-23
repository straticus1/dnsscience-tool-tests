#!/usr/bin/env python3
"""
Verify and fix login credentials
"""

import sys
import os
from pathlib import Path

# Add to path
sys.path.insert(0, '/var/www/dnsscience')
os.chdir('/var/www/dnsscience')

# Load environment
from dotenv import load_dotenv
load_dotenv(Path('/var/www/dnsscience/.env.production'))

from database import Database
from auth import AuthManager
import hashlib

db = Database()
auth = AuthManager()

print("=" * 50)
print("DNS Science Login Verification")
print("=" * 50)
print()

# Check existing users
conn = db.get_connection()
try:
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT id, username, email, is_admin, created_at
            FROM users
            ORDER BY id
            LIMIT 10
        """)

        users = cursor.fetchall()
        print(f"Found {len(users)} users:")
        for user in users:
            print(f"  ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Admin: {user[3]}")

        print()

        # Check if admin user exists
        cursor.execute("""
            SELECT id, username, email, password_hash, salt
            FROM users
            WHERE email = 'admin@dnsscience.io' OR username = 'admin'
            LIMIT 1
        """)

        admin = cursor.fetchone()

        if admin:
            print("✓ Admin user found")
            admin_id, admin_username, admin_email, current_hash, current_salt = admin
            print(f"  ID: {admin_id}")
            print(f"  Username: {admin_username}")
            print(f"  Email: {admin_email}")
            print()

            # Reset password to DNSScience2025!
            new_password = "DNSScience2025!"
            result = auth.reset_password(admin_id, new_password)

            if result['success']:
                print(f"✓ Password reset successful for {admin_email}")
            else:
                print(f"✗ Password reset failed: {result.get('error')}")

            # Test login
            print()
            print("Testing login...")
            login_result = auth.login(admin_email, new_password)

            if login_result['success']:
                print(f"✓ Login successful!")
                print(f"  User ID: {login_result['user_id']}")
                print(f"  Username: {login_result['username']}")
            else:
                print(f"✗ Login failed: {login_result.get('error')}")

        else:
            print("✗ Admin user not found")
            print()
            print("Creating admin user...")

            # Create admin user
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, salt, is_admin, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                RETURNING id
            """, ('admin', 'admin@dnsscience.io', 'temp', 'temp', True))

            admin_id = cursor.fetchone()[0]
            conn.commit()

            # Reset password
            result = auth.reset_password(admin_id, "DNSScience2025!")
            if result['success']:
                print(f"✓ Admin user created with password: DNSScience2025!")
            else:
                print(f"✗ Failed to set password: {result.get('error')}")

        print()
        print("=" * 50)
        print("Creating/Verifying Test User")
        print("=" * 50)
        print()

        # Check for test user
        cursor.execute("""
            SELECT id, username, email
            FROM users
            WHERE email = 'test@dnsscience.io'
            LIMIT 1
        """)

        test_user = cursor.fetchone()

        if test_user:
            print(f"✓ Test user exists (ID: {test_user[0]})")
            test_id = test_user[0]
        else:
            print("Creating test user...")
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, salt, is_admin, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                RETURNING id
            """, ('testuser', 'test@dnsscience.io', 'temp', 'temp', False))

            test_id = cursor.fetchone()[0]
            conn.commit()
            print(f"✓ Test user created (ID: {test_id})")

        # Reset test user password
        result = auth.reset_password(test_id, "TestPassword123!")
        if result['success']:
            print(f"✓ Test password set: TestPassword123!")
        else:
            print(f"✗ Failed to set test password: {result.get('error')}")

        # Test login
        print()
        print("Testing test user login...")
        login_result = auth.login('test@dnsscience.io', 'TestPassword123!')

        if login_result['success']:
            print(f"✓ Test login successful!")
        else:
            print(f"✗ Test login failed: {login_result.get('error')}")

finally:
    db.return_connection(conn)

print()
print("=" * 50)
print("Summary")
print("=" * 50)
print()
print("Admin Credentials:")
print("  Email: admin@dnsscience.io")
print("  Password: DNSScience2025!")
print("  URL: https://www.dnsscience.io/login")
print()
print("Test User Credentials:")
print("  Email: test@dnsscience.io")
print("  Password: TestPassword123!")
print("  URL: https://www.dnsscience.io/login")
print()
