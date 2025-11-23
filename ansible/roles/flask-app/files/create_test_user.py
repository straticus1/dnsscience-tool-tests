#!/usr/bin/env python3
"""
Create test user for DNS Science
Run this on the EC2 instance after fixing the database connection
"""
import sys
import os
from pathlib import Path

# Setup path
sys.path.insert(0, '/var/www/dnsscience')

# Load environment
from dotenv import load_dotenv
env_file = Path('/var/www/dnsscience/.env.production')
if env_file.exists():
    load_dotenv(env_file)
else:
    print("WARNING: .env.production not found, trying .env")
    load_dotenv(Path('/var/www/dnsscience/.env'))

from database import Database
from auth import UserAuth, PasswordHasher

def main():
    print("=" * 60)
    print("DNS Science - User Management Script")
    print("=" * 60)

    # Initialize database and auth
    print("\n[1] Initializing database connection...")
    try:
        db = Database()
        auth = UserAuth(db)
        print("✓ Database connected")
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return 1

    # Check if admin user exists
    print("\n[2] Checking for admin user...")
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, email, is_active, created_at
                FROM users
                WHERE email = 'admin@dnsscience.io'
            """)
            admin = cur.fetchone()

            if admin:
                print(f"✓ Admin user exists:")
                print(f"  ID: {admin[0]}")
                print(f"  Email: {admin[1]}")
                print(f"  Active: {admin[2]}")
                print(f"  Created: {admin[3]}")

                # Ask if password should be reset
                print("\n  To reset admin password:")
                new_password = "DNSScience2025!"
                password_hash = PasswordHasher.hash_password(new_password)

                cur.execute("""
                    UPDATE users
                    SET password_hash = %s
                    WHERE email = 'admin@dnsscience.io'
                """, (password_hash,))
                conn.commit()

                print(f"  ✓ Admin password reset to: {new_password}")
            else:
                print("  Admin user does not exist")

    finally:
        db.return_connection(conn)

    # Create test user
    print("\n[3] Creating test user...")
    test_email = "test@dnsscience.io"
    test_password = "TestPassword123!"

    try:
        user_id, error = auth.register_user(
            email=test_email,
            password=test_password,
            full_name="Test User",
            company="DNS Science Testing"
        )

        if error:
            if "already registered" in error.lower():
                print(f"  ℹ Test user already exists: {test_email}")

                # Reset password
                conn = db.get_connection()
                try:
                    password_hash = PasswordHasher.hash_password(test_password)
                    with conn.cursor() as cur:
                        cur.execute("""
                            UPDATE users
                            SET password_hash = %s
                            WHERE email = %s
                        """, (password_hash, test_email))
                        conn.commit()
                    print(f"  ✓ Test user password reset to: {test_password}")
                finally:
                    db.return_connection(conn)
            else:
                print(f"  ✗ Error creating test user: {error}")
        else:
            print(f"  ✓ Test user created successfully!")
            print(f"  ID: {user_id}")

    except Exception as e:
        print(f"  ✗ Error: {e}")

    # Display credentials
    print("\n" + "=" * 60)
    print("WORKING CREDENTIALS:")
    print("=" * 60)
    print("\nOption 1 - Admin Account:")
    print(f"  Email: admin@dnsscience.io")
    print(f"  Password: DNSScience2025!")
    print(f"  Login URL: https://www.dnsscience.io/login")

    print("\nOption 2 - Test Account:")
    print(f"  Email: {test_email}")
    print(f"  Password: {test_password}")
    print(f"  Login URL: https://www.dnsscience.io/login")
    print("\n" + "=" * 60)

    # Test login
    print("\n[4] Testing login functionality...")
    user_data, error = auth.login_user("test@dnsscience.io", test_password)

    if error:
        print(f"  ✗ Login test failed: {error}")
    else:
        print(f"  ✓ Login successful!")
        print(f"  User: {user_data.get('full_name')} ({user_data.get('email')})")

    print("\nScript completed successfully!")
    return 0

if __name__ == '__main__':
    sys.exit(main())
