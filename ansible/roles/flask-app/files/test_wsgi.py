#!/usr/bin/python3
"""Test WSGI application loading"""
import sys
import os
import traceback

# Add application directory
sys.path.insert(0, '/var/www/dnsscience')

# Set environment
os.environ['DB_HOST'] = 'dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com'
os.environ['DB_PORT'] = '5432'
os.environ['DB_NAME'] = 'dnsscience'
os.environ['DB_USER'] = 'dnsscience'
os.environ['DB_PASS'] = 'lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK'

print("Testing WSGI application loading...")
print(f"Python version: {sys.version}")
print(f"Python path: {sys.path}")
print()

try:
    print("1. Checking if files exist...")
    import os
    files = [
        '/var/www/dnsscience/app.py',
        '/var/www/dnsscience/database.py',
        '/var/www/dnsscience/checkers.py',
        '/var/www/dnsscience/dnsscience.wsgi'
    ]
    for f in files:
        exists = os.path.exists(f)
        print(f"  {f}: {'✓' if exists else '✗ MISSING'}")
    print()

    print("2. Testing imports...")
    try:
        import flask
        print("  flask: ✓")
    except Exception as e:
        print(f"  flask: ✗ {e}")

    try:
        import psycopg2
        print("  psycopg2: ✓")
    except Exception as e:
        print(f"  psycopg2: ✗ {e}")

    try:
        import dns.resolver
        print("  dnspython: ✓")
    except Exception as e:
        print(f"  dnspython: ✗ {e}")
    print()

    print("3. Testing application import...")
    try:
        from app import app
        print("  app.py imported: ✓")
        print(f"  Flask app: {app}")
    except Exception as e:
        print(f"  app.py import failed: ✗")
        print(f"  Error: {e}")
        traceback.print_exc()

    print("\nTest complete!")

except Exception as e:
    print(f"\nFATAL ERROR: {e}")
    traceback.print_exc()
