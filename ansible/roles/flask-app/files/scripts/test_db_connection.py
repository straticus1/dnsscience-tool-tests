#!/usr/bin/env python3
"""Test database connectivity and check data on EC2 instances"""

import boto3
import time
import sys

REGION = 'us-east-1'
INSTANCES = ['i-05add94e8603bd5b3']  # Test on first instance

TEST_SCRIPT = '''#!/bin/bash
cd /var/www/dnsscience
export $(sudo cat .env | grep -v "^#" | grep -v "^$" | xargs)

python3 << 'ENDPYTHON'
import os
import sys

try:
    import psycopg2
except ImportError:
    print("Installing psycopg2-binary...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg2-binary", "-q"])
    import psycopg2

try:
    print("=" * 70)
    print("DATABASE CONNECTION TEST")
    print("=" * 70)

    db_host = os.getenv("DB_HOST")
    db_name = os.getenv("DB_NAME")
    db_user = os.getenv("DB_USER")

    print(f"\\nConnecting to database...")
    print(f"  Host: {db_host}")
    print(f"  Database: {db_name}")
    print(f"  User: {db_user}")

    conn = psycopg2.connect(
        host=db_host,
        port=5432,
        database=db_name,
        user=db_user,
        password=os.getenv("DB_PASS")
    )

    print("\\n✓ Successfully connected to database!")

    cur = conn.cursor()

    # Get PostgreSQL version
    cur.execute("SELECT version()")
    version = cur.fetchone()[0]
    print(f"\\nPostgreSQL Version:")
    print(f"  {version[:80]}")

    # List all tables
    cur.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        ORDER BY table_name
    """)
    tables = cur.fetchall()

    print(f"\\nTables in database: {len(tables)}")
    for table in tables:
        print(f"  - {table[0]}")

    # Get row counts for key tables
    print(f"\\nRow Counts:")
    key_tables = ['domains', 'scan_history', 'certificate_history', 'threat_intelligence']
    for table_name in key_tables:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cur.fetchone()[0]
            print(f"  {table_name:30s} {count:>10,} rows")
        except Exception as e:
            print(f"  {table_name:30s} {'ERROR':>10s}")

    conn.close()

    print("\\n" + "=" * 70)
    print("✓ DATABASE CONNECTION TEST PASSED")
    print("=" * 70)

except Exception as e:
    print(f"\\n✗ Database connection FAILED!")
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
ENDPYTHON
'''

def run_test_on_instance(ssm_client, instance_id):
    """Run database connection test on instance"""
    print(f"\n{'='*70}")
    print(f"Testing database connection on: {instance_id}")
    print(f"{'='*70}")

    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [TEST_SCRIPT]},
        TimeoutSeconds=60
    )

    command_id = response['Command']['CommandId']
    print(f"Command ID: {command_id}")
    print("Waiting for test to complete...")

    # Wait for completion
    for i in range(20):
        time.sleep(3)
        try:
            result = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            status = result['Status']

            if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                print(f"\n{'='*70}")
                print(f"Status: {status}")
                print(f"{'='*70}")

                if result.get('StandardOutputContent'):
                    print("\nOutput:")
                    print(result['StandardOutputContent'])

                if result.get('StandardErrorContent'):
                    print("\nErrors:")
                    print(result['StandardErrorContent'])

                return status == 'Success'

        except ssm_client.exceptions.InvocationDoesNotExist:
            pass

    print("✗ Timeout waiting for test to complete")
    return False


def main():
    """Main function"""
    ssm_client = boto3.client('ssm', region_name=REGION)

    success = run_test_on_instance(ssm_client, INSTANCES[0])

    if success:
        print("\n✓ Database connectivity test PASSED")
        return 0
    else:
        print("\n✗ Database connectivity test FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
