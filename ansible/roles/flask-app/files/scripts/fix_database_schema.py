#!/usr/bin/env python3
"""Fix database schema issues - check and fix certificate_history table"""

import boto3
import time
import sys

REGION = 'us-east-1'
INSTANCE = 'i-05add94e8603bd5b3'

FIX_SCHEMA_SCRIPT = '''#!/bin/bash
set -e

cd /var/www/dnsscience
export $(sudo cat .env | grep -v "^#" | grep -v "^$" | xargs)

python3 << 'ENDPYTHON'
import os
import sys
import psycopg2

try:
    print("="*70)
    print("CHECKING AND FIXING DATABASE SCHEMA")
    print("="*70)

    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=5432,
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS")
    )
    conn.autocommit = False

    cur = conn.cursor()

    print("\\nChecking certificate_history table structure...")
    cur.execute("""
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'certificate_history'
        ORDER BY ordinal_position
    """)

    columns = cur.fetchall()
    print(f"Found {len(columns)} columns:")
    for col_name, col_type in columns:
        print(f"  - {col_name}: {col_type}")

    # Check if 'service' column exists
    column_names = [col[0] for col in columns]

    if 'service' not in column_names:
        print("\\n✗ Column 'service' is missing from certificate_history table")
        print("  Adding column...")

        try:
            cur.execute("""
                ALTER TABLE certificate_history
                ADD COLUMN IF NOT EXISTS service VARCHAR(50)
            """)
            conn.commit()
            print("  ✓ Column 'service' added successfully")
        except Exception as e:
            print(f"  ✗ Error adding column: {e}")
            conn.rollback()
            raise
    else:
        print("\\n✓ Column 'service' already exists")

    # Check if 'domain' column exists (sometimes used instead of domain_id)
    if 'domain' not in column_names:
        print("\\nNote: 'domain' column not found (using domain_id foreign key)")

    # Test database operations
    print("\\nTesting database operations...")

    # Get statistics
    cur.execute("SELECT COUNT(*) FROM domains")
    domain_count = cur.fetchone()[0]
    print(f"  Domains: {domain_count}")

    cur.execute("SELECT COUNT(*) FROM scan_history")
    scan_count = cur.fetchone()[0]
    print(f"  Scan history: {scan_count}")

    cur.execute("SELECT COUNT(*) FROM certificate_history")
    cert_count = cur.fetchone()[0]
    print(f"  Certificates: {cert_count}")

    # Reset any stuck transactions by creating a new connection
    conn.close()

    conn2 = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=5432,
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS")
    )
    cur2 = conn2.cursor()

    # Test get_dashboard_statistics query
    print("\\nTesting dashboard statistics query...")
    try:
        cur2.execute("SELECT COUNT(*) as count FROM domains")
        total_domains = cur2.fetchone()[0]

        cur2.execute("""
            SELECT COUNT(DISTINCT domain_id) as count
            FROM scan_history
        """)
        monitored_domains = cur2.fetchone()[0]

        print(f"  Total domains: {total_domains}")
        print(f"  Monitored domains: {monitored_domains}")
        print("  ✓ Dashboard query successful")

    except Exception as e:
        print(f"  ✗ Dashboard query failed: {e}")
        conn2.rollback()

    conn2.close()

    print("\\n" + "="*70)
    print("✓ DATABASE SCHEMA CHECK COMPLETE")
    print("="*70)

except Exception as e:
    print(f"\\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
ENDPYTHON

echo ""
echo "Restarting Apache to clear any cached connections..."
sudo systemctl restart apache2
sleep 2
echo "✓ Apache restarted"
'''

def fix_schema_on_instance(ssm_client, instance_id):
    """Fix database schema on instance"""
    print(f"\n{'='*70}")
    print(f"Fixing database schema on: {instance_id}")
    print(f"{'='*70}")

    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [FIX_SCHEMA_SCRIPT]},
        TimeoutSeconds=120
    )

    command_id = response['Command']['CommandId']
    print(f"Command ID: {command_id}")
    print("Waiting for schema fix to complete...")

    # Wait for completion
    for i in range(30):
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

    print("✗ Timeout waiting for schema fix to complete")
    return False


def main():
    """Main function"""
    print("="*70)
    print("DNS Science - Fix Database Schema")
    print("="*70)

    ssm_client = boto3.client('ssm', region_name=REGION)

    if fix_schema_on_instance(ssm_client, INSTANCE):
        print("\n✓ Database schema fixed successfully!")
        return 0
    else:
        print("\n✗ Database schema fix failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
