#!/usr/bin/env python3
"""Configure Apache to serve the Flask application properly"""

import boto3
import time
import sys

REGION = 'us-east-1'
INSTANCES = ['i-05add94e8603bd5b3', 'i-0f730a50a9d1723fd']

APACHE_CONFIG_SCRIPT = '''#!/bin/bash
set -e

echo "======================================================================="
echo "Configuring Apache for DNS Science Flask Application"
echo "======================================================================="

# Install required packages
echo "Installing required packages..."
apt-get update -qq
apt-get install -y -qq libapache2-mod-wsgi-py3 python3-pip python3-venv

# Install Python dependencies
echo "Installing Python dependencies..."
cd /var/www/dnsscience
pip3 install -q python-dotenv psycopg2-binary flask redis

# Create WSGI file that loads environment variables
echo "Creating WSGI configuration..."
cat > /var/www/dnsscience/dnsscience.wsgi << 'EOFWSGI'
#!/usr/bin/python3
import sys
import os
from pathlib import Path

# Add application directory to Python path
sys.path.insert(0, '/var/www/dnsscience')

# Load environment variables from .env file
env_file = Path('/var/www/dnsscience/.env')
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key] = value

# Import Flask application
from app import app as application
EOFWSGI

chmod 644 /var/www/dnsscience/dnsscience.wsgi

# Create Apache configuration
echo "Creating Apache virtual host configuration..."
cat > /etc/apache2/sites-available/dnsscience.conf << 'EOFAPACHE'
<VirtualHost *:80>
    ServerName dnsscience.io
    ServerAlias www.dnsscience.io

    # Set environment variables for Apache/WSGI
    SetEnv DB_HOST dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com
    SetEnv DB_PORT 5432
    SetEnv DB_NAME dnsscience
    SetEnv DB_USER dnsscience
    SetEnv DB_PASS lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK
    SetEnv REDIS_HOST dnsscience-redis.092cyw.0001.use1.cache.amazonaws.com
    SetEnv REDIS_PORT 6379

    # WSGI Configuration
    WSGIDaemonProcess dnsscience user=www-data group=www-data threads=5 python-path=/var/www/dnsscience
    WSGIScriptAlias / /var/www/dnsscience/dnsscience.wsgi

    <Directory /var/www/dnsscience>
        WSGIProcessGroup dnsscience
        WSGIApplicationGroup %{GLOBAL}
        Require all granted
        Options -Indexes +FollowSymLinks
    </Directory>

    # Static files
    Alias /static /var/www/dnsscience/static
    <Directory /var/www/dnsscience/static>
        Require all granted
        Options -Indexes
    </Directory>

    # Health check endpoint
    <Location /health>
        Require all granted
    </Location>

    # Logging
    ErrorLog ${APACHE_LOG_DIR}/dnsscience-error.log
    CustomLog ${APACHE_LOG_DIR}/dnsscience-access.log combined

    # Security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
</VirtualHost>
EOFAPACHE

# Enable required modules
echo "Enabling Apache modules..."
a2enmod wsgi headers rewrite

# Disable default site and enable DNS Science site
echo "Configuring virtual hosts..."
a2dissite 000-default.conf 2>/dev/null || true
a2ensite dnsscience.conf

# Set correct permissions
echo "Setting permissions..."
chown -R www-data:www-data /var/www/dnsscience
chmod 755 /var/www/dnsscience
chmod 644 /var/www/dnsscience/*.py
chmod 600 /var/www/dnsscience/.env

# Test Apache configuration
echo "Testing Apache configuration..."
apache2ctl configtest

# Restart Apache
echo "Restarting Apache..."
systemctl restart apache2

# Wait for Apache to start
sleep 3

# Test the application
echo ""
echo "Testing application..."
curl -s http://localhost/health | python3 -m json.tool || echo "Health check returned non-JSON response"

echo ""
echo "======================================================================="
echo "✓ Apache configuration complete!"
echo "======================================================================="
echo ""
echo "Application Status:"
systemctl status apache2 --no-pager -l | head -15
echo ""
echo "Recent logs:"
tail -20 /var/log/apache2/dnsscience-error.log 2>/dev/null || echo "No error logs yet"
'''

def configure_instance(ssm_client, instance_id):
    """Configure Apache on an instance"""
    print(f"\n{'='*70}")
    print(f"Configuring Apache on: {instance_id}")
    print(f"{'='*70}")

    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [APACHE_CONFIG_SCRIPT]},
        TimeoutSeconds=300
    )

    command_id = response['Command']['CommandId']
    print(f"Command ID: {command_id}")
    print("Waiting for configuration to complete...")

    # Wait for completion
    for i in range(40):
        time.sleep(5)
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

    print("✗ Timeout waiting for configuration to complete")
    return False


def main():
    """Main function"""
    print("="*70)
    print("DNS Science - Configure Apache for Flask Application")
    print("="*70)

    ssm_client = boto3.client('ssm', region_name=REGION)

    success_count = 0
    for instance_id in INSTANCES:
        if configure_instance(ssm_client, instance_id):
            success_count += 1

    # Summary
    print(f"\n{'='*70}")
    print(f"Configuration Summary")
    print(f"{'='*70}")
    print(f"Total instances: {len(INSTANCES)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {len(INSTANCES) - success_count}")

    if success_count == len(INSTANCES):
        print(f"\n✓ All configurations successful!")
        return 0
    else:
        print(f"\n✗ Some configurations failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
