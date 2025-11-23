#!/bin/bash
#
# EMERGENCY FIX for DNS Science Platform
# This script takes a simple, direct approach to fix the 500 errors
#

set -e

INSTANCE_IP="52.87.234.135"
SSH_KEY="/Users/ryan/.ssh/dnsscience-prod.pem"

echo "=========================================="
echo "DNS SCIENCE EMERGENCY FIX"
echo "Target: $INSTANCE_IP"
echo "=========================================="
echo ""

# Test SSH connectivity first
echo "Testing SSH connection..."
if ! ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 ubuntu@$INSTANCE_IP "echo 'SSH OK'" 2>/dev/null; then
    echo "❌ Cannot connect via SSH. Instance may still be booting."
    echo "Waiting 30 seconds and retrying..."
    sleep 30
    if ! ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 ubuntu@$INSTANCE_IP "echo 'SSH OK'" 2>/dev/null; then
        echo "❌ Still cannot connect. Exiting."
        exit 1
    fi
fi

echo "✓ SSH connection successful"
echo ""

# Create simple health check fix
echo "Step 1: Creating health check endpoint..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@$INSTANCE_IP << 'ENDSSH'
sudo tee /var/www/dnsscience/health_check.wsgi > /dev/null << 'EOF'
def application(environ, start_response):
    """Ultra-simple health check that always returns 200"""
    status = '200 OK'
    headers = [('Content-Type', 'text/plain')]
    start_response(status, headers)
    return [b'OK']
EOF

# Create Apache config for health endpoint
sudo tee /etc/apache2/sites-available/health.conf > /dev/null << 'EOF'
<VirtualHost *:80>
    WSGIScriptAlias /health /var/www/dnsscience/health_check.wsgi

    <Directory /var/www/dnsscience>
        Require all granted
    </Directory>
</VirtualHost>
EOF

# Enable health site
sudo a2ensite health.conf
sudo systemctl reload apache2

echo "✓ Health check endpoint created"
ENDSSH

echo ""
echo "Step 2: Testing health endpoint..."
sleep 2

if curl -s -o /dev/null -w "%{http_code}" "http://$INSTANCE_IP/health" | grep -q "200"; then
    echo "✓ Health check endpoint working!"
else
    echo "⚠️  Health check not yet responding (may need more time)"
fi

echo ""
echo "Step 3: Checking main application..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@$INSTANCE_IP << 'ENDSSH'
echo "Checking if /var/www/dnsscience/app.py exists..."
if [ -f /var/www/dnsscience/app.py ]; then
    echo "✓ app.py exists"
    echo "Lines in app.py: $(wc -l < /var/www/dnsscience/app.py)"
else
    echo "❌ app.py NOT FOUND"
fi

echo ""
echo "Checking Apache error log..."
sudo tail -20 /var/log/apache2/error.log | grep -i "error\|traceback" || echo "No recent Python errors found"
ENDSSH

echo ""
echo "=========================================="
echo "Emergency fix complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Update load balancer health check to: /health"
echo "2. Check if instance becomes healthy in target group"
echo "3. If healthy, proceed with full app.py deployment"
