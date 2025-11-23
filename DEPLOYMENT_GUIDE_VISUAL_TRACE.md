# Visual Traceroute - Deployment Guide

## Pre-Deployment Checklist

- [ ] Python 3.7+ installed
- [ ] Flask application configured
- [ ] Static file serving enabled
- [ ] Traceroute command available
- [ ] Network access for GeoIP lookups
- [ ] Web server (Apache/Nginx) configured

## Deployment Steps

### 1. Copy Files to Production

```bash
#!/bin/bash

# Set production directory
PROD_DIR="/var/www/dnsscience"

# Copy backend API
cp visual_traceroute.py $PROD_DIR/

# Copy frontend files
cp templates/visualtrace.html $PROD_DIR/templates/
cp static/js/visualtrace.js $PROD_DIR/static/js/
cp static/css/visualtrace.css $PROD_DIR/static/css/

# Copy data files
cp static/data/root_servers.json $PROD_DIR/static/data/
cp static/data/dns_resolvers.json $PROD_DIR/static/data/

echo "Files copied to production"
```

### 2. Integrate with Flask App

Add to your main Flask application:

```python
# app.py or main application file

from flask import Flask, render_template
from visual_traceroute import visual_trace_bp

app = Flask(__name__)

# Register Visual Traceroute blueprint
app.register_blueprint(visual_trace_bp)

# Add route for the page
@app.route('/visualtrace')
def visualtrace():
    """Visual Traceroute Tool"""
    return render_template('visualtrace.html')

# Add to navigation
@app.route('/tools')
def tools():
    tools = [
        {
            'name': 'Visual Traceroute',
            'url': '/visualtrace',
            'description': 'Interactive network path visualization',
            'icon': 'fa-route'
        }
    ]
    return render_template('tools.html', tools=tools)
```

### 3. Configure System Dependencies

```bash
# Install traceroute if not present
sudo apt-get update
sudo apt-get install traceroute -y

# Verify installation
which traceroute
traceroute --version

# Test traceroute (should work without sudo for basic usage)
traceroute google.com
```

### 4. Set Up Permissions

```bash
# Ensure Flask app can execute traceroute
# Option 1: Use traceroute without sudo (preferred)
# Already works for most systems

# Option 2: If sudo required, add to sudoers (NOT RECOMMENDED for production)
# echo "www-data ALL=(ALL) NOPASSWD: /usr/bin/traceroute" >> /etc/sudoers.d/traceroute

# Set file permissions
chmod 644 $PROD_DIR/visual_traceroute.py
chmod 644 $PROD_DIR/templates/visualtrace.html
chmod 644 $PROD_DIR/static/js/visualtrace.js
chmod 644 $PROD_DIR/static/css/visualtrace.css
chmod 644 $PROD_DIR/static/data/*.json

# Set directory permissions
chmod 755 $PROD_DIR/static/data
```

### 5. Configure Flask Production Server

#### Using Gunicorn

```bash
# Install Gunicorn
pip install gunicorn

# Create systemd service
sudo nano /etc/systemd/system/dnsscience.service
```

```ini
[Unit]
Description=DNSScience Flask Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/dnsscience
Environment="PATH=/var/www/dnsscience/venv/bin"
ExecStart=/var/www/dnsscience/venv/bin/gunicorn \
    --workers 4 \
    --bind 127.0.0.1:8000 \
    --timeout 120 \
    --access-logfile /var/log/dnsscience/access.log \
    --error-logfile /var/log/dnsscience/error.log \
    app:app

Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Create log directory
sudo mkdir -p /var/log/dnsscience
sudo chown www-data:www-data /var/log/dnsscience

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable dnsscience
sudo systemctl start dnsscience
sudo systemctl status dnsscience
```

### 6. Configure Nginx Reverse Proxy

```bash
sudo nano /etc/nginx/sites-available/dnsscience
```

```nginx
server {
    listen 80;
    server_name dnsscience.io www.dnsscience.io;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name dnsscience.io www.dnsscience.io;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/dnsscience.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dnsscience.io/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Static files
    location /static {
        alias /var/www/dnsscience/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Traceroute API - longer timeout
    location /api/traceroute {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Extended timeout for traceroute
        proxy_read_timeout 120s;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
    }

    # Other API endpoints
    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Main application
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml text/javascript;
    gzip_min_length 1000;
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/dnsscience /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 7. Install Python Dependencies

```bash
# Create virtual environment
cd /var/www/dnsscience
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install flask requests

# Deactivate
deactivate
```

### 8. Configure Firewall

```bash
# Allow HTTP and HTTPS
sudo ufw allow 'Nginx Full'
sudo ufw status

# If needed, allow outbound for GeoIP
# (Usually allowed by default)
```

### 9. Set Up Rate Limiting

Add to Nginx configuration:

```nginx
# Rate limiting for traceroute API
limit_req_zone $binary_remote_addr zone=traceroute:10m rate=5r/m;

server {
    # ... existing config ...

    location /api/traceroute {
        limit_req zone=traceroute burst=2 nodelay;
        # ... existing proxy config ...
    }
}
```

### 10. Configure GeoIP API

For production, consider upgrading to ipinfo.io paid plan:

```python
# In visual_traceroute.py, update geolocate_ip function:

IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN', None)

def geolocate_ip(ip):
    """Get geographic location for an IP address"""
    if not ip or ip == '*':
        return None

    try:
        url = f'https://ipinfo.io/{ip}/json'
        if IPINFO_TOKEN:
            url += f'?token={IPINFO_TOKEN}'

        response = requests.get(url, timeout=5)
        # ... rest of function
```

Set environment variable:

```bash
# In /etc/systemd/system/dnsscience.service
Environment="IPINFO_TOKEN=your_token_here"
```

### 11. Test Deployment

```bash
# Test traceroute API
curl -X POST https://dnsscience.io/api/traceroute \
  -H "Content-Type: application/json" \
  -d '{"target": "google.com", "source": "local", "max_hops": 15}'

# Test page load
curl https://dnsscience.io/visualtrace

# Test remote locations API
curl https://dnsscience.io/api/remote-locations
```

### 12. Monitor and Logs

```bash
# View application logs
sudo journalctl -u dnsscience -f

# View Nginx access logs
sudo tail -f /var/log/nginx/access.log

# View Nginx error logs
sudo tail -f /var/log/nginx/error.log

# View application-specific logs
sudo tail -f /var/log/dnsscience/error.log
```

## Quick Deploy Script

```bash
#!/bin/bash
# deploy_visual_traceroute.sh

set -e

echo "Deploying Visual Traceroute..."

PROD_DIR="/var/www/dnsscience"
BACKUP_DIR="/var/backups/dnsscience/$(date +%Y%m%d_%H%M%S)"

# Create backup
echo "Creating backup..."
mkdir -p $BACKUP_DIR
cp -r $PROD_DIR/visual_traceroute.py $BACKUP_DIR/ 2>/dev/null || true
cp -r $PROD_DIR/templates/visualtrace.html $BACKUP_DIR/ 2>/dev/null || true
cp -r $PROD_DIR/static/js/visualtrace.js $BACKUP_DIR/ 2>/dev/null || true

# Copy new files
echo "Copying new files..."
cp visual_traceroute.py $PROD_DIR/
cp templates/visualtrace.html $PROD_DIR/templates/
cp static/js/visualtrace.js $PROD_DIR/static/js/
cp static/css/visualtrace.css $PROD_DIR/static/css/
cp static/data/root_servers.json $PROD_DIR/static/data/
cp static/data/dns_resolvers.json $PROD_DIR/static/data/

# Set permissions
echo "Setting permissions..."
chown -R www-data:www-data $PROD_DIR/static/data
chmod 644 $PROD_DIR/visual_traceroute.py
chmod 644 $PROD_DIR/templates/visualtrace.html
chmod 644 $PROD_DIR/static/js/visualtrace.js
chmod 644 $PROD_DIR/static/css/visualtrace.css

# Restart service
echo "Restarting application..."
systemctl restart dnsscience

# Wait for service to start
sleep 3

# Test deployment
echo "Testing deployment..."
if systemctl is-active --quiet dnsscience; then
    echo "✓ Service is running"
else
    echo "✗ Service failed to start"
    exit 1
fi

# Test API endpoint
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" https://dnsscience.io/visualtrace)
if [ $HTTP_CODE -eq 200 ]; then
    echo "✓ Visual Traceroute page accessible"
else
    echo "✗ Page returned HTTP $HTTP_CODE"
    exit 1
fi

echo "Deployment complete!"
echo "Backup saved to: $BACKUP_DIR"
```

## Rollback Procedure

If deployment fails:

```bash
#!/bin/bash
# rollback.sh

BACKUP_DIR="/var/backups/dnsscience/LATEST_BACKUP_TIMESTAMP"
PROD_DIR="/var/www/dnsscience"

echo "Rolling back to backup..."

cp -r $BACKUP_DIR/* $PROD_DIR/
systemctl restart dnsscience

echo "Rollback complete"
```

## Performance Tuning

### Caching GeoIP Results

Add Redis caching for GeoIP lookups:

```python
import redis
import json

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def geolocate_ip(ip):
    # Check cache first
    cache_key = f"geoip:{ip}"
    cached = redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    # ... perform GeoIP lookup ...

    # Cache result for 24 hours
    redis_client.setex(cache_key, 86400, json.dumps(result))
    return result
```

### Database Logging

Log traceroutes to database:

```python
@visual_trace_bp.route('/api/traceroute', methods=['POST'])
def api_traceroute():
    # ... existing code ...

    # Log to database
    db.execute("""
        INSERT INTO traceroute_logs (target, source, hops_count, timestamp)
        VALUES (?, ?, ?, ?)
    """, (target, source, len(hops), datetime.now()))

    return jsonify(result)
```

## Security Hardening

### Input Validation

```python
import re

def validate_target(target):
    # Allow only valid domain names and IPs
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

    if re.match(domain_pattern, target) or re.match(ip_pattern, target):
        return True
    return False
```

### Rate Limiting in Application

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@visual_trace_bp.route('/api/traceroute', methods=['POST'])
@limiter.limit("5 per minute")
def api_traceroute():
    # ... existing code ...
```

## Monitoring

### Application Monitoring

```python
import logging
from datetime import datetime

logging.basicConfig(
    filename='/var/log/dnsscience/traceroute.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@visual_trace_bp.route('/api/traceroute', methods=['POST'])
def api_traceroute():
    start_time = datetime.now()

    # ... existing code ...

    duration = (datetime.now() - start_time).total_seconds()
    logging.info(f"Traceroute to {target}: {len(hops)} hops in {duration}s")
```

### Health Check Endpoint

```python
@visual_trace_bp.route('/api/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'services': {
            'traceroute': check_traceroute_available(),
            'geoip': check_geoip_available()
        }
    })
```

## Support

For deployment issues:
- Check logs: `/var/log/dnsscience/`
- Test API: `curl -X POST https://dnsscience.io/api/traceroute`
- Verify traceroute: `which traceroute`
- Check service: `systemctl status dnsscience`

Email: support@dnsscience.io
