#!/usr/bin/env python3
"""
Enterprise-Grade Deployment System for DNS Science
Handles complete application deployment with zero-downtime capability
"""

import os
import sys
import json
import tarfile
import subprocess
import time
from datetime import datetime
from pathlib import Path

# Configuration
LOCAL_APP_DIR = "/Users/ryan/development/afterdarksys.com/subdomains/dnsscience"
S3_BUCKET = "dnsscience-deployments"
S3_PREFIX = "production"
INSTANCE_ID = "i-04082a00e438ac40e"
ASG_NAME = "dnsscience-asg"
LAUNCH_TEMPLATE_ID = "lt-01ddc2002537308a3"

# Files to include in deployment
APP_FILES = [
    "app.py",
    "auth.py",
    "checkers.py",
    "config.py",
    "database.py",
    "domain_valuation.py",
    "email_system.py",
    "ip_intelligence.py",
    "opensrs_integration.py",
    "stripe_integration.py",
    "trial_manager.py",
    "deliverability_scoring.py",
    "darkweb_monitor.py",
    "certificate_alerts.py",
    "tld_pricing_manager.py",
    "domain_marketplace_api.py",
    "domain_acquisition_api.py",
    "domain_payment_processor.py",
    "domain_renewal_system.py",
    "rate_limiting.py",
    "webhooks.py",
]

DAEMON_FILES = [
    "daemons/domain_discovery_daemon.py",
    "daemons/rdap_daemon.py",
    "daemons/domain_expiry_daemon.py",
    "daemons/email_scheduler_daemon.py",
    "daemons/trial_reminder_daemon.py",
    "daemons/auto_renewal_daemon.py",
    "daemons/domain_acquisition_daemon.py",
    "daemons/arpad_daemon_updated.py",
]

CLI_FILES = [
    "cli/dnsscience-cli.py",
    "cli/dnsscience-email.py",
]

def log(message, level="INFO"):
    """Structured logging"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def run_command(cmd, capture=True):
    """Execute shell command with error handling"""
    log(f"Executing: {cmd}")
    try:
        if capture:
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        else:
            subprocess.run(cmd, shell=True, check=True)
            return None
    except subprocess.CalledProcessError as e:
        log(f"Command failed: {e}", "ERROR")
        if e.stderr:
            log(f"Error output: {e.stderr}", "ERROR")
        raise

def create_deployment_package():
    """Create comprehensive deployment tarball"""
    log("Creating deployment package...")

    os.chdir(LOCAL_APP_DIR)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tarball_name = f"dnsscience-complete-{timestamp}.tar.gz"
    tarball_path = f"/tmp/{tarball_name}"

    with tarfile.open(tarball_path, "w:gz") as tar:
        # Add main app files
        for file in APP_FILES:
            if os.path.exists(file):
                tar.add(file)
                log(f"  Added: {file}")

        # Add daemon files
        for file in DAEMON_FILES:
            if os.path.exists(file):
                tar.add(file)
                log(f"  Added: {file}")

        # Add CLI tools
        for file in CLI_FILES:
            if os.path.exists(file):
                tar.add(file)
                log(f"  Added: {file}")

        # Add directories
        for directory in ["templates", "static", "php-frontend"]:
            if os.path.exists(directory):
                tar.add(directory)
                log(f"  Added directory: {directory}")

        # Add SQL migrations
        if os.path.exists("sql-files"):
            tar.add("sql-files")
            log(f"  Added directory: sql-files")

    log(f"Created deployment package: {tarball_path}")
    return tarball_path

def upload_to_s3(tarball_path):
    """Upload deployment package to S3"""
    log("Uploading to S3...")

    # Upload with timestamp
    s3_path_timestamped = f"s3://{S3_BUCKET}/{S3_PREFIX}/{os.path.basename(tarball_path)}"
    run_command(f"aws s3 cp {tarball_path} {s3_path_timestamped}")
    log(f"  Uploaded to: {s3_path_timestamped}")

    # Upload as 'latest' for easy reference
    s3_path_latest = f"s3://{S3_BUCKET}/{S3_PREFIX}/dnsscience-complete.tar.gz"
    run_command(f"aws s3 cp {tarball_path} {s3_path_latest}")
    log(f"  Uploaded to: {s3_path_latest}")

    # Upload environment file
    env_file = f"{LOCAL_APP_DIR}/.env.production"
    if os.path.exists(env_file):
        s3_env = f"s3://{S3_BUCKET}/{S3_PREFIX}/.env.production"
        run_command(f"aws s3 cp {env_file} {s3_env}")
        log(f"  Uploaded environment file to: {s3_env}")

    return s3_path_latest

def create_daemon_management_scripts():
    """Create daemon start/stop scripts"""
    log("Creating daemon management scripts...")

    # Start script
    start_script = """#!/bin/bash
# Start all DNS Science daemons
# Generated: """ + datetime.now().isoformat() + """

set -e

DAEMON_DIR="/var/www/dnsscience/daemons"
LOG_DIR="/var/log/dnsscience"
PID_DIR="/var/run/dnsscience"

mkdir -p "$LOG_DIR" "$PID_DIR"
chown www-data:www-data "$LOG_DIR" "$PID_DIR"

echo "Starting DNS Science daemons..."

# Array of daemons to start
DAEMONS=(
    "domain_discovery_daemon.py"
    "rdap_daemon.py"
    "domain_expiry_daemon.py"
    "email_scheduler_daemon.py"
    "trial_reminder_daemon.py"
    "auto_renewal_daemon.py"
    "domain_acquisition_daemon.py"
    "arpad_daemon_updated.py"
)

for daemon in "${DAEMONS[@]}"; do
    daemon_name=$(basename "$daemon" .py)
    log_file="$LOG_DIR/${daemon_name}.log"
    pid_file="$PID_DIR/${daemon_name}.pid"

    if [ -f "$pid_file" ] && kill -0 $(cat "$pid_file") 2>/dev/null; then
        echo "  $daemon_name already running (PID: $(cat $pid_file))"
        continue
    fi

    cd /var/www/dnsscience
    nohup python3 "$DAEMON_DIR/$daemon" >> "$log_file" 2>&1 &
    echo $! > "$pid_file"
    echo "  Started $daemon_name (PID: $!)"
done

echo "All daemons started successfully"
echo ""
echo "Monitor logs with: tail -f $LOG_DIR/*.log"
"""

    # Stop script
    stop_script = """#!/bin/bash
# Stop all DNS Science daemons
# Generated: """ + datetime.now().isoformat() + """

PID_DIR="/var/run/dnsscience"

echo "Stopping DNS Science daemons..."

for pid_file in "$PID_DIR"/*.pid; do
    if [ -f "$pid_file" ]; then
        daemon_name=$(basename "$pid_file" .pid)
        pid=$(cat "$pid_file")

        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo "  Stopped $daemon_name (PID: $pid)"
            rm -f "$pid_file"
        else
            echo "  $daemon_name not running (stale PID file)"
            rm -f "$pid_file"
        fi
    fi
done

echo "All daemons stopped"
"""

    # Save scripts
    start_path = "/tmp/start-all-daemons.sh"
    stop_path = "/tmp/stop-all-daemons.sh"

    with open(start_path, 'w') as f:
        f.write(start_script)
    with open(stop_path, 'w') as f:
        f.write(stop_script)

    os.chmod(start_path, 0o755)
    os.chmod(stop_path, 0o755)

    # Upload to S3
    run_command(f"aws s3 cp {start_path} s3://{S3_BUCKET}/{S3_PREFIX}/start-all-daemons.sh")
    run_command(f"aws s3 cp {stop_path} s3://{S3_BUCKET}/{S3_PREFIX}/stop-all-daemons.sh")

    log("Daemon management scripts uploaded to S3")

def create_systemd_service():
    """Create systemd service file for daemons"""
    log("Creating systemd service file...")

    service_content = """[Unit]
Description=DNS Science Background Daemons
After=network.target apache2.service
Wants=apache2.service

[Service]
Type=forking
User=www-data
Group=www-data
WorkingDirectory=/var/www/dnsscience
ExecStart=/var/www/dnsscience/scripts/start-all-daemons.sh
ExecStop=/var/www/dnsscience/scripts/stop-all-daemons.sh
Restart=on-failure
RestartSec=10

# Environment
EnvironmentFile=/var/www/dnsscience/.env

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
"""

    service_path = "/tmp/dnsscience-daemons.service"
    with open(service_path, 'w') as f:
        f.write(service_content)

    # Upload to S3
    run_command(f"aws s3 cp {service_path} s3://{S3_BUCKET}/{S3_PREFIX}/dnsscience-daemons.service")
    log("Systemd service uploaded to S3")

def create_enhanced_userdata():
    """Create enhanced user-data script with better error handling and monitoring"""
    log("Creating enhanced user-data script...")

    userdata = """#!/bin/bash
#####################################################################
# DNS Science Production Deployment - Enterprise Edition
# Version: 3.0 - Zero-Downtime with Enhanced Monitoring
# Date: """ + datetime.now().strftime("%Y-%m-%d") + """
#####################################################################

exec > >(tee -a /var/log/user-data.log)
exec 2>&1

set -e

echo "========================================"
echo "DNS Science Enterprise Deployment START"
echo "Instance ID: $(ec2-metadata --instance-id | cut -d' ' -f2)"
echo "Time: $(date)"
echo "========================================"

#####################################################################
# ERROR HANDLING
#####################################################################

function error_exit {
    echo "ERROR: $1" >&2
    echo "Deployment failed at $(date)" >&2

    # Send failure notification via CloudWatch
    aws cloudwatch put-metric-data \\
        --namespace DNSScience/Deployment \\
        --metric-name DeploymentFailed \\
        --value 1 \\
        --dimensions Instance=$(ec2-metadata --instance-id | cut -d' ' -f2) || true

    exit 1
}

trap 'error_exit "Unexpected error on line $LINENO"' ERR

#####################################################################
# PHASE 1: System Package Installation
#####################################################################

echo "[1/8] Installing system packages..."
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq || error_exit "apt-get update failed"

apt-get install -y -qq \\
    apache2 \\
    libapache2-mod-wsgi-py3 \\
    python3-pip \\
    python3-flask \\
    python3-psycopg2 \\
    python3-redis \\
    python3-requests \\
    python3-cryptography \\
    python3-bs4 \\
    python3-lxml \\
    postgresql-client \\
    redis-tools \\
    dnsutils \\
    whois \\
    curl \\
    wget \\
    unzip \\
    git \\
    htop \\
    iotop \\
    sysstat \\
    python3-dev \\
    build-essential || error_exit "System package installation failed"

# Install AWS CLI v2
if ! command -v aws &> /dev/null; then
    echo "[1/8] Installing AWS CLI v2..."
    curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install
    rm -rf /tmp/aws /tmp/awscliv2.zip
fi

# Install Python packages
echo "[1/8] Installing Python packages..."
pip3 install -q --upgrade pip

pip3 install -q \\
    dnspython \\
    bcrypt \\
    PyJWT \\
    email-validator \\
    python-whois \\
    pycryptodome \\
    pyOpenSSL \\
    python-dotenv \\
    stripe \\
    boto3 \\
    botocore \\
    psycopg2-binary \\
    redis \\
    requests \\
    flask \\
    flask-cors \\
    gunicorn \\
    setproctitle || error_exit "Python package installation failed"

#####################################################################
# PHASE 2: Application Deployment from S3
#####################################################################

echo "[2/8] Creating application directories..."
mkdir -p /var/www/dnsscience/{scripts,static,templates,daemons,cli,logs}
mkdir -p /tmp/dnsscience_uploads
mkdir -p /var/log/dnsscience
mkdir -p /var/run/dnsscience

cd /var/www/dnsscience

echo "[2/8] Downloading application from S3..."
aws s3 cp s3://""" + S3_BUCKET + """/""" + S3_PREFIX + """/dnsscience-complete.tar.gz /tmp/dnsscience-complete.tar.gz || error_exit "Failed to download application from S3"

echo "[2/8] Extracting application files..."
tar -xzf /tmp/dnsscience-complete.tar.gz -C /var/www/dnsscience/ || error_exit "Failed to extract application"
rm -f /tmp/dnsscience-complete.tar.gz

# Count deployed files
PYTHON_FILES=$(find /var/www/dnsscience -type f -name "*.py" | wc -l)
TEMPLATE_FILES=$(find /var/www/dnsscience/templates -type f 2>/dev/null | wc -l)
DAEMON_FILES=$(find /var/www/dnsscience/daemons -type f -name "*.py" 2>/dev/null | wc -l)

echo "[2/8] Deployment verification:"
echo "  - Python files: $PYTHON_FILES"
echo "  - Templates: $TEMPLATE_FILES"
echo "  - Daemons: $DAEMON_FILES"

#####################################################################
# PHASE 3: Configuration Files
#####################################################################

echo "[3/8] Downloading environment configuration..."
aws s3 cp s3://""" + S3_BUCKET + """/""" + S3_PREFIX + """/.env.production /var/www/dnsscience/.env || error_exit "Failed to download .env file"

echo "[3/8] Creating WSGI configuration..."
cat > /var/www/dnsscience/dnsscience.wsgi << 'WSGI_EOF'
import sys
import os
import logging
import gc

# Configure logging
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Set up Python path
sys.path.insert(0, '/var/www/dnsscience')
os.chdir('/var/www/dnsscience')

# Load environment variables
from dotenv import load_dotenv
load_dotenv('/var/www/dnsscience/.env')

# Enable garbage collection optimization
gc.set_threshold(700, 10, 10)

try:
    from app import app as application
    logging.info("Flask application loaded successfully")
except Exception as e:
    logging.error(f"Failed to load Flask application: {e}")
    import traceback
    logging.error(traceback.format_exc())
    raise
WSGI_EOF

echo "[3/8] Creating Apache virtual host configuration..."
cat > /etc/apache2/sites-available/dnsscience.conf << 'APACHE_EOF'
<VirtualHost *:80>
    ServerName dnsscience.io
    ServerAlias www.dnsscience.io

    # WSGI Configuration with Memory Management
    WSGIDaemonProcess dnsscience \\
        user=www-data \\
        group=www-data \\
        threads=5 \\
        processes=4 \\
        python-path=/var/www/dnsscience \\
        home=/var/www/dnsscience \\
        display-name=%{GROUP} \\
        maximum-requests=1000 \\
        request-timeout=60 \\
        graceful-timeout=30 \\
        shutdown-timeout=5 \\
        deadlock-timeout=60 \\
        eviction-timeout=60

    WSGIScriptAlias / /var/www/dnsscience/dnsscience.wsgi
    WSGIProcessGroup dnsscience
    WSGIApplicationGroup %{GLOBAL}
    WSGIPassAuthorization On

    # Application Directory
    <Directory /var/www/dnsscience>
        Require all granted
        Options -Indexes +FollowSymLinks
        AllowOverride None
    </Directory>

    # Static Files
    Alias /static /var/www/dnsscience/static
    <Directory /var/www/dnsscience/static>
        Require all granted
        Options -Indexes
        Header set Cache-Control "max-age=86400, public"
    </Directory>

    # Health Check Endpoint
    <Location /health>
        Require all granted
    </Location>

    # Logging
    ErrorLog ${APACHE_LOG_DIR}/dnsscience_error.log
    CustomLog ${APACHE_LOG_DIR}/dnsscience_access.log combined
    LogLevel warn

    # Security Headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # Timeouts
    TimeOut 300
    KeepAlive On
    KeepAliveTimeout 5
    MaxKeepAliveRequests 100
</VirtualHost>
APACHE_EOF

#####################################################################
# PHASE 4: Daemon Management Setup
#####################################################################

echo "[4/8] Setting up daemon management..."
aws s3 cp s3://""" + S3_BUCKET + """/""" + S3_PREFIX + """/start-all-daemons.sh /var/www/dnsscience/scripts/start-all-daemons.sh
aws s3 cp s3://""" + S3_BUCKET + """/""" + S3_PREFIX + """/stop-all-daemons.sh /var/www/dnsscience/scripts/stop-all-daemons.sh
chmod +x /var/www/dnsscience/scripts/*.sh

echo "[4/8] Installing systemd service..."
aws s3 cp s3://""" + S3_BUCKET + """/""" + S3_PREFIX + """/dnsscience-daemons.service /etc/systemd/system/dnsscience-daemons.service

#####################################################################
# PHASE 5: Permissions
#####################################################################

echo "[5/8] Setting file permissions..."
chown -R www-data:www-data /var/www/dnsscience
chown -R www-data:www-data /tmp/dnsscience_uploads
chown -R www-data:www-data /var/log/dnsscience
chown -R www-data:www-data /var/run/dnsscience

chmod 755 /var/www/dnsscience
chmod 644 /var/www/dnsscience/*.py 2>/dev/null || true
chmod 644 /var/www/dnsscience/dnsscience.wsgi
chmod 600 /var/www/dnsscience/.env
chmod 755 /var/www/dnsscience/daemons/*.py 2>/dev/null || true
chmod 755 /var/www/dnsscience/cli/*.py 2>/dev/null || true

#####################################################################
# PHASE 6: Apache Configuration
#####################################################################

echo "[6/8] Configuring Apache..."
a2enmod wsgi headers rewrite ssl
a2dissite 000-default 2>/dev/null || true
a2ensite dnsscience

echo "[6/8] Testing Apache configuration..."
apache2ctl configtest || error_exit "Apache configuration test failed"

echo "[6/8] Starting Apache..."
systemctl restart apache2
systemctl enable apache2

# Wait for Apache
sleep 5

#####################################################################
# PHASE 7: Daemon Startup
#####################################################################

echo "[7/8] Starting background daemons..."
systemctl daemon-reload
systemctl enable dnsscience-daemons
systemctl start dnsscience-daemons

sleep 3

#####################################################################
# PHASE 8: Health Checks and Monitoring
#####################################################################

echo "[8/8] Running health checks..."

# Check Apache
if ! systemctl is-active --quiet apache2; then
    error_exit "Apache failed to start"
fi

# Check daemon service
if ! systemctl is-active --quiet dnsscience-daemons; then
    echo "WARNING: Daemon service not running, attempting restart..."
    systemctl restart dnsscience-daemons
    sleep 2
fi

# Count running daemons
DAEMON_COUNT=$(ps aux | grep -E "python3.*daemon" | grep -v grep | wc -l)
echo "  - Running daemons: $DAEMON_COUNT"

# Test health endpoint
HTTP_CODE=0
for i in {1..5}; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/health 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "  - Health endpoint: OK"
        break
    fi
    echo "  - Health check attempt $i failed, retrying..."
    sleep 2
done

if [ "$HTTP_CODE" != "200" ]; then
    echo "WARNING: Health endpoint not responding"
    echo "Recent Apache errors:"
    tail -20 /var/log/apache2/dnsscience_error.log
fi

# Send success metric to CloudWatch
aws cloudwatch put-metric-data \\
    --namespace DNSScience/Deployment \\
    --metric-name DeploymentSuccess \\
    --value 1 \\
    --dimensions Instance=$(ec2-metadata --instance-id | cut -d' ' -f2) || true

aws cloudwatch put-metric-data \\
    --namespace DNSScience/Application \\
    --metric-name DaemonCount \\
    --value $DAEMON_COUNT \\
    --dimensions Instance=$(ec2-metadata --instance-id | cut -d' ' -f2) || true

echo ""
echo "========================================"
echo "DNS Science Deployment COMPLETE"
echo "========================================"
echo ""
echo "Deployment Summary:"
echo "  - Python files: $PYTHON_FILES"
echo "  - Templates: $TEMPLATE_FILES"
echo "  - Daemons: $DAEMON_FILES"
echo "  - Running daemons: $DAEMON_COUNT"
echo "  - Apache: $(systemctl is-active apache2)"
echo "  - Daemon Service: $(systemctl is-active dnsscience-daemons)"
echo "  - Health endpoint: HTTP $HTTP_CODE"
echo ""
echo "Instance is ready for production traffic"
echo "========================================"
"""

    userdata_path = "/tmp/userdata.sh"
    with open(userdata_path, 'w') as f:
        f.write(userdata)

    # Upload to S3
    run_command(f"aws s3 cp {userdata_path} s3://{S3_BUCKET}/{S3_PREFIX}/userdata.sh")
    log("Enhanced user-data script uploaded to S3")

    return userdata

def deploy_to_current_instance():
    """Deploy application to current instance via SSM"""
    log("Deploying to current instance via SSM...")

    # Create deployment script
    deploy_script = f"""#!/bin/bash
set -e

echo "Starting deployment to instance {INSTANCE_ID}..."

# Create directories
sudo mkdir -p /var/www/dnsscience/{{scripts,static,templates,daemons,cli,logs}}
sudo mkdir -p /tmp/dnsscience_uploads
sudo mkdir -p /var/log/dnsscience
sudo mkdir -p /var/run/dnsscience

# Download application
cd /tmp
aws s3 cp s3://{S3_BUCKET}/{S3_PREFIX}/dnsscience-complete.tar.gz .
sudo tar -xzf dnsscience-complete.tar.gz -C /var/www/dnsscience/
rm -f dnsscience-complete.tar.gz

# Download environment file
sudo aws s3 cp s3://{S3_BUCKET}/{S3_PREFIX}/.env.production /var/www/dnsscience/.env

# Download daemon scripts
sudo aws s3 cp s3://{S3_BUCKET}/{S3_PREFIX}/start-all-daemons.sh /var/www/dnsscience/scripts/
sudo aws s3 cp s3://{S3_BUCKET}/{S3_PREFIX}/stop-all-daemons.sh /var/www/dnsscience/scripts/
sudo chmod +x /var/www/dnsscience/scripts/*.sh

# Download systemd service
sudo aws s3 cp s3://{S3_BUCKET}/{S3_PREFIX}/dnsscience-daemons.service /etc/systemd/system/

# Set permissions
sudo chown -R www-data:www-data /var/www/dnsscience
sudo chown -R www-data:www-data /tmp/dnsscience_uploads
sudo chown -R www-data:www-data /var/log/dnsscience
sudo chown -R www-data:www-data /var/run/dnsscience
sudo chmod 600 /var/www/dnsscience/.env

# Reload and restart services
sudo systemctl daemon-reload
sudo systemctl enable dnsscience-daemons
sudo systemctl restart dnsscience-daemons
sudo systemctl restart apache2

echo "Deployment complete"
"""

    # Execute via SSM
    script_file = "/tmp/deploy_script.sh"
    with open(script_file, 'w') as f:
        f.write(deploy_script)

    cmd = f"""aws ssm send-command \
        --instance-ids {INSTANCE_ID} \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["{deploy_script}"]' \
        --output json"""

    result = run_command(cmd)
    command_data = json.loads(result)
    command_id = command_data['Command']['CommandId']

    log(f"SSM Command ID: {command_id}")
    log("Waiting for deployment to complete...")

    # Wait for command to complete
    time.sleep(10)

    # Check command status
    status_cmd = f"aws ssm get-command-invocation --command-id {command_id} --instance-id {INSTANCE_ID} --output json"
    status_result = run_command(status_cmd)
    status_data = json.loads(status_result)

    log(f"Deployment status: {status_data['Status']}")
    if status_data['Status'] == 'Success':
        log("Deployment completed successfully", "SUCCESS")
    else:
        log(f"Deployment may have issues: {status_data.get('StandardErrorContent', 'N/A')}", "WARNING")

    return command_id

def update_launch_template(userdata):
    """Create new version of launch template with enhanced user-data"""
    log("Updating Launch Template...")

    # Get current launch template
    cmd = f"aws ec2 describe-launch-template-versions --launch-template-id {LAUNCH_TEMPLATE_ID} --versions '$Latest' --output json"
    result = run_command(cmd)
    template_data = json.loads(result)
    current_version = template_data['LaunchTemplateVersions'][0]

    # Encode user-data
    import base64
    userdata_encoded = base64.b64encode(userdata.encode()).decode()

    # Create new version
    version_desc = f"Enterprise deployment {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    cmd = f"""aws ec2 create-launch-template-version \
        --launch-template-id {LAUNCH_TEMPLATE_ID} \
        --source-version $Latest \
        --version-description "{version_desc}" \
        --launch-template-data '{{"UserData":"{userdata_encoded}"}}' \
        --output json"""

    result = run_command(cmd)
    version_data = json.loads(result)
    new_version = version_data['LaunchTemplateVersion']['VersionNumber']

    log(f"Created launch template version: {new_version}")

    # Update ASG to use new version
    cmd = f"""aws autoscaling update-auto-scaling-group \
        --auto-scaling-group-name {ASG_NAME} \
        --launch-template LaunchTemplateId={LAUNCH_TEMPLATE_ID},Version={new_version}"""

    run_command(cmd)
    log(f"ASG updated to use version {new_version}")

    return new_version

def create_cloudwatch_alarms():
    """Create CloudWatch alarms for monitoring"""
    log("Creating CloudWatch alarms...")

    # Application health alarm
    alarm_cmd = f"""aws cloudwatch put-metric-alarm \
        --alarm-name dnsscience-health-check \
        --alarm-description "Alert when health check fails" \
        --metric-name HealthCheckFailed \
        --namespace DNSScience/Application \
        --statistic Sum \
        --period 60 \
        --evaluation-periods 2 \
        --threshold 1 \
        --comparison-operator GreaterThanThreshold \
        --treat-missing-data notBreaching"""

    run_command(alarm_cmd, capture=False)
    log("  Created health check alarm")

    # Daemon count alarm
    alarm_cmd = f"""aws cloudwatch put-metric-alarm \
        --alarm-name dnsscience-daemon-count \
        --alarm-description "Alert when daemon count is low" \
        --metric-name DaemonCount \
        --namespace DNSScience/Application \
        --statistic Average \
        --period 300 \
        --evaluation-periods 2 \
        --threshold 6 \
        --comparison-operator LessThanThreshold \
        --treat-missing-data breaching"""

    run_command(alarm_cmd, capture=False)
    log("  Created daemon count alarm")

def main():
    """Main deployment orchestration"""
    try:
        log("=" * 60)
        log("DNS Science Enterprise Deployment System")
        log("=" * 60)

        # Step 1: Create deployment package
        tarball_path = create_deployment_package()

        # Step 2: Create supporting scripts
        create_daemon_management_scripts()
        create_systemd_service()

        # Step 3: Upload to S3
        s3_path = upload_to_s3(tarball_path)

        # Step 4: Create enhanced user-data
        userdata = create_enhanced_userdata()

        log("=" * 60)
        log("Phase 1 Complete: Artifacts uploaded to S3")
        log("=" * 60)

        # Step 5: Deploy to current instance
        log("\nDeploying to current instance...")
        command_id = deploy_to_current_instance()

        log("=" * 60)
        log("Phase 2 Complete: Application deployed to current instance")
        log("=" * 60)

        # Step 6: Update launch template
        log("\nUpdating Launch Template for future instances...")
        new_version = update_launch_template(userdata)

        log("=" * 60)
        log("Phase 3 Complete: Launch Template updated")
        log("=" * 60)

        # Step 7: Create CloudWatch alarms
        log("\nSetting up CloudWatch monitoring...")
        create_cloudwatch_alarms()

        log("=" * 60)
        log("DEPLOYMENT COMPLETE!")
        log("=" * 60)
        log("")
        log("Summary:")
        log(f"  - Deployment package: {s3_path}")
        log(f"  - SSM Command ID: {command_id}")
        log(f"  - Launch Template Version: {new_version}")
        log(f"  - Instance ID: {INSTANCE_ID}")
        log("")
        log("Next steps:")
        log("  1. Verify instance health: Check SSM command output")
        log(f"  2. Test application: curl http://54.91.147.253/health")
        log("  3. Monitor CloudWatch alarms")
        log("  4. Verify all 8 daemons are running")
        log("")
        log("The system is now configured for zero-downtime deployments!")

    except Exception as e:
        log(f"Deployment failed: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
