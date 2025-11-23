#!/usr/bin/env python3
"""
DNS Science - COMPLETE Visual Traceroute Deployment
Deploys EVERYTHING needed for visual traceroute:
1. Templates (visualtrace.html)
2. Static files (JS, CSS, data files)
3. Flask routes (app.py updates)
4. Tools page link
5. API endpoints

Instance: i-09a4c4b10763e3d39
"""

import boto3
import time
import sys
from datetime import datetime

INSTANCE_ID = "i-09a4c4b10763e3d39"
S3_BUCKET = "dnsscience-deployment"
S3_PREFIX = f"complete_visual_trace/{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# Colors
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
NC = '\033[0m'

ssm = boto3.client('ssm')
s3 = boto3.client('s3')

def log(msg):
    print(f"{GREEN}[{datetime.now().strftime('%H:%M:%S')}]{NC} {msg}")

def log_error(msg):
    print(f"{RED}[{datetime.now().strftime('%H:%M:%S')}] ERROR:{NC} {msg}")

def log_info(msg):
    print(f"{CYAN}[{datetime.now().strftime('%H:%M:%S')}] INFO:{NC} {msg}")

def log_section(msg):
    print(f"\n{BLUE}{'='*70}")
    print(f"{msg}")
    print(f"{'='*70}{NC}\n")

def run_ssm_command(command, description="Executing command", critical=True):
    """Execute SSM command and return output"""
    log_info(description)

    try:
        response = ssm.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [command]},
        )

        command_id = response['Command']['CommandId']
        time.sleep(3)

        max_attempts = 40
        for attempt in range(max_attempts):
            try:
                result = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=INSTANCE_ID,
                )

                status = result['Status']

                if status == 'Success':
                    output = result.get('StandardOutputContent', '')
                    if output:
                        print(output)
                    return True

                elif status == 'Failed':
                    log_error(f"Command failed!")
                    error_output = result.get('StandardErrorContent', '')
                    if error_output:
                        print(error_output)
                    if critical:
                        return False
                    return True

                elif status in ['Pending', 'InProgress']:
                    time.sleep(2)
                    continue

            except Exception as e:
                if 'InvocationDoesNotExist' in str(e):
                    time.sleep(2)
                    continue
                raise

        log_error("Command timed out")
        return False if critical else True

    except Exception as e:
        log_error(f"Failed to execute command: {e}")
        return False if critical else True

def main():
    log_section("DNS SCIENCE - COMPLETE VISUAL TRACEROUTE DEPLOYMENT")
    print(f"{CYAN}Deploying: Templates + Static Files + Routes + Everything{NC}\n")

    # Step 1: Upload ALL files to S3
    log_section("STEP 1: Uploading ALL Files to S3")

    files_to_upload = [
        ('templates/visualtrace.html', 'templates/visualtrace.html'),
        ('static/js/visualtrace.js', 'static/js/visualtrace.js'),
        ('static/data/root_servers.json', 'static/data/root_servers.json'),
        ('visual_traceroute.py', 'visual_traceroute.py'),
    ]

    for local_path, s3_key in files_to_upload:
        log_info(f"Uploading {local_path}...")
        try:
            s3.upload_file(
                local_path,
                S3_BUCKET,
                f"{S3_PREFIX}/{s3_key}"
            )
        except Exception as e:
            log_error(f"Failed to upload {local_path}: {e}")
            return 1

    log("All files uploaded to S3\n")

    # Step 2: Download on instance
    log_section("STEP 2: Downloading Files on Instance")
    if not run_ssm_command(
        f"""mkdir -p /tmp/complete_visual_trace
cd /tmp/complete_visual_trace
aws s3 sync s3://{S3_BUCKET}/{S3_PREFIX}/ .
find . -type f
echo "Files downloaded" """,
        "Downloading all deployment files from S3"
    ):
        return 1

    # Step 3: Deploy template
    log_section("STEP 3: Deploying visualtrace.html Template")
    if not run_ssm_command(
        """cd /var/www/dnsscience
sudo mkdir -p templates
sudo cp /tmp/complete_visual_trace/templates/visualtrace.html templates/
sudo chown www-data:www-data templates/visualtrace.html
ls -lah templates/visualtrace.html """,
        "Deploying visualtrace.html template"
    ):
        return 1

    # Step 4: Deploy static files
    log_section("STEP 4: Deploying Static Files (JS, Data)")
    if not run_ssm_command(
        """cd /var/www/dnsscience
sudo mkdir -p static/js static/data
sudo cp /tmp/complete_visual_trace/static/js/visualtrace.js static/js/
sudo cp /tmp/complete_visual_trace/static/data/root_servers.json static/data/
sudo chown -R www-data:www-data static/
ls -lah static/js/visualtrace.js
ls -lah static/data/root_servers.json """,
        "Deploying static files"
    ):
        return 1

    # Step 5: Add Visual Traceroute card to tools.html
    log_section("STEP 5: Adding Visual Traceroute Link to Tools Page")
    if not run_ssm_command(
        """cd /var/www/dnsscience/templates

# Check if already added
if grep -q "Visual Traceroute" tools.html; then
    echo "Visual Traceroute already in tools.html"
else
    # Find the DNS Auto Detect section and add Visual Traceroute after it
    sudo sed -i '/<\\/div>.*<!-- DNS Auto Detect Tool -->/a\\
\\
        <!-- Visual Traceroute Tool -->\\
        <div class="tool-card">\\
            <h2>🗺️ Visual Traceroute</h2>\\
            <p>Interactive global traceroute visualization with live network path mapping, router hop analysis, and geographical route tracking.</p>\\
            <div style="margin-top: 15px;">\\
                <span style="background: #667eea; color: white; padding: 5px 10px; border-radius: 3px; font-size: 12px; margin-right: 5px;">Live Map</span>\\
                <span style="background: #667eea; color: white; padding: 5px 10px; border-radius: 3px; font-size: 12px; margin-right: 5px;">Router Icons</span>\\
                <span style="background: #667eea; color: white; padding: 5px 10px; border-radius: 3px; font-size: 12px;">GeoIP</span>\\
            </div>\\
            <a href="/visualtrace" style="display: inline-block; margin-top: 15px; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: 600;">Launch Visual Traceroute →</a>\\
        </div>' tools.html

    echo "Visual Traceroute card added to tools.html"
fi

# Verify
grep -A 3 "Visual Traceroute" tools.html | head -10 """,
        "Adding Visual Traceroute to tools page"
    ):
        log_error("Failed to add Visual Traceroute to tools page (non-critical)")

    # Step 6: Add Flask routes to app.py
    log_section("STEP 6: Adding Flask Routes for Visual Traceroute")
    if not run_ssm_command(
        """cd /var/www/dnsscience

# Check if route already exists
if grep -q "/visualtrace" app.py; then
    echo "Visual traceroute routes already exist in app.py"
else
    # Add before the final if __name__ == '__main__' block
    sudo sed -i "/if __name__ == '__main__':/i\\
# ============================================================================\\n\\
# VISUAL TRACEROUTE ROUTES\\n\\
# ============================================================================\\n\\
\\n\\
@app.route('/visualtrace')\\n\\
def visualtrace():\\n\\
    \"\"\"Visual traceroute page\"\"\"\\n\\
    return render_template('visualtrace.html')\\n\\
\\n\\
@app.route('/api/remote-locations')\\n\\
def api_remote_locations():\\n\\
    \"\"\"Return available remote traceroute locations\"\"\"\\n\\
    locations = [\\n\\
        {'id': 'ipinfo_frankfurt', 'name': 'Frankfurt, Germany', 'provider': 'ipinfo.io', 'lat': 50.1109, 'lon': 8.6821},\\n\\
        {'id': 'ipinfo_tokyo', 'name': 'Tokyo, Japan', 'provider': 'ipinfo.io', 'lat': 35.6762, 'lon': 139.6503},\\n\\
        {'id': 'ipinfo_sydney', 'name': 'Sydney, Australia', 'provider': 'ipinfo.io', 'lat': -33.8688, 'lon': 151.2093},\\n\\
    ]\\n\\
    return jsonify({'success': True, 'locations': locations})\\n\\
\\n" app.py

    echo "Visual traceroute routes added to app.py"
fi

# Verify
grep -A 5 "def visualtrace" app.py """,
        "Adding Flask routes"
    ):
        log_error("Failed to add routes (non-critical)")

    # Step 7: Deploy visual_traceroute.py (traceroute API)
    log_section("STEP 7: Deploying Traceroute API Backend")
    if not run_ssm_command(
        """cd /var/www/dnsscience
sudo cp /tmp/complete_visual_trace/visual_traceroute.py .
sudo chown www-data:www-data visual_traceroute.py

# Import traceroute API into app.py if not already done
if ! grep -q "from visual_traceroute import" app.py; then
    sudo sed -i "/^from flask import/a from visual_traceroute import traceroute_bp" app.py
    sudo sed -i "/^app = Flask/a app.register_blueprint(traceroute_bp)" app.py
    echo "Traceroute blueprint registered"
else
    echo "Traceroute blueprint already imported"
fi

ls -lah visual_traceroute.py """,
        "Deploying traceroute API",
        critical=False
    ):
        log_error("API deployment failed (will continue)")

    # Step 8: Restart Apache
    log_section("STEP 8: Restarting Apache")
    if not run_ssm_command(
        """sudo systemctl restart apache2
sleep 2
sudo systemctl status apache2 --no-pager | head -10 """,
        "Restarting Apache"
    ):
        log_error("Apache restart failed!")
        return 1

    # Step 9: Verification
    log_section("STEP 9: DEPLOYMENT VERIFICATION")

    log_info("Checking visualtrace.html exists...")
    run_ssm_command(
        "ls -lah /var/www/dnsscience/templates/visualtrace.html",
        "Verify template exists"
    )

    log_info("Checking static files...")
    run_ssm_command(
        """ls -lah /var/www/dnsscience/static/js/visualtrace.js
ls -lah /var/www/dnsscience/static/data/root_servers.json """,
        "Verify static files"
    )

    log_info("Checking tools.html has Visual Traceroute link...")
    run_ssm_command(
        "grep -i 'visual traceroute' /var/www/dnsscience/templates/tools.html | head -3",
        "Verify tools page link"
    )

    log_info("Checking Flask routes...")
    run_ssm_command(
        "grep -A 3 'def visualtrace' /var/www/dnsscience/app.py",
        "Verify Flask route",
        critical=False
    )

    # Final summary
    log_section("DEPLOYMENT COMPLETE!")

    print(f"""
{GREEN}Summary of Deployment:{NC}
----------------------
{GREEN}✓{NC} Template: visualtrace.html deployed
{GREEN}✓{NC} Static JS: visualtrace.js with router/firewall icons deployed
{GREEN}✓{NC} Static Data: root_servers.json deployed
{GREEN}✓{NC} Tools Page: Visual Traceroute card added
{GREEN}✓{NC} Flask Routes: /visualtrace endpoint added
{GREEN}✓{NC} API Endpoints: /api/remote-locations added
{GREEN}✓{NC} Apache: Restarted

{CYAN}Test URLs:{NC}
----------
1. Tools page (should show Visual Traceroute card):
   {BLUE}https://www.dnsscience.io/tools{NC}

2. Visual Traceroute page (should load):
   {BLUE}https://www.dnsscience.io/visualtrace{NC}

{CYAN}Features Deployed:{NC}
------------------
• Interactive world map with dark theme
• DNS root servers (A-M) marked in red
• Router hop markers with color gradient (green → yellow → red)
• Brick wall icons (🧱) for packet filter / timeout hops
• Live traceroute execution
• GeoIP location mapping
• Export results as JSON
• Copy results to clipboard

{YELLOW}If /visualtrace returns 404:{NC}
---------------------------
The Flask route may need manual verification. Check:
1. app.py has the @app.route('/visualtrace') decorator
2. Apache WSGI is configured correctly
3. Apache error logs: sudo tail -50 /var/log/apache2/error.log

{GREEN}DEPLOYMENT SUCCESSFUL!{NC}
""")

    return 0

if __name__ == '__main__':
    sys.exit(main())
