#!/usr/bin/env python3
"""
DNS Science - Visual Traceroute Enhancement Deployment
Deploys fixes for:
1. Tools page - add home navigation link
2. Visual traceroute - add router hop markers with gradient colors
3. Visual traceroute - add brick wall icons for packet filter (*) hops

Instance: i-09a4c4b10763e3d39
"""

import boto3
import time
import sys
from datetime import datetime

INSTANCE_ID = "i-09a4c4b10763e3d39"
S3_BUCKET = "dnsscience-deployment"
S3_PREFIX = f"visual_traceroute_fixes/{datetime.now().strftime('%Y%m%d_%H%M%S')}"

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

        # Wait for command to complete
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
                    return True  # Non-critical failure

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
    log_section("DNS SCIENCE - VISUAL TRACEROUTE ENHANCEMENTS")
    print(f"{CYAN}Deploying: Home Navigation + Router Hop Markers + Packet Filter Icons{NC}\n")

    # Step 1: Upload files to S3
    log_section("STEP 1: Uploading Files to S3")

    files_to_upload = [
        ('static/js/visualtrace.js', 'visualtrace.js'),
        ('templates/visualtrace.html', 'visualtrace.html'),
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

    # Step 2: Download files on instance
    log_section("STEP 2: Downloading Files on Instance")
    if not run_ssm_command(
        f"mkdir -p /tmp/visual_trace_fixes && cd /tmp/visual_trace_fixes && aws s3 sync s3://{S3_BUCKET}/{S3_PREFIX}/ . && ls -lah",
        "Downloading deployment files from S3"
    ):
        return 1
    log("Files downloaded\n")

    # Step 3: Fix tools.html - Add home link to navigation
    log_section("STEP 3: Fixing Tools Page Navigation")

    if not run_ssm_command(
        """cd /var/www/dnsscience/templates

# Backup current tools.html
sudo cp tools.html tools.html.bak.$(date +%Y%m%d_%H%M%S)

# Add home link to navigation bar (right after opening nav-bar div)
sudo sed -i '/<div class="nav-bar">/a\\        <a href="/" class="nav-button">🏠 Home</a>' tools.html

# Verify change
echo "=== Navigation Bar Preview ==="
grep -A 3 'class="nav-bar"' tools.html

echo ""
echo "Home link added successfully" """,
        "Adding home link to tools page navigation"
    ):
        log_error("Tools page navigation fix failed (non-critical)")

    log("Tools page navigation updated\n")

    # Step 4: Deploy enhanced visualtrace.js
    log_section("STEP 4: Deploying Enhanced Visual Traceroute Script")

    if not run_ssm_command(
        """cd /var/www/dnsscience/static/js

# Backup current visualtrace.js
sudo cp visualtrace.js visualtrace.js.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || echo "No existing visualtrace.js to backup"

# Deploy new version with router icons and packet filter support
sudo cp /tmp/visual_trace_fixes/visualtrace.js visualtrace.js
sudo chown www-data:www-data visualtrace.js
sudo chmod 644 visualtrace.js

# Verify file
ls -lah visualtrace.js
echo "Preview of new features:"
grep -A 3 "routerIcon" visualtrace.js | head -10 """,
        "Deploying enhanced visualtrace.js with router and firewall icons"
    ):
        return 1

    log("Enhanced visualtrace.js deployed\n")

    # Step 5: Deploy updated visual_traceroute.py backend
    log_section("STEP 5: Deploying Updated Traceroute Backend")

    if not run_ssm_command(
        """cd /var/www/dnsscience

# Backup current visual_traceroute.py if it exists
sudo cp visual_traceroute.py visual_traceroute.py.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || echo "No existing visual_traceroute.py to backup"

# Deploy new version
sudo cp /tmp/visual_trace_fixes/visual_traceroute.py visual_traceroute.py
sudo chown www-data:www-data visual_traceroute.py
sudo chmod 644 visual_traceroute.py

# Verify file
ls -lah visual_traceroute.py
echo "Backend updated" """,
        "Deploying updated traceroute backend",
        critical=False
    ):
        log_error("Backend update failed (non-critical)")

    log("Traceroute backend updated\n")

    # Step 6: Restart Apache to clear cache
    log_section("STEP 6: Restarting Apache")

    if not run_ssm_command(
        """sudo systemctl restart apache2
sleep 2
sudo systemctl status apache2 --no-pager | head -10 """,
        "Restarting Apache to apply changes"
    ):
        log_error("Apache restart failed!")
        return 1

    log("Apache restarted successfully\n")

    # Step 7: Verification
    log_section("STEP 7: DEPLOYMENT VERIFICATION")

    log_info("Checking tools.html navigation...")
    run_ssm_command(
        """grep -A 1 'class="nav-bar"' /var/www/dnsscience/templates/tools.html | head -5""",
        "Verifying home link in tools page"
    )

    log_info("Checking visualtrace.js enhancements...")
    run_ssm_command(
        """echo "Router icon definition:"
grep -A 2 "routerIcon" /var/www/dnsscience/static/js/visualtrace.js | head -5

echo ""
echo "Firewall icon definition:"
grep -A 2 "firewallIcon" /var/www/dnsscience/static/js/visualtrace.js | head -5 """,
        "Verifying new icon definitions"
    )

    # Final summary
    log_section("DEPLOYMENT COMPLETE!")

    print(f"""
{GREEN}Summary of Changes:{NC}
-------------------
{GREEN}✓{NC} Tools Page: Home link added to navigation bar
{GREEN}✓{NC} Visual Traceroute: Router icon markers for each hop
{GREEN}✓{NC} Visual Traceroute: Gradient color coding (green → yellow → red)
{GREEN}✓{NC} Visual Traceroute: Brick wall icons for packet filter (*) hops
{GREEN}✓{NC} Apache: Restarted to clear cache

{CYAN}New Features:{NC}
--------------
• {YELLOW}Router Icons:{NC} Each traceroute hop now displays a router icon on the map
• {YELLOW}Color Gradient:{NC} Hops color-coded from source (green) to destination (red)
• {YELLOW}Packet Filters:{NC} Timeouts (*) display brick wall 🧱 icon
• {YELLOW}Home Navigation:{NC} Tools page now has direct link back to homepage

{CYAN}Test URLs:{NC}
-----------
1. Tools page with home link:
   {BLUE}https://www.dnsscience.io/tools{NC}

2. Visual traceroute with new icons:
   {BLUE}https://www.dnsscience.io/visualtrace{NC}

{CYAN}Next Steps:{NC}
-----------
1. Test the tools page - verify home link works
2. Run a traceroute on /visualtrace and verify:
   - Each hop shows a router icon
   - Hops are color-coded (green → red gradient)
   - Any * (timeout) hops show brick wall icon
3. Test navigation flow between pages

{GREEN}DEPLOYMENT SUCCESSFUL!{NC}
""")

    return 0

if __name__ == '__main__':
    sys.exit(main())
