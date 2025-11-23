#!/usr/bin/env python3
"""
Fix and Deploy app.py
====================
This script:
1. Downloads production app.py
2. Adds missing visual traceroute routes
3. Adds missing if __name__ == '__main__': block
4. Deploys to production
5. Restarts Apache
"""

import boto3
import time
import sys

INSTANCE_ID = 'i-09a4c4b10763e3d39'
ssm = boto3.client('ssm', region_name='us-east-1')

def run_ssm_command(command, description="Running command", timeout=120):
    """Execute SSM command and return output"""
    print(f"[*] {description}...")

    response = ssm.send_command(
        InstanceIds=[INSTANCE_ID],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [command]}
    )

    command_id = response['Command']['CommandId']

    # Wait for command to complete
    time.sleep(3)

    for i in range(timeout // 3):
        try:
            result = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=INSTANCE_ID
            )

            status = result['Status']

            if status == 'Success':
                output = result.get('StandardOutputContent', '')
                error = result.get('StandardErrorContent', '')
                if error:
                    print(f"[!] Stderr: {error[:500]}")
                return output
            elif status in ['Failed', 'Cancelled', 'TimedOut']:
                error = result.get('StandardErrorContent', 'Unknown error')
                print(f"[!] Command failed: {error[:500]}")
                return None

            time.sleep(3)
        except Exception as e:
            print(f"[!] Error checking command: {e}")
            time.sleep(3)

    print(f"[!] Command timed out after {timeout}s")
    return None

# Visual traceroute routes to add
VISUAL_TRACEROUTE_ROUTES = '''
# ========================================
# Visual Traceroute Routes
# ========================================

@app.route('/visualtrace')
def visualtrace_page():
    """Visual traceroute with map"""
    return render_template('visualtrace.html')

@app.route('/api/remote-locations', methods=['GET'])
def api_remote_locations():
    """Get available remote traceroute locations"""
    locations = [
        {
            'id': 'us-east',
            'name': 'US East (Virginia)',
            'provider': 'Hurricane Electric',
            'lat': 38.9072,
            'lon': -77.0369,
            'endpoint': 'https://lg.he.net'
        },
        {
            'id': 'us-west',
            'name': 'US West (California)',
            'provider': 'Hurricane Electric',
            'lat': 37.7749,
            'lon': -122.4194,
            'endpoint': 'https://lg.he.net'
        },
        {
            'id': 'eu-west',
            'name': 'Europe (London)',
            'provider': 'LINX',
            'lat': 51.5074,
            'lon': -0.1278,
            'endpoint': 'https://www.lonap.net/lg/'
        },
        {
            'id': 'asia-east',
            'name': 'Asia (Tokyo)',
            'provider': 'JPIX',
            'lat': 35.6762,
            'lon': 139.6503,
            'endpoint': 'https://lg.jpix.ad.jp'
        },
        {
            'id': 'oceania',
            'name': 'Australia (Sydney)',
            'provider': 'Vocus',
            'lat': -33.8688,
            'lon': 151.2093,
            'endpoint': 'https://lg.vocus.net.au'
        }
    ]

    return jsonify({
        'success': True,
        'locations': locations
    })
'''

MAIN_BLOCK = '''
# ========================================
# Main Entry Point
# ========================================

if __name__ == '__main__':
    # Development server (NOT FOR PRODUCTION)
    # In production, use WSGI server (gunicorn, uwsgi, mod_wsgi)
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )
'''

def main():
    print("=" * 70)
    print("DNS Science app.py Fix and Deployment Script")
    print("=" * 70)

    # Step 1: Download current app.py
    print("\n[1/7] Downloading production app.py...")
    output = run_ssm_command(
        'cat /var/www/dnsscience/app.py',
        'Downloading app.py',
        timeout=30
    )

    if not output:
        print("[!] Failed to download app.py")
        sys.exit(1)

    print(f"[+] Downloaded {len(output)} bytes")

    # Step 2: Check if already has main block or visual traceroute
    print("\n[2/7] Analyzing app.py structure...")
    has_main_block = "if __name__ == '__main__':" in output
    has_visualtrace = '/visualtrace' in output or 'visualtrace_page' in output

    print(f"    Has main block: {has_main_block}")
    print(f"    Has visual traceroute: {has_visualtrace}")

    # Step 3: Backup current app.py
    print("\n[3/7] Creating backup...")
    timestamp = int(time.time())
    backup_cmd = f"cp /var/www/dnsscience/app.py /var/www/dnsscience/app.py.backup.{timestamp}"
    run_ssm_command(backup_cmd, "Backing up app.py")
    print(f"[+] Backup created: app.py.backup.{timestamp}")

    # Step 4: Build fixed app.py
    print("\n[4/7] Building fixed app.py...")

    if not has_visualtrace:
        # Add visual traceroute routes before end
        output = output.rstrip() + "\n" + VISUAL_TRACEROUTE_ROUTES
        print("[+] Added visual traceroute routes")
    else:
        print("[+] Visual traceroute routes already present")

    if not has_main_block:
        # Add main block at the end
        output = output.rstrip() + "\n" + MAIN_BLOCK
        print("[+] Added if __name__ == '__main__': block")
    else:
        print("[+] Main block already present")

    # Save fixed app.py locally
    local_path = '/tmp/app_fixed.py'
    with open(local_path, 'w') as f:
        f.write(output)

    print(f"[+] Fixed app.py saved to {local_path}")
    print(f"[+] Total size: {len(output)} bytes")

    # Step 5: Upload to S3 and then to instance
    print("\n[5/7] Deploying fixed app.py...")

    # Upload to S3
    s3 = boto3.client('s3')
    bucket = 'dnsscience-deployments'
    s3_key = f'deployments/app.py.fixed.{timestamp}'

    try:
        s3.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=output.encode('utf-8'),
            ContentType='text/x-python'
        )
        print(f"[+] Uploaded to s3://{bucket}/{s3_key}")
    except Exception as e:
        print(f"[!] S3 upload failed: {e}")
        print("[*] Falling back to direct SSM upload...")

    # Deploy via SSM
    deploy_cmd = f'''
cd /var/www/dnsscience
cat > app.py.new << 'EOFPYTHON'
{output}
EOFPYTHON

# Verify syntax
python3 -m py_compile app.py.new
if [ $? -eq 0 ]; then
    mv app.py.new app.py
    chown www-data:www-data app.py
    chmod 644 app.py
    echo "SUCCESS: app.py deployed and verified"
else
    echo "ERROR: Python syntax error in app.py.new"
    exit 1
fi
'''

    result = run_ssm_command(deploy_cmd, "Deploying app.py", timeout=60)

    if result and 'SUCCESS' in result:
        print("[+] app.py deployed successfully")
    else:
        print("[!] Deployment failed")
        print(f"Output: {result}")
        sys.exit(1)

    # Step 6: Restart Apache
    print("\n[6/7] Restarting Apache...")
    restart_cmd = 'systemctl restart apache2 && sleep 3 && systemctl status apache2 | head -10'
    result = run_ssm_command(restart_cmd, "Restarting Apache", timeout=30)

    if result and 'active (running)' in result:
        print("[+] Apache restarted successfully")
    else:
        print("[!] Apache restart may have failed")
        print(f"Output: {result}")

    # Step 7: Verify deployment
    print("\n[7/7] Verifying deployment...")
    verify_cmd = '''
curl -s -o /dev/null -w "Visual Traceroute: %{http_code}\\n" http://localhost/visualtrace
curl -s -o /dev/null -w "Remote Locations API: %{http_code}\\n" http://localhost/api/remote-locations
curl -s -o /dev/null -w "Tools Page: %{http_code}\\n" http://localhost/tools
grep -c "visualtrace_page" /var/www/dnsscience/app.py
grep -c "if __name__" /var/www/dnsscience/app.py
'''

    result = run_ssm_command(verify_cmd, "Verifying endpoints", timeout=30)
    print(result)

    print("\n" + "=" * 70)
    print("DEPLOYMENT COMPLETE")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Test https://dnsscience.io/visualtrace")
    print("2. Test https://dnsscience.io/tools")
    print("3. Check https://dnsscience.io/api/remote-locations")
    print("\nBackup location: /var/www/dnsscience/app.py.backup.{}".format(timestamp))

if __name__ == '__main__':
    main()
