#!/usr/bin/env python3
"""
Add Visual Traceroute Routes to app.py
======================================
"""

import boto3
import time

INSTANCE_ID = 'i-04782c22ad2cac52f'
ssm = boto3.client('ssm', region_name='us-east-1')
s3 = boto3.client('s3', region_name='us-east-1')

VISUAL_TRACEROUTE_ROUTES = '''# ============================================================================
# VISUAL TRACEROUTE ROUTES
# ============================================================================

@app.route('/visualtrace')
def visualtrace_page():
    """Visual traceroute with interactive map"""
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

def run_ssm(cmd, desc, timeout=120):
    """Run SSM command"""
    print(f"[*] {desc}...")
    resp = ssm.send_command(
        InstanceIds=[INSTANCE_ID],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [cmd]}
    )
    cmd_id = resp['Command']['CommandId']
    time.sleep(3)

    for _ in range(timeout // 3):
        try:
            result = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=INSTANCE_ID)
            if result['Status'] == 'Success':
                return result.get('StandardOutputContent', '')
            elif result['Status'] in ['Failed', 'Cancelled', 'TimedOut']:
                print(f"[!] Failed: {result.get('StandardErrorContent', '')[:200]}")
                return None
            time.sleep(3)
        except:
            time.sleep(3)
    return None

def main():
    print("=" * 70)
    print("Adding Visual Traceroute Routes to app.py")
    print("=" * 70)

    # Download from S3
    print("\n[1/6] Downloading production app.py from S3...")
    s3.download_file('dnsscience-deployments', 'app-files/app.py', '/tmp/app_prod.py')

    with open('/tmp/app_prod.py', 'r') as f:
        content = f.read()

    print(f"[+] Downloaded {len(content)} bytes, {content.count(chr(10))} lines")

    # Check if already has visualtrace
    if 'def visualtrace_page' in content:
        print("[!] Visual traceroute routes already present!")
        return

    # Insert before if __name__
    print("\n[2/6] Adding visual traceroute routes...")
    parts = content.split("\nif __name__ == '__main__':")
    if len(parts) != 2:
        print("[!] Could not find if __name__ block")
        return

    new_content = parts[0] + "\n" + VISUAL_TRACEROUTE_ROUTES + "\nif __name__ == '__main__':" + parts[1]

    # Save locally
    with open('/tmp/app_fixed_final.py', 'w') as f:
        f.write(new_content)

    print(f"[+] New size: {len(new_content)} bytes, {new_content.count(chr(10))} lines")

    # Verify syntax
    print("\n[3/6] Verifying Python syntax...")
    import subprocess
    result = subprocess.run(['python3', '-m', 'py_compile', '/tmp/app_fixed_final.py'],
                          capture_output=True)
    if result.returncode != 0:
        print(f"[!] Syntax error: {result.stderr.decode()}")
        return

    print("[+] Syntax valid!")

    # Upload to S3
    print("\n[4/6] Uploading to S3...")
    timestamp = int(time.time())
    s3_key = f'deployments/app.py.with-visualtrace.{timestamp}'

    s3.put_object(
        Bucket='dnsscience-deployments',
        Key=s3_key,
        Body=new_content.encode('utf-8')
    )
    print(f"[+] Uploaded to s3://dnsscience-deployments/{s3_key}")

    # Deploy to instance
    print("\n[5/6] Deploying to production...")

    deploy_cmd = f'''
cd /var/www/dnsscience
cp app.py app.py.backup.{timestamp}
aws s3 cp s3://dnsscience-deployments/{s3_key} app.py.new

python3 -m py_compile app.py.new
if [ $? -eq 0 ]; then
    mv app.py.new app.py
    chown www-data:www-data app.py
    chmod 644 app.py
    systemctl restart apache2
    sleep 3
    echo "SUCCESS"
else
    echo "FAILED"
    exit 1
fi
'''

    result = run_ssm(deploy_cmd, "Deploying app.py", 60)
    if result and 'SUCCESS' in result:
        print("[+] Deployed successfully!")
    else:
        print(f"[!] Deployment failed: {result}")
        return

    # Verify
    print("\n[6/6] Verifying...")
    verify_cmd = '''
curl -s -o /dev/null -w "%{http_code}" http://localhost/visualtrace
echo ""
curl -s -o /dev/null -w "%{http_code}" http://localhost/api/remote-locations
echo ""
systemctl status apache2 --no-pager | grep active
'''

    result = run_ssm(verify_cmd, "Verifying deployment", 30)
    print(result)

    print("\n" + "=" * 70)
    print("DEPLOYMENT COMPLETE!")
    print("=" * 70)
    print("\nTest URLs:")
    print("  https://dnsscience.io/visualtrace")
    print("  https://dnsscience.io/api/remote-locations")
    print(f"\nBackup: app.py.backup.{timestamp}")

if __name__ == '__main__':
    main()
