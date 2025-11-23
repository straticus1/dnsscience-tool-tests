#!/bin/bash
# Deploy ALL missing pages to DNS Science platform via SSM
# Instance: i-0609352c5884a48ee

INSTANCE_ID="i-0609352c5884a48ee"

echo "=========================================="
echo "DNS SCIENCE - DEPLOY ALL MISSING PAGES"
echo "Instance: $INSTANCE_ID"
echo "=========================================="
echo ""

# Step 1: Add routes to app.py
echo "Step 1: Adding missing routes to app.py..."
aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
"cd /var/www/dnsscience",
"# Backup app.py",
"sudo cp app.py app.py.backup.$(date +%Y%m%d_%H%M%S)",
"# Add missing routes before the if __name__ block",
"sudo python3 << '\''PYTHON'\''
import re

with open(\"/var/www/dnsscience/app.py\", \"r\") as f:
    content = f.read()

# Routes to add
routes_to_add = \"\"\"
# ============================================================================
# MISSING PAGE ROUTES
# ============================================================================

@app.route('\''/tools'\'')
def tools():
    \"\"\"Tools landing page\"\"\"
    return render_template('\''tools.html'\'')

@app.route('\''/explorer'\'')
def explorer():
    \"\"\"Domain explorer page\"\"\"
    return render_template('\''explorer.html'\'')

@app.route('\''/visualtrace'\'')
def visualtrace():
    \"\"\"Visual traceroute page\"\"\"
    return render_template('\''visualtrace.html'\'')

@app.route('\''/autolookup'\'')
def autolookup():
    \"\"\"DNS auto-detect page\"\"\"
    return render_template('\''autolookup.html'\'')

@app.route('\''/api/remote-locations'\'')
def api_remote_locations():
    \"\"\"Remote traceroute locations\"\"\"
    locations = [
        {'\''id'\'': '\''us-east'\'', '\''name'\'': '\''US East (Virginia)'\'', '\''provider'\'': '\''AWS'\'', '\''lat'\'': 38.13, '\''lon'\'': -78.45},
        {'\''id'\'': '\''us-west'\'': '\''name'\'': '\''US West (California)'\'', '\''provider'\'': '\''AWS'\'', '\''lat'\'': 37.35, '\''lon'\'': -121.96},
        {'\''id'\'': '\''eu-west'\'', '\''name'\'': '\''Europe (Ireland)'\'', '\''provider'\'': '\''AWS'\'', '\''lat'\'': 53.33, '\''lon'\'': -6.25},
        {'\''id'\'': '\''ap-northeast'\'', '\''name'\'': '\''Asia (Tokyo)'\'', '\''provider'\'': '\''AWS'\'', '\''lat'\'': 35.68, '\''lon'\'': 139.69},
        {'\''id'\'': '\''ap-southeast'\'', '\''name'\'': '\''Oceania (Sydney)'\'', '\''provider'\'': '\''AWS'\'', '\''lat'\'': -33.86, '\''lon'\'': 151.21},
    ]
    return jsonify({'\''success'\'': True, '\''locations'\'': locations})

\"\"\"

# Check if routes already exist
if '\''/tools'\'' not in content or '\''def tools()'\'' not in content:
    # Find the position before if __name__
    lines = content.split('\''\\n'\'')
    insert_index = None
    for i, line in enumerate(lines):
        if line.strip().startswith(\"if __name__\"):
            insert_index = i
            break

    if insert_index:
        lines.insert(insert_index, routes_to_add)
        content = '\''\\n'\''.join(lines)

        with open(\"/var/www/dnsscience/app.py\", \"w\") as f:
            f.write(content)
        print(\"✓ Routes added to app.py\")
    else:
        print(\"❌ Could not find insertion point in app.py\")
else:
    print(\"✓ Routes already exist in app.py\")
PYTHON
",
"echo \"\"",
"echo \"Verifying Python syntax...\"",
"sudo python3 -m py_compile app.py && echo \"✓ Syntax OK\" || echo \"❌ Syntax error\"",
"sudo systemctl restart apache2 && echo \"✓ Apache restarted\""
]' \
  --query 'Command.CommandId' \
  --output text

echo ""
echo "Deployment complete! Testing pages..."
sleep 8

# Test pages
for url in "/" "/tools" "/explorer" "/visualtrace" "/health"; do
  echo -n "Testing https://www.dnsscience.io$url ... "
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://www.dnsscience.io$url")
  if [ "$status" = "200" ] || [ "$status" = "302" ]; then
    echo "✓ OK ($status)"
  else
    echo "❌ FAILED ($status)"
  fi
done

echo ""
echo "=========================================="
echo "Deployment complete!"
echo "=========================================="
