#!/usr/bin/env python3
"""
Visual Traceroute Fix and Enhancement Script
Fixes the visual traceroute feature and adds geolocation integration
"""

import subprocess
import json
import sys

def deploy_visual_traceroute_fix():
    """Deploy comprehensive visual traceroute fixes"""

    print("="*60)
    print("VISUAL TRACEROUTE FIX DEPLOYMENT")
    print("="*60)

    # Visual traceroute backend code
    visual_trace_code = '''
#!/usr/bin/env python3
"""Visual Traceroute Backend with Geolocation"""

import subprocess
import json
import re
import socket
from flask import Blueprint, request, jsonify
import requests
import redis
import time
from typing import List, Dict, Any, Optional

visual_trace_bp = Blueprint('visual_trace', __name__)
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

class VisualTraceroute:
    """Enhanced visual traceroute with geolocation"""

    def __init__(self):
        self.ipgeolocation_key = os.getenv('IPGEOLOCATION_API_KEY', '')
        self.cache_ttl = 86400  # 24 hours for geo data

    def get_geolocation(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get geolocation for IP address"""
        # Check cache
        cache_key = f"geo:{ip}"
        cached = redis_client.get(cache_key)
        if cached:
            return json.loads(cached)

        # Check for private IPs
        if self._is_private_ip(ip):
            return {
                'ip': ip,
                'country': 'Private Network',
                'city': 'Local',
                'latitude': 0,
                'longitude': 0,
                'isp': 'Private'
            }

        # Use free IP-API service as fallback
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    location = {
                        'ip': ip,
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'isp': data.get('isp', 'Unknown'),
                        'region': data.get('regionName', '')
                    }
                    # Cache result
                    redis_client.setex(cache_key, self.cache_ttl, json.dumps(location))
                    return location
        except:
            pass

        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255')
        ]

        try:
            ip_int = int(''.join([f'{int(x):08b}' for x in ip.split('.')]), 2)
            for start, end in private_ranges:
                start_int = int(''.join([f'{int(x):08b}' for x in start.split('.')]), 2)
                end_int = int(''.join([f'{int(x):08b}' for x in end.split('.')]), 2)
                if start_int <= ip_int <= end_int:
                    return True
        except:
            pass

        return False

    def run_traceroute(self, target: str, max_hops: int = 30) -> Dict[str, Any]:
        """Run traceroute and collect hop data with geolocation"""

        result = {
            'target': target,
            'timestamp': time.time(),
            'hops': [],
            'status': 'running'
        }

        try:
            # Resolve target to IP
            target_ip = socket.gethostbyname(target)
            result['target_ip'] = target_ip
        except:
            result['status'] = 'error'
            result['error'] = f'Failed to resolve {target}'
            return result

        # Run traceroute command
        cmd = ['traceroute', '-n', '-m', str(max_hops), '-w', '2', target]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            hop_pattern = re.compile(r'^\\s*(\\d+)\\s+(.+)$')
            ip_pattern = re.compile(r'(\\d+\\.\\d+\\.\\d+\\.\\d+)')
            time_pattern = re.compile(r'(\\d+\\.\\d+)\\s*ms')

            for line in process.stdout:
                match = hop_pattern.match(line)
                if match:
                    hop_num = int(match.group(1))
                    hop_data = match.group(2)

                    # Extract IPs and response times
                    ips = ip_pattern.findall(hop_data)
                    times = time_pattern.findall(hop_data)

                    hop_info = {
                        'hop': hop_num,
                        'ips': [],
                        'times': [float(t) for t in times],
                        'avg_time': sum(float(t) for t in times) / len(times) if times else None
                    }

                    # Get geolocation for each IP
                    for ip in set(ips):  # Use set to avoid duplicates
                        geo = self.get_geolocation(ip)
                        if geo:
                            hop_info['ips'].append({
                                'ip': ip,
                                'location': geo
                            })

                    # Handle timeout (*)
                    if not ips and '*' in hop_data:
                        hop_info['timeout'] = True

                    result['hops'].append(hop_info)

            process.wait()
            result['status'] = 'completed'

        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)

        return result

visual_trace = VisualTraceroute()

@visual_trace_bp.route('/api/traceroute', methods=['POST'])
def api_traceroute():
    """Run traceroute with geolocation"""
    data = request.json
    target = data.get('target')

    if not target:
        return jsonify({'error': 'Target required'}), 400

    # Check cache for recent results
    cache_key = f"traceroute:{target}"
    cached = redis_client.get(cache_key)
    if cached:
        return jsonify(json.loads(cached))

    # Run traceroute
    result = visual_trace.run_traceroute(target)

    # Cache successful results for 5 minutes
    if result.get('status') == 'completed':
        redis_client.setex(cache_key, 300, json.dumps(result))

    return jsonify(result)

@visual_trace_bp.route('/api/traceroute/stream', methods=['POST'])
def api_traceroute_stream():
    """Stream traceroute results in real-time"""
    from flask import Response

    data = request.json
    target = data.get('target')

    if not target:
        return jsonify({'error': 'Target required'}), 400

    def generate():
        """Generator for streaming response"""
        try:
            # Resolve target
            target_ip = socket.gethostbyname(target)
            yield f"data: {json.dumps({'type': 'start', 'target': target, 'ip': target_ip})}\\n\\n"

            # Run traceroute
            cmd = ['traceroute', '-n', '-m', '30', '-w', '2', target]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            hop_pattern = re.compile(r'^\\s*(\\d+)\\s+(.+)$')

            for line in process.stdout:
                match = hop_pattern.match(line)
                if match:
                    hop_data = {
                        'type': 'hop',
                        'hop': int(match.group(1)),
                        'raw': match.group(2)
                    }

                    # Extract IP if present
                    ip_match = re.search(r'(\\d+\\.\\d+\\.\\d+\\.\\d+)', match.group(2))
                    if ip_match:
                        ip = ip_match.group(1)
                        geo = visual_trace.get_geolocation(ip)
                        if geo:
                            hop_data['location'] = geo

                    yield f"data: {json.dumps(hop_data)}\\n\\n"

            process.wait()
            yield f"data: {json.dumps({'type': 'complete'})}\\n\\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\\n\\n"

    return Response(generate(), mimetype='text/event-stream')
'''

    # Visual traceroute frontend HTML
    visual_trace_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Visual Traceroute - DNS Science</title>
    <link rel="stylesheet" href="/static/css/main.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
    <style>
        #map {
            height: 500px;
            width: 100%;
            border-radius: 8px;
            margin: 20px 0;
        }
        .trace-form {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .trace-results {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .hop-item {
            padding: 10px;
            border-left: 3px solid #007bff;
            margin: 10px 0;
            background: #f8f9fa;
        }
        .hop-timeout {
            color: #dc3545;
            border-left-color: #dc3545;
        }
        .loading {
            text-align: center;
            padding: 40px;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #007bff;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Visual Traceroute</h1>

        <div class="trace-form">
            <h2>Trace Network Path</h2>
            <form id="traceForm">
                <div class="form-group">
                    <label for="target">Target Domain or IP:</label>
                    <input type="text" id="target" name="target"
                           placeholder="example.com or 8.8.8.8" required>
                </div>
                <button type="submit" class="btn btn-primary">Start Traceroute</button>
            </form>
        </div>

        <div id="mapContainer" style="display:none;">
            <h2>Network Path Visualization</h2>
            <div id="map"></div>
        </div>

        <div id="results" class="trace-results" style="display:none;">
            <h2>Traceroute Results</h2>
            <div id="resultsContent"></div>
        </div>

        <div id="loading" class="loading" style="display:none;">
            <div class="spinner"></div>
            <p>Running traceroute...</p>
        </div>
    </div>

    <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
    <script>
        let map = null;
        let markers = [];
        let polyline = null;

        document.getElementById('traceForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const target = document.getElementById('target').value;

            // Show loading
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            document.getElementById('mapContainer').style.display = 'none';

            // Clear previous results
            if (map) {
                markers.forEach(m => map.removeLayer(m));
                markers = [];
                if (polyline) map.removeLayer(polyline);
            }

            try {
                const response = await fetch('/api/traceroute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                });

                const data = await response.json();

                // Hide loading
                document.getElementById('loading').style.display = 'none';

                if (data.status === 'completed') {
                    displayResults(data);
                    displayMap(data);
                } else {
                    alert('Traceroute failed: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                document.getElementById('loading').style.display = 'none';
                alert('Error: ' + error.message);
            }
        });

        function displayResults(data) {
            const resultsDiv = document.getElementById('resultsContent');
            resultsDiv.innerHTML = '';

            resultsDiv.innerHTML = `
                <p><strong>Target:</strong> ${data.target} (${data.target_ip || 'N/A'})</p>
                <h3>Hops:</h3>
            `;

            data.hops.forEach(hop => {
                const hopDiv = document.createElement('div');
                hopDiv.className = hop.timeout ? 'hop-item hop-timeout' : 'hop-item';

                if (hop.timeout) {
                    hopDiv.innerHTML = `<strong>Hop ${hop.hop}:</strong> * * * (Timeout)`;
                } else {
                    let hopInfo = `<strong>Hop ${hop.hop}:</strong> `;

                    if (hop.ips && hop.ips.length > 0) {
                        hop.ips.forEach(ipInfo => {
                            const loc = ipInfo.location;
                            hopInfo += `${ipInfo.ip} (${loc.city}, ${loc.country}) `;
                        });
                    }

                    if (hop.avg_time !== null) {
                        hopInfo += `- ${hop.avg_time.toFixed(2)}ms`;
                    }

                    hopDiv.innerHTML = hopInfo;
                }

                resultsDiv.appendChild(hopDiv);
            });

            document.getElementById('results').style.display = 'block';
        }

        function displayMap(data) {
            document.getElementById('mapContainer').style.display = 'block';

            if (!map) {
                map = L.map('map').setView([20, 0], 2);
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap contributors'
                }).addTo(map);
            }

            const coords = [];

            data.hops.forEach((hop, index) => {
                if (hop.ips && hop.ips.length > 0) {
                    hop.ips.forEach(ipInfo => {
                        const loc = ipInfo.location;
                        if (loc && loc.latitude && loc.longitude) {
                            const marker = L.marker([loc.latitude, loc.longitude])
                                .addTo(map)
                                .bindPopup(`
                                    <strong>Hop ${hop.hop}</strong><br>
                                    IP: ${ipInfo.ip}<br>
                                    Location: ${loc.city}, ${loc.country}<br>
                                    ISP: ${loc.isp || 'Unknown'}<br>
                                    ${hop.avg_time ? `Response: ${hop.avg_time.toFixed(2)}ms` : ''}
                                `);

                            markers.push(marker);
                            coords.push([loc.latitude, loc.longitude]);
                        }
                    });
                }
            });

            // Draw path
            if (coords.length > 1) {
                polyline = L.polyline(coords, {
                    color: 'blue',
                    weight: 3,
                    opacity: 0.7
                }).addTo(map);

                // Fit map to show all markers
                const bounds = L.latLngBounds(coords);
                map.fitBounds(bounds, {padding: [50, 50]});
            }
        }
    </script>
</body>
</html>
'''

    # Create deployment commands
    commands = [
        # Save visual trace module
        f"echo '{visual_trace_code}' | sudo tee /var/www/dnsscience/visual_traceroute.py",

        # Update app.py to include visual trace
        """sudo cat >> /var/www/dnsscience/app.py << 'EOF'

# Import visual traceroute
try:
    from visual_traceroute import visual_trace_bp
    app.register_blueprint(visual_trace_bp)
    print("Visual traceroute loaded successfully")
except Exception as e:
    print(f"Failed to load visual traceroute: {e}")

EOF""",

        # Save HTML template
        f"echo '{visual_trace_html}' | sudo tee /var/www/dnsscience/templates/visualtrace.html",

        # Set permissions
        "sudo chown -R apache:apache /var/www/dnsscience/",
        "sudo chmod 755 /var/www/dnsscience/*.py",

        # Restart Apache
        "sudo systemctl restart httpd",

        # Test the endpoint
        "curl -s http://localhost/visualtrace | grep -q 'Visual Traceroute' && echo 'Visual traceroute page loads successfully' || echo 'Failed to load visual traceroute page'"
    ]

    print("\nDeployment commands generated. To deploy:")
    print("1. SSH to the instance")
    print("2. Run each command in sequence")
    print("\nOr use the deployment script: deploy_comprehensive_stabilization.sh")

    return commands

if __name__ == "__main__":
    commands = deploy_visual_traceroute_fix()

    # Save to deployment script
    with open('deploy_visual_traceroute.sh', 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# Visual Traceroute Deployment\n\n")
        for cmd in commands:
            f.write(f"{cmd}\n\n")

    print("\nDeployment script saved to: deploy_visual_traceroute.sh")
    print("Make it executable: chmod +x deploy_visual_traceroute.sh")