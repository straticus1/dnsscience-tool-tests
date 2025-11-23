"""
Visual Traceroute API
Backend for visual traceroute tool with map visualization
"""

import subprocess
import re
import json
import requests
from flask import Blueprint, request, jsonify
import socket
import time

visual_trace_bp = Blueprint('visual_trace', __name__)

# GeoIP lookup using ipinfo.io (free tier allows 50k requests/month)
def geolocate_ip(ip):
    """Get geographic location for an IP address"""
    if not ip or ip == '*':
        return None

    try:
        # Use ipinfo.io free tier (no auth required for limited requests)
        response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'loc' in data:
                lat, lon = data['loc'].split(',')
                return {
                    'ip': ip,
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', ''),
                    'country': data.get('country', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'lat': float(lat),
                    'lon': float(lon),
                    'hostname': data.get('hostname', ip)
                }
    except Exception as e:
        print(f"GeoIP lookup failed for {ip}: {e}")

    # Fallback: return IP without location
    return {
        'ip': ip,
        'city': 'Unknown',
        'region': '',
        'country': 'Unknown',
        'org': 'Unknown',
        'lat': None,
        'lon': None,
        'hostname': ip
    }

def parse_traceroute_output(output):
    """Parse traceroute output into structured hop data"""
    hops = []
    lines = output.split('\n')

    for line in lines:
        # Skip empty lines and headers
        if not line.strip() or 'traceroute to' in line.lower():
            continue

        # Match traceroute lines like: " 1  192.168.1.1 (192.168.1.1)  1.234 ms"
        # or: " 2  * * *"
        hop_match = re.match(r'\s*(\d+)\s+(.+)', line)
        if hop_match:
            hop_num = int(hop_match.group(1))
            hop_data = hop_match.group(2).strip()

            # Check for timeout
            if '*' in hop_data and hop_data.count('*') >= 2:
                hops.append({
                    'hop': hop_num,
                    'ip': None,
                    'hostname': 'Timeout',
                    'latency': None,
                    'location': None
                })
                continue

            # Extract IP and hostname
            ip_match = re.search(r'\(?([\d\.]+)\)?', hop_data)
            hostname_match = re.search(r'^([^\s\(]+)', hop_data)
            latency_match = re.search(r'([\d\.]+)\s*ms', hop_data)

            ip = ip_match.group(1) if ip_match else None
            hostname = hostname_match.group(1) if hostname_match else ip
            latency = float(latency_match.group(1)) if latency_match else None

            if ip:
                hops.append({
                    'hop': hop_num,
                    'ip': ip,
                    'hostname': hostname if hostname != ip else None,
                    'latency': latency,
                    'location': None  # Will be filled by geolocate
                })

    return hops

def run_local_traceroute(target, max_hops=30):
    """Execute local traceroute command"""
    try:
        # Resolve domain to IP if needed
        try:
            target_ip = socket.gethostbyname(target)
        except:
            target_ip = target

        # Run traceroute (use -I for ICMP, -n for no DNS resolution to speed up)
        # Note: May require sudo on some systems
        cmd = ['traceroute', '-m', str(max_hops), '-w', '2', target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            # Try without sudo
            return result.stdout if result.stdout else result.stderr

        return result.stdout
    except subprocess.TimeoutExpired:
        return "Traceroute timed out"
    except Exception as e:
        return f"Error running traceroute: {e}"

def get_remote_traceroute_locations():
    """Get list of available remote traceroute locations"""
    # This would integrate with looking glass servers or traceroute APIs
    # For now, return a curated list of known public looking glass servers
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

    return locations

@visual_trace_bp.route('/api/traceroute', methods=['POST'])
def api_traceroute():
    """Run traceroute and return geolocated hops"""
    data = request.get_json()
    target = data.get('target')
    source = data.get('source', 'local')
    max_hops = data.get('max_hops', 30)

    if not target:
        return jsonify({'error': 'Target required'}), 400

    # Validate target (basic)
    if not re.match(r'^[a-zA-Z0-9\.\-]+$', target):
        return jsonify({'error': 'Invalid target format'}), 400

    # Run traceroute
    if source == 'local':
        output = run_local_traceroute(target, max_hops)
    else:
        # TODO: Implement remote traceroute via looking glass APIs
        return jsonify({'error': 'Remote traceroute not yet implemented'}), 501

    # Parse output
    hops = parse_traceroute_output(output)

    # Geolocate each hop (with rate limiting consideration)
    for hop in hops:
        if hop['ip']:
            location = geolocate_ip(hop['ip'])
            hop['location'] = location
            # Small delay to avoid rate limiting
            time.sleep(0.1)

    # Calculate statistics
    valid_hops = [h for h in hops if h['ip']]
    countries = set([h['location']['country'] for h in valid_hops if h.get('location')])
    total_latency = sum([h['latency'] for h in valid_hops if h.get('latency')]) or 0

    return jsonify({
        'success': True,
        'target': target,
        'source': source,
        'hops': hops,
        'stats': {
            'total_hops': len(hops),
            'valid_hops': len(valid_hops),
            'countries_traversed': len(countries),
            'total_latency_ms': round(total_latency, 2)
        }
    })

@visual_trace_bp.route('/api/remote-locations', methods=['GET'])
def api_remote_locations():
    """Get available remote traceroute locations"""
    locations = get_remote_traceroute_locations()
    return jsonify({
        'success': True,
        'locations': locations
    })

@visual_trace_bp.route('/api/dns-path', methods=['POST'])
def api_dns_path():
    """Trace DNS resolution path through resolvers"""
    data = request.get_json()
    domain = data.get('domain')

    if not domain:
        return jsonify({'error': 'Domain required'}), 400

    # This would trace:
    # Client -> Recursive Resolver -> Root Server -> TLD Server -> Authoritative NS
    # For now, return a simplified path

    return jsonify({
        'success': True,
        'message': 'DNS path tracing coming soon',
        'path': []
    })

# Helper function to load DNS resolvers from file
def load_dns_resolvers():
    """Load DNS resolvers from JSON file"""
    try:
        with open('/Users/ryan/development/dnsscience-tool-tests/dns_resolvers.json', 'r') as f:
            data = json.load(f)
            return data.get('resolvers', [])
    except Exception as e:
        print(f"Error loading DNS resolvers: {e}")
        return []

@visual_trace_bp.route('/api/dns-resolvers', methods=['GET'])
def api_dns_resolvers():
    """Get DNS resolver locations for map display"""
    resolvers = load_dns_resolvers()

    # Add basic geocoding for resolvers (many already have location data)
    # Filter to reduce payload size - only return unique locations
    unique_locations = {}

    for resolver in resolvers:
        key = f"{resolver.get('city', 'Unknown')}-{resolver.get('country_code', 'XX')}"
        if key not in unique_locations:
            unique_locations[key] = {
                'provider': resolver.get('provider', 'Unknown'),
                'city': resolver.get('city', 'Unknown'),
                'country': resolver.get('country', 'Unknown'),
                'country_code': resolver.get('country_code', 'XX'),
                'tier': resolver.get('tier', 'tier2'),
                'ip': resolver.get('ip', ''),
                # Note: We'll need to add lat/lon to the JSON file
                # For now, return what we have
            }

    return jsonify({
        'success': True,
        'resolvers': list(unique_locations.values()),
        'total': len(unique_locations)
    })
