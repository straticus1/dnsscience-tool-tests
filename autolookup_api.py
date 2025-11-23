"""
DNS Auto Lookup API Endpoints
Provides real-time detection of IP, DNS resolver, EDNS, and security settings
"""

from flask import Blueprint, request, jsonify
import socket
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import ipaddress
import re
from typing import Dict, Any, Optional, Tuple

# Create Blueprint
autolookup_bp = Blueprint('autolookup', __name__)

# Known DNS resolver providers
KNOWN_RESOLVERS = {
    # Google Public DNS
    '8.8.8.8': 'Google Public DNS',
    '8.8.4.4': 'Google Public DNS',
    '2001:4860:4860::8888': 'Google Public DNS',
    '2001:4860:4860::8844': 'Google Public DNS',

    # Cloudflare DNS
    '1.1.1.1': 'Cloudflare DNS',
    '1.0.0.1': 'Cloudflare DNS',
    '2606:4700:4700::1111': 'Cloudflare DNS',
    '2606:4700:4700::1001': 'Cloudflare DNS',

    # Quad9
    '9.9.9.9': 'Quad9',
    '149.112.112.112': 'Quad9',
    '2620:fe::fe': 'Quad9',

    # OpenDNS
    '208.67.222.222': 'OpenDNS',
    '208.67.220.220': 'OpenDNS',
    '2620:119:35::35': 'OpenDNS',
    '2620:119:53::53': 'OpenDNS',

    # Level3
    '4.2.2.1': 'Level3',
    '4.2.2.2': 'Level3',
    '4.2.2.3': 'Level3',
    '4.2.2.4': 'Level3',
}

def get_client_ip() -> Tuple[Optional[str], Optional[str]]:
    """
    Extract client IP from request headers.
    Returns tuple of (ipv4, ipv6)
    """
    # Check various headers in order of preference
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    real_ip = request.headers.get('X-Real-IP', '')
    remote_addr = request.remote_addr

    # Parse X-Forwarded-For (may contain multiple IPs)
    ip_address = None
    if forwarded_for:
        ip_address = forwarded_for.split(',')[0].strip()
    elif real_ip:
        ip_address = real_ip
    else:
        ip_address = remote_addr

    # Determine if IPv4 or IPv6
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return (ip_address, None)
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return (None, ip_address)
    except ValueError:
        pass

    return (ip_address, None)

def identify_resolver(resolver_ip: str) -> str:
    """Identify the DNS resolver provider from IP address"""
    return KNOWN_RESOLVERS.get(resolver_ip, 'Unknown Provider')

def get_system_resolvers() -> list:
    """Get system configured DNS resolvers"""
    try:
        resolver = dns.resolver.Resolver()
        return resolver.nameservers
    except Exception as e:
        print(f"Error getting system resolvers: {e}")
        return []

def query_edns_subnet(domain: str = 'o-o.myaddr.l.google.com') -> Optional[str]:
    """
    Query special DNS records that echo back EDNS Client Subnet.
    Google's o-o.myaddr.l.google.com returns the client subnet in TXT record.
    """
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'TXT')

        for rdata in answers:
            text = rdata.to_text().strip('"')
            # Parse the response which contains IP or subnet
            if '/' in text or ':' in text or '.' in text:
                return text

        return None
    except Exception as e:
        print(f"Error querying EDNS subnet: {e}")
        return None

def check_dnssec_validation() -> bool:
    """
    Check if the resolver supports DNSSEC validation.
    Tests with a known DNSSEC-signed domain.
    """
    try:
        resolver = dns.resolver.Resolver()
        # Query a DNSSEC-signed domain
        answers = resolver.resolve('dnssec-failed.org', 'A')
        # If we get here, DNSSEC validation might not be working
        # (this domain should fail DNSSEC validation)
        return False
    except dns.resolver.NXDOMAIN:
        # Domain doesn't exist, but that's okay for this test
        return True
    except dns.exception.DNSException:
        # DNS error might indicate DNSSEC validation is working
        return True
    except Exception:
        return False

def check_resolver_supports_feature(resolver_ip: str, feature: str) -> Optional[bool]:
    """
    Check if a resolver supports DoH or DoT.
    Returns True, False, or None (unknown)
    """
    # Known resolvers with DoH/DoT support
    doh_providers = {
        '8.8.8.8', '8.8.4.4',  # Google
        '1.1.1.1', '1.0.0.1',  # Cloudflare
        '9.9.9.9', '149.112.112.112',  # Quad9
        '208.67.222.222', '208.67.220.220',  # OpenDNS
    }

    dot_providers = {
        '8.8.8.8', '8.8.4.4',  # Google
        '1.1.1.1', '1.0.0.1',  # Cloudflare
        '9.9.9.9', '149.112.112.112',  # Quad9
    }

    if feature == 'doh':
        if resolver_ip in doh_providers:
            return True
        elif resolver_ip in KNOWN_RESOLVERS:
            return False
        else:
            return None
    elif feature == 'dot':
        if resolver_ip in dot_providers:
            return True
        elif resolver_ip in KNOWN_RESOLVERS:
            return False
        else:
            return None

    return None

def calculate_security_score(dnssec: bool, doh: Optional[bool], dot: Optional[bool]) -> int:
    """Calculate overall security score (0-100)"""
    score = 0

    # DNSSEC: 40 points
    if dnssec:
        score += 40

    # DoH: 30 points
    if doh is True:
        score += 30
    elif doh is None:
        score += 15  # Unknown, give partial credit

    # DoT: 30 points
    if dot is True:
        score += 30
    elif dot is None:
        score += 15  # Unknown, give partial credit

    return score

# ========== API ENDPOINTS ==========

@autolookup_bp.route('/api/autolookup/ip', methods=['GET'])
def api_get_ip():
    """
    Get client IP address (IPv4 and IPv6 if available)

    Returns:
        {
            "ipv4": "1.2.3.4" or null,
            "ipv6": "2001:db8::1" or null,
            "source": "X-Forwarded-For|X-Real-IP|remote_addr"
        }
    """
    try:
        ipv4, ipv6 = get_client_ip()

        # Determine source
        source = "remote_addr"
        if request.headers.get('X-Forwarded-For'):
            source = "X-Forwarded-For"
        elif request.headers.get('X-Real-IP'):
            source = "X-Real-IP"

        return jsonify({
            'ipv4': ipv4,
            'ipv6': ipv6,
            'source': source,
            'success': True
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

@autolookup_bp.route('/api/autolookup/resolver', methods=['GET'])
def api_get_resolver():
    """
    Detect DNS resolver being used

    Returns:
        {
            "resolver_ip": "8.8.8.8",
            "provider": "Google Public DNS",
            "resolvers": ["8.8.8.8", "8.8.4.4"]
        }
    """
    try:
        resolvers = get_system_resolvers()

        if not resolvers:
            return jsonify({
                'error': 'No DNS resolvers detected',
                'success': False
            }), 404

        # Use first resolver as primary
        primary_resolver = resolvers[0]
        provider = identify_resolver(primary_resolver)

        return jsonify({
            'resolver_ip': primary_resolver,
            'provider': provider,
            'resolvers': resolvers,
            'count': len(resolvers),
            'success': True
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

@autolookup_bp.route('/api/autolookup/edns', methods=['GET'])
def api_get_edns():
    """
    Detect EDNS Client Subnet information

    Returns:
        {
            "enabled": true/false,
            "subnet": "1.2.3.0/24" or null,
            "privacy_impact": "Low|Medium|High"
        }
    """
    try:
        # Query Google's special domain that echoes back ECS
        subnet = query_edns_subnet()

        enabled = subnet is not None

        # Assess privacy impact
        privacy_impact = "Low"
        if subnet:
            # If full IP is exposed (no subnet mask or /32), privacy impact is high
            if '/' not in subnet:
                privacy_impact = "High"
            elif subnet.endswith('/32') or subnet.endswith('/128'):
                privacy_impact = "High"
            elif subnet.endswith('/24') or subnet.endswith('/64'):
                privacy_impact = "Medium"

        return jsonify({
            'enabled': enabled,
            'subnet': subnet,
            'privacy_impact': privacy_impact,
            'success': True
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

@autolookup_bp.route('/api/autolookup/security', methods=['GET'])
def api_get_security():
    """
    Assess DNS security configuration

    Returns:
        {
            "dnssec": true/false,
            "doh": true/false/null,
            "dot": true/false/null,
            "score": 0-100
        }
    """
    try:
        # Check DNSSEC
        dnssec_enabled = check_dnssec_validation()

        # Get resolver info
        resolvers = get_system_resolvers()
        primary_resolver = resolvers[0] if resolvers else None

        # Check DoH and DoT support
        doh_available = None
        dot_available = None

        if primary_resolver:
            doh_available = check_resolver_supports_feature(primary_resolver, 'doh')
            dot_available = check_resolver_supports_feature(primary_resolver, 'dot')

        # Calculate security score
        score = calculate_security_score(dnssec_enabled, doh_available, dot_available)

        return jsonify({
            'dnssec': dnssec_enabled,
            'doh': doh_available,
            'dot': dot_available,
            'score': score,
            'resolver': primary_resolver,
            'success': True
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

@autolookup_bp.route('/api/autolookup/all', methods=['GET'])
def api_get_all():
    """
    Get all diagnostic information in one request

    Returns combined data from all endpoints
    """
    try:
        # Get IP
        ipv4, ipv6 = get_client_ip()

        # Get resolvers
        resolvers = get_system_resolvers()
        primary_resolver = resolvers[0] if resolvers else None
        provider = identify_resolver(primary_resolver) if primary_resolver else "Unknown"

        # Get EDNS
        subnet = query_edns_subnet()
        edns_enabled = subnet is not None

        # Get security
        dnssec_enabled = check_dnssec_validation()
        doh_available = check_resolver_supports_feature(primary_resolver, 'doh') if primary_resolver else None
        dot_available = check_resolver_supports_feature(primary_resolver, 'dot') if primary_resolver else None
        score = calculate_security_score(dnssec_enabled, doh_available, dot_available)

        return jsonify({
            'ip': {
                'ipv4': ipv4,
                'ipv6': ipv6
            },
            'resolver': {
                'ip': primary_resolver,
                'provider': provider,
                'all_resolvers': resolvers
            },
            'edns': {
                'enabled': edns_enabled,
                'subnet': subnet
            },
            'security': {
                'dnssec': dnssec_enabled,
                'doh': doh_available,
                'dot': dot_available,
                'score': score
            },
            'success': True
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

# ========== FLASK ROUTE FOR HTML PAGE ==========

def register_autolookup_routes(app):
    """
    Register autolookup routes with Flask app.
    Call this from your main app.py
    """
    from flask import render_template

    # Register API blueprint
    app.register_blueprint(autolookup_bp)

    # Register HTML route
    @app.route('/autolookup')
    def autolookup_page():
        return render_template('autolookup.html')

# ========== USAGE IN app.py ==========
"""
To integrate this into your main Flask app, add to app.py:

from autolookup_api import register_autolookup_routes

# After creating your Flask app
app = Flask(__name__)

# Register autolookup routes
register_autolookup_routes(app)
"""
