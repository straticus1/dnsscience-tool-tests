"""DNS Science Tracker - Flask Application"""
from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect
import json
import os
import logging
import psycopg2
import psycopg2.extras
from werkzeug.utils import secure_filename
from database import Database
from checkers import DomainScanner
# from async_scanner import get_async_scanner  # Disabled - using synchronous scanning
from browser import DataBrowser
from custom_scanners import CustomScannerManager
from search import AdvancedSearch
from domain_valuation import DomainValuationEngine
from dns_config_validator import (
    DNSConfigValidator,
    DNSCacheInspector,
    DNSSECValidator,
    ZoneTransferChecker,
    DomainHijackingValidator
)
from auth import UserAuth, PasswordHasher, login_required, optional_auth
from api_key_manager import APIKeyManager
from flask import g
import time

from certificate_tools import (
    CertificateChainResolver,
    CertificateRevocationValidator,
    CertificateExpiryValidator,
    CertificateConverter,
    JKSManager,
    OpenSSLCommandBuilder
)

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'  # TODO: Move to config

# Initialize SocketIO for WebSockets
from flask_socketio import SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize GraphQL
from flask_graphql import GraphQLView
from graphql_schema import schema

# Initialize WebSocket manager
from websocket_server import register_websocket_handlers, WebSocketManager
register_websocket_handlers(socketio)
ws_manager = WebSocketManager(socketio)

# Configure file uploads
UPLOAD_FOLDER = '/tmp/dnsscience_uploads'
ALLOWED_EXTENSIONS = {'conf', 'txt', 'zip', 'pem', 'crt', 'key', 'cer', 'jks', 'p12', 'pfx', 'keystore'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max file size for large DNS installations

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = Database()

# Initialize authentication system
user_auth = UserAuth(db)
api_key_manager = APIKeyManager(db)
scanner = DomainScanner()
browser = DataBrowser()
scanner_manager = CustomScannerManager()
search_manager = AdvancedSearch()
valuation_engine = DomainValuationEngine()
config_validator = DNSConfigValidator()
cache_inspector = DNSCacheInspector()
dnssec_validator = DNSSECValidator()
zone_checker = ZoneTransferChecker()
hijack_validator = DomainHijackingValidator()
cert_chain_resolver = CertificateChainResolver()
cert_revocation_validator = CertificateRevocationValidator()
cert_expiry_validator = CertificateExpiryValidator()
cert_converter = CertificateConverter()
jks_manager = JKSManager()
openssl_cmd_builder = OpenSSLCommandBuilder()


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def require_premium(f):
    """Decorator to require premium membership for certain features"""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # TODO: Implement actual premium membership check
        # For now, check if user is authenticated
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        # TODO: Check if user has premium subscription
        # if not user.has_premium_subscription():
        #     return jsonify({'error': 'Premium subscription required'}), 403

        return f(*args, **kwargs)
    return decorated_function




@app.before_request
def load_auth():
    """Make auth available in Flask g for all requests"""
    g.auth = user_auth
    g.api_key_manager = api_key_manager


@app.route('/')
def index():
    """Serve the main web interface"""
    # Check if subdomain is registrar and redirect
    if request.host.startswith('registrar.'):
        return redirect('/registrar', code=302)

    # Cache busting for static assets
    static_dir = os.path.join(app.root_path, 'static')
    cache_bust = {
        'css': {},
        'js': {}
    }

    # Get modification times for cache busting
    try:
        css_file = os.path.join(static_dir, 'css', 'live-stats.css')
        if os.path.exists(css_file):
            cache_bust['css']['live_stats'] = int(os.path.getmtime(css_file))
        else:
            cache_bust['css']['live_stats'] = int(time.time())

        for js_file in ['live-stats.js', 'threat-feed.js']:
            js_path = os.path.join(static_dir, 'js', js_file)
            if os.path.exists(js_path):
                cache_bust['js'][js_file.replace('.js', '').replace('-', '_')] = int(os.path.getmtime(js_path))
            else:
                cache_bust['js'][js_file.replace('.js', '').replace('-', '_')] = int(time.time())
    except:
        # Fallback to timestamp
        cache_bust = {
            'css': {'live_stats': int(time.time())},
            'js': {'live_stats': int(time.time()), 'threat_feed': int(time.time())}
        }

    return render_template('index.php', cache_bust=cache_bust)


@app.route('/health')
def health():
    """Health check endpoint for load balancer"""
    return jsonify({'status': 'healthy'}), 200


@app.route('/tools')
def tools_page():
    """DNS Tools page with certificate chain resolver, DNS comparison, etc."""
    return render_template('tools.html')


# GraphQL endpoint
app.add_url_rule(
    '/graphql',
    view_func=GraphQLView.as_view(
        'graphql',
        schema=schema,
        graphiql=True  # Enable GraphiQL interface for development
    )
)


@app.route('/realtime')
def realtime_page():
    """Real-time monitoring demo page with WebSockets"""
    return render_template('realtime.html')


@app.route('/api/tools/cert-chain')
def api_cert_chain():
    """API endpoint for certificate chain resolution"""
    domain = request.args.get('domain')
    port = int(request.args.get('port', 443))

    if not domain:
        return jsonify({'error': 'Domain parameter required'}), 400

    try:
        import ssl
        import socket
        from datetime import datetime

        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()

                chain = []

                # Parse certificate details
                subject = dict(x[0] for x in cert_dict['subject'])
                issuer = dict(x[0] for x in cert_dict['issuer'])

                chain.append({
                    'subject': subject.get('commonName', 'Unknown'),
                    'issuer': issuer.get('commonName', 'Unknown'),
                    'valid_from': cert_dict['notBefore'],
                    'valid_until': cert_dict['notAfter'],
                    'serial': cert_dict.get('serialNumber', 'Unknown'),
                    'san': cert_dict.get('subjectAltName', [])
                })

                return jsonify({'chain': chain, 'success': True})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/tools/dns-compare', methods=['POST'])
def api_dns_compare():
    """API endpoint for DNS comparison between two servers"""
    data = request.get_json()
    domain = data.get('domain')
    old_server = data.get('old_server')
    new_server = data.get('new_server')

    if not all([domain, old_server, new_server]):
        return jsonify({'error': 'Missing required parameters'}), 400

    try:
        import dns.resolver

        def query_server(nameserver, domain_name):
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [nameserver]
            resolver.timeout = 5
            resolver.lifetime = 5

            records = {}
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']

            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain_name, rtype)
                    records[rtype] = [str(rdata) for rdata in answers]
                except:
                    pass

            return records

        old_records = query_server(old_server, domain)
        new_records = query_server(new_server, domain)

        # Compare records
        missing = []
        extra = []
        matching = []

        for rtype in set(list(old_records.keys()) + list(new_records.keys())):
            old_vals = set(old_records.get(rtype, []))
            new_vals = set(new_records.get(rtype, []))

            for val in old_vals - new_vals:
                missing.append({'name': domain, 'type': rtype, 'value': val})

            for val in new_vals - old_vals:
                extra.append({'name': domain, 'type': rtype, 'value': val})

            for val in old_vals & new_vals:
                matching.append({'name': domain, 'type': rtype, 'value': val})

        status = 'pass' if len(missing) == 0 else 'fail'

        return jsonify({
            'status': status,
            'missing_records': missing,
            'extra_records': extra,
            'matching_records': matching
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/tools/propagation')
def api_propagation_check():
    """API endpoint for global DNS propagation checking"""
    domain = request.args.get('domain')
    record_type = request.args.get('type', 'A')

    if not domain:
        return jsonify({'error': 'Domain parameter required'}), 400

    try:
        import dns.resolver

        # Major public DNS servers worldwide
        servers = [
            {'name': 'Google (US)', 'ip': '8.8.8.8'},
            {'name': 'Cloudflare (Global)', 'ip': '1.1.1.1'},
            {'name': 'Quad9 (Global)', 'ip': '9.9.9.9'},
            {'name': 'OpenDNS (US)', 'ip': '208.67.222.222'},
            {'name': 'Level3 (US)', 'ip': '4.2.2.2'},
            {'name': 'Comodo (Global)', 'ip': '8.26.56.26'},
        ]

        results = []

        for server in servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server['ip']]
                resolver.timeout = 3
                resolver.lifetime = 3

                answers = resolver.resolve(domain, record_type)
                value = ', '.join([str(rdata) for rdata in answers])

                results.append({
                    'location': server['name'],
                    'success': True,
                    'value': value
                })
            except:
                results.append({
                    'location': server['name'],
                    'success': False,
                    'value': None
                })

        return jsonify({'results': results})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/tools/dnssec-validate')
def api_dnssec_validate():
    """API endpoint for DNSSEC validation"""
    domain = request.args.get('domain')

    if not domain:
        return jsonify({'error': 'Domain parameter required'}), 400

    try:
        import dns.resolver
        import dns.dnssec

        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)

        try:
            # Try to get DNSKEY records
            dnskey = resolver.resolve(domain, 'DNSKEY')
            enabled = True

            # Basic DNSSEC validation
            try:
                answers = resolver.resolve(domain, 'A')
                valid = True
                details = "DNSSEC signatures verified"
            except:
                valid = False
                details = "DNSSEC validation failed"

        except dns.resolver.NoAnswer:
            enabled = False
            valid = False
            details = "DNSSEC not enabled for this domain"

        return jsonify({
            'enabled': enabled,
            'valid': valid,
            'details': details
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan', methods=['POST'])
def scan_domain():
    """
    Scan a domain (synchronous).
    POST /api/scan
    Body: {
        "domain": "example.com",
        "check_ssl": true,
        "advanced": false,
        "expert": false,
        "options": {
            "dns": ["records", "dnssec", "propagation"],
            "security": ["ssl", "ssl-chain", "cert-transparency"],
            "email": ["spf", "dkim", "dmarc", "mx-health"],
            "intel": ["whois", "reputation", "threat"]
        }
    }

    Returns: scan results immediately
    """
    data = request.get_json()

    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain is required'}), 400

    domain = data['domain'].strip().lower()
    check_ssl = data.get('check_ssl', True)
    advanced = data.get('advanced', False)
    expert = data.get('expert', False)
    expert_options = data.get('options', {})

    if not domain:
        return jsonify({'error': 'Invalid domain'}), 400

    # Check authentication and rate limits
    user_id = session.get('user_id')
    api_key_id = None
    
    # Check API key authentication
    api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
    if api_key:
        user_id, api_key_id, auth_error = user_auth.verify_api_key(api_key)
        if auth_error:
            return jsonify({'error': auth_error}), 401
    
    # Check rate limits
    allowed, remaining, limit_type = user_auth.check_rate_limit(user_id)
    if not allowed:
        return jsonify({
            'error': 'Rate limit exceeded',
            'limit_type': limit_type,
            'scans_remaining': remaining,
            'upgrade_url': '/pricing' if not user_id else '/account/upgrade'
        }), 429
    
    try:
        # Track scan status in session
        if 'scan_status' not in session:
            session['scan_status'] = {}
        session['scan_status'][domain] = 'scanning'
        session.modified = True

        # Record scan start time
        scan_start = time.time()

        # Perform synchronous scan
        scan_result = scanner.scan_domain(domain, check_ssl=check_ssl)

        # Calculate scan duration
        scan_duration_ms = int((time.time() - scan_start) * 1000)

        # Save to database
        db.save_scan_result(domain, scan_result)

        # Get domain_id for tracking
        domain_id = db.get_domain_id(domain)

        # Save SSL certificates if present
        if 'ssl_certificates' in scan_result and scan_result['ssl_certificates']:
            db.save_certificates_batch(domain, scan_result['ssl_certificates'])

        # Record scan for user (authenticated or anonymous)
        try:
            user_auth.record_scan(
                user_id=user_id,
                domain_id=domain_id,
                scan_duration_ms=scan_duration_ms,
                scan_source='api' if api_key_id else 'web',
                api_key_id=api_key_id
            )
        except Exception as e:
            # Don't fail the scan if tracking fails
            print(f"Warning: Failed to record scan: {e}")

        # Track user's scan in session (for anonymous users)
        if not user_id:
            if 'my_scans' not in session:
                session['my_scans'] = []
            if domain not in session['my_scans']:
                session['my_scans'].append(domain)

        # Update scan status to completed
        session['scan_status'][domain] = 'completed'
        session.modified = True

        # Add rate limit info to response
        scan_result['rate_limit'] = {
            'scans_remaining': remaining - 1,
            'limit_type': limit_type
        }

        return jsonify(scan_result)
    except Exception as e:
        # Mark scan as failed in session
        if 'scan_status' not in session:
            session['scan_status'] = {}
        session['scan_status'][domain] = 'failed'
        session.modified = True
        return jsonify({'error': str(e), 'domain': domain}), 500


@app.route('/api/scan/status/<job_id>', methods=['GET'])
def get_scan_status(job_id):
    """
    Get status of a scan job.
    GET /api/scan/status/<job_id>

    Returns:
        {
            "job_id": "uuid",
            "domain": "example.com",
            "status": "queued|processing|completed|failed",
            "result": {...} (if completed)
        }
    """
    async_scanner = get_async_scanner()
    status = async_scanner.get_job_status(job_id)

    if 'error' in status:
        return jsonify(status), 404

    return jsonify(status)


@app.route('/api/domain/<domain>', methods=['GET'])
def get_domain_latest(domain):
    """
    Get the latest scan result for a domain.
    GET /api/domain/<domain>
    """
    try:
        result = db.get_latest_scan(domain)

        if not result:
            return jsonify({'error': 'Domain not found'}), 404

        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error fetching domain {domain}: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@app.route('/api/domain/<domain>/history', methods=['GET'])
def get_domain_history(domain):
    """
    Get scan history for a domain.
    GET /api/domain/<domain>/history?limit=100
    """
    limit = request.args.get('limit', 100, type=int)
    history = db.get_scan_history(domain, limit=limit)

    return jsonify({
        'domain': domain,
        'count': len(history),
        'history': history
    })


@app.route('/api/search', methods=['GET'])
def search_domains():
    """
    Search for domains.
    GET /api/search?q=example
    """
    query = request.args.get('q', '')

    if not query:
        # Return all domains if no query
        domains = db.get_all_domains()
    else:
        domains = db.search_domains(query)

    return jsonify({
        'count': len(domains),
        'domains': domains
    })


@app.route('/api/domains', methods=['GET'])
def get_all_domains():
    """
    Get all tracked domains.
    GET /api/domains?limit=100
    """
    limit = request.args.get('limit', 100, type=int)
    domains = db.get_all_domains(limit=limit)

    return jsonify({
        'count': len(domains),
        'domains': domains
    })


@app.route('/api/scans', methods=['GET'])
def get_all_scans():
    """
    Get all scan history.
    GET /api/scans?page=1&limit=50
    """
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = (page - 1) * limit

    conn = db.get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("""
                SELECT
                    sh.id,
                    sh.domain_id,
                    d.domain_name,
                    sh.scan_timestamp,
                    sh.dnssec_enabled,
                    sh.spf_record,
                    sh.dmarc_record,
                    sh.scan_status,
                    sh.scan_data::text as scan_data
                FROM scan_history sh
                JOIN domains d ON sh.domain_id = d.id
                ORDER BY sh.scan_timestamp DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))

            scans = []
            for row in cursor.fetchall():
                scan = dict(row)
                # Parse scan_data JSON string
                if scan.get('scan_data'):
                    try:
                        scan['scan_data'] = json.loads(scan['scan_data'])
                    except:
                        scan['scan_data'] = {}
                scans.append(scan)

            cursor.execute("SELECT COUNT(*) as total FROM scan_history")
            total = cursor.fetchone()['total']

            return jsonify({
                'count': len(scans),
                'total': total,
                'page': page,
                'limit': limit,
                'total_pages': (total + limit - 1) // limit,
                'scans': scans
            })
    finally:
        db.return_connection(conn)


@app.route('/api/certificates', methods=['GET'])
def get_all_certificates():
    """
    Get all SSL certificates.
    GET /api/certificates?page=1&limit=50
    """
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = (page - 1) * limit

    conn = db.get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("""
                SELECT
                    sc.id,
                    sc.domain_id,
                    d.domain_name,
                    sc.common_name,
                    sc.subject_alternative_names,
                    sc.issuer,
                    sc.valid_from,
                    sc.valid_until,
                    sc.is_valid,
                    sc.scan_timestamp
                FROM ssl_certificates sc
                JOIN domains d ON sc.domain_id = d.id
                WHERE sc.is_current = TRUE
                ORDER BY sc.scan_timestamp DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))

            certs = [dict(row) for row in cursor.fetchall()]

            cursor.execute("SELECT COUNT(*) as total FROM ssl_certificates WHERE is_current = TRUE")
            total = cursor.fetchone()['total']

            return jsonify({
                'count': len(certs),
                'total': total,
                'page': page,
                'limit': limit,
                'total_pages': (total + limit - 1) // limit,
                'certificates': certs
            })
    finally:
        db.return_connection(conn)


@app.route('/api/threats', methods=['GET'])
def get_all_threats():
    """
    Get all threat intelligence findings.
    GET /api/threats?page=1&limit=50
    """
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = (page - 1) * limit

    conn = db.get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("""
                SELECT
                    ti.id,
                    ti.domain_id,
                    d.domain_name,
                    ti.threat_type,
                    ti.severity,
                    ti.description,
                    ti.source,
                    ti.first_seen,
                    ti.last_seen,
                    ti.is_active
                FROM threat_intel ti
                JOIN domains d ON ti.domain_id = d.id
                WHERE ti.is_active = TRUE
                ORDER BY ti.last_seen DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))

            threats = [dict(row) for row in cursor.fetchall()]

            cursor.execute("SELECT COUNT(*) as total FROM threat_intel WHERE is_active = TRUE")
            total = cursor.fetchone()['total']

            return jsonify({
                'count': len(threats),
                'total': total,
                'page': page,
                'limit': limit,
                'total_pages': (total + limit - 1) // limit,
                'threats': threats
            })
    finally:
        db.return_connection(conn)


@app.route('/api/web3-domains', methods=['GET'])
def get_web3_domains():
    """
    Get Web3 domains (ENS, SNS, etc.).
    GET /api/web3-domains?page=1&limit=50&tld=eth
    """
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    tld = request.args.get('tld')
    offset = (page - 1) * limit

    conn = db.get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            where_clause = "WHERE w.is_active = TRUE"
            params = []

            if tld:
                where_clause += " AND w.tld = %s"
                params.append(tld)

            params.extend([limit, offset])

            cursor.execute(f"""
                SELECT
                    w.id,
                    w.domain_name,
                    w.tld,
                    w.owner_address,
                    w.registered_at,
                    w.expires_at,
                    w.resolver_records,
                    w.last_sale_price_usd,
                    w.estimated_value_usd,
                    w.transfer_count,
                    w.last_checked,
                    r.registry_name,
                    n.network_name
                FROM web3_domains w
                JOIN web3_registries r ON w.registry_id = r.id
                JOIN web3_networks n ON r.network_id = n.id
                {where_clause}
                ORDER BY w.created_at DESC
                LIMIT %s OFFSET %s
            """, params)

            domains = [dict(row) for row in cursor.fetchall()]

            cursor.execute(f"""
                SELECT COUNT(*) as total
                FROM web3_domains w
                {where_clause}
            """, params[:-2] if tld else [])
            total = cursor.fetchone()['total']

            return jsonify({
                'count': len(domains),
                'total': total,
                'page': page,
                'limit': limit,
                'total_pages': (total + limit - 1) // limit,
                'web3_domains': domains
            })
    finally:
        db.return_connection(conn)


@app.route('/api/rdap', methods=['GET'])
def get_rdap_data():
    """
    Get RDAP (Registration Data Access Protocol) data.
    GET /api/rdap?page=1&limit=50&registrar=verisign
    """
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    registrar = request.args.get('registrar')
    status = request.args.get('status')
    offset = (page - 1) * limit

    conn = db.get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            where_clause = "WHERE r.is_current = TRUE"
            params = []

            if registrar:
                where_clause += " AND LOWER(r.registrar_name) LIKE LOWER(%s)"
                params.append(f'%{registrar}%')

            if status:
                where_clause += " AND %s = ANY(r.status)"
                params.append(status)

            params.extend([limit, offset])

            cursor.execute(f"""
                SELECT
                    r.id,
                    r.domain_name,
                    r.registrar_name,
                    r.registration_date,
                    r.expiration_date,
                    r.last_changed_date,
                    r.status,
                    r.nameservers,
                    r.secure_dns_delegated,
                    r.secure_dns_zone_signed,
                    r.registrar_abuse_email,
                    r.registrar_abuse_phone,
                    r.query_timestamp,
                    EXTRACT(DAY FROM (r.expiration_date - CURRENT_TIMESTAMP)) as days_until_expiration
                FROM rdap_domains r
                {where_clause}
                ORDER BY r.query_timestamp DESC
                LIMIT %s OFFSET %s
            """, params)

            rdap_records = []
            for row in cursor.fetchall():
                record = dict(row)
                # Convert datetime objects to ISO format strings for JSON serialization
                for key in ['registration_date', 'expiration_date', 'last_changed_date', 'query_timestamp']:
                    if key in record and record[key]:
                        record[key] = record[key].isoformat() if record[key] else None
                # Convert Decimal to float for JSON serialization
                if 'days_until_expiration' in record and record['days_until_expiration'] is not None:
                    record['days_until_expiration'] = float(record['days_until_expiration'])
                rdap_records.append(record)

            cursor.execute(f"""
                SELECT COUNT(*) as total
                FROM rdap_domains r
                {where_clause}
            """, params[:-2])
            total = cursor.fetchone()['total']

            return jsonify({
                'count': len(rdap_records),
                'total': total,
                'page': page,
                'limit': limit,
                'total_pages': (total + limit - 1) // limit,
                'rdap_data': rdap_records
            })
    finally:
        db.return_connection(conn)


@app.route('/api/enrichment', methods=['GET'])
def get_enrichment_data():
    """
    Get domain enrichment data from scan history.
    GET /api/enrichment?page=1&limit=50
    """
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = (page - 1) * limit

    conn = db.get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            # Get latest scans with enrichment data
            cursor.execute("""
                WITH latest_scans AS (
                    SELECT DISTINCT ON (sh.domain_id)
                        sh.domain_id,
                        sh.scan_timestamp,
                        sh.dnssec_enabled,
                        sh.spf_record,
                        sh.dmarc_record,
                        sh.scan_data
                    FROM scan_history sh
                    ORDER BY sh.domain_id, sh.scan_timestamp DESC
                )
                SELECT
                    d.id,
                    d.domain_name,
                    ls.dnssec_enabled,
                    CASE WHEN ls.spf_record IS NOT NULL AND ls.spf_record != '' THEN true ELSE false END as spf_valid,
                    CASE WHEN ls.dmarc_record IS NOT NULL AND ls.dmarc_record != '' THEN true ELSE false END as dmarc_enabled,
                    ls.scan_data,
                    ls.scan_timestamp as last_enriched,
                    d.created_at
                FROM domains d
                INNER JOIN latest_scans ls ON d.id = ls.domain_id
                ORDER BY ls.scan_timestamp DESC
                LIMIT %s OFFSET %s
            """, [limit, offset])

            enrichment_records = []
            for row in cursor.fetchall():
                record = dict(row)

                # Extract data from scan_data JSONB if it exists
                scan_data = record.pop('scan_data', {}) or {}
                record['ssl_enabled'] = scan_data.get('has_ssl', False) if scan_data else False
                record['ssl_expired'] = scan_data.get('ssl_expired', False) if scan_data else False
                record['security_score'] = scan_data.get('security_score', 0) if scan_data else 0
                record['is_malicious'] = scan_data.get('is_malicious', False) if scan_data else False
                record['is_blacklisted'] = scan_data.get('is_blacklisted', False) if scan_data else False
                record['tld'] = record['domain_name'].split('.')[-1] if '.' in record['domain_name'] else ''

                # Convert datetime to ISO format
                if 'last_enriched' in record and record['last_enriched']:
                    record['last_enriched'] = record['last_enriched'].isoformat()
                if 'created_at' in record and record['created_at']:
                    record['created_at'] = record['created_at'].isoformat()

                enrichment_records.append(record)

            # Get total count
            cursor.execute("""
                SELECT COUNT(DISTINCT sh.domain_id) as total
                FROM scan_history sh
            """)
            total = cursor.fetchone()['total']

            # Get enrichment statistics
            cursor.execute("""
                WITH latest_scans AS (
                    SELECT DISTINCT ON (sh.domain_id)
                        sh.domain_id,
                        sh.scan_timestamp,
                        sh.dnssec_enabled,
                        sh.spf_record,
                        sh.dmarc_record,
                        sh.scan_data
                    FROM scan_history sh
                    ORDER BY sh.domain_id, sh.scan_timestamp DESC
                )
                SELECT
                    COUNT(*) as total_domains,
                    COUNT(*) as enriched_domains,
                    COUNT(CASE WHEN ls.dnssec_enabled THEN 1 END) as dnssec_count,
                    COUNT(CASE WHEN ls.spf_record IS NOT NULL AND ls.spf_record != '' THEN 1 END) as spf_count,
                    COUNT(CASE WHEN ls.dmarc_record IS NOT NULL AND ls.dmarc_record != '' THEN 1 END) as dmarc_count,
                    0 as ssl_count,
                    0 as ssl_expired_count,
                    0 as malicious_count,
                    0 as blacklisted_count,
                    0.0 as avg_security_score,
                    0 as high_security_count,
                    0 as medium_security_count,
                    0 as low_security_count
                FROM latest_scans ls
            """)
            stats = dict(cursor.fetchone())

            # Convert any Decimal types to float for JSON serialization
            from decimal import Decimal
            for key, value in stats.items():
                if isinstance(value, Decimal):
                    stats[key] = float(value)

            return jsonify({
                'count': len(enrichment_records),
                'total': int(total) if isinstance(total, Decimal) else total,
                'page': page,
                'limit': limit,
                'total_pages': (int(total) + limit - 1) // limit if total > 0 else 1,
                'enrichment_data': enrichment_records,
                'statistics': stats
            })
    finally:
        db.return_connection(conn)


@app.route('/api/my-scans', methods=['GET'])
def get_my_scans():
    """
    Get domains scanned by the current user with pagination.
    For logged-in users: persistent database history
    For anonymous users: session-based history
    GET /api/my-scans?q=query&page=1&limit=20
    """
    user_id = session.get('user_id')

    # Get search query and pagination parameters
    query = request.args.get('q', '').strip().lower()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('limit', 20, type=int)

    # Ensure page is at least 1
    page = max(1, page)
    per_page = max(1, min(per_page, 100))  # Max 100 per page

    if user_id:
        # Logged-in user: get persistent history from database
        conn = db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Build query with optional search filter
                if query:
                    count_sql = """
                        SELECT COUNT(DISTINCT d.domain_name) as total
                        FROM user_scans us
                        JOIN domains d ON us.domain_id = d.id
                        WHERE us.user_id = %s AND LOWER(d.domain_name) LIKE %s
                    """
                    cursor.execute(count_sql, (user_id, f'%{query}%'))
                else:
                    count_sql = """
                        SELECT COUNT(DISTINCT d.domain_name) as total
                        FROM user_scans us
                        JOIN domains d ON us.domain_id = d.id
                        WHERE us.user_id = %s
                    """
                    cursor.execute(count_sql, (user_id,))

                total_count = cursor.fetchone()['total']
                total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 0

                # Get paginated results with latest scan timestamp
                offset = (page - 1) * per_page
                if query:
                    data_sql = """
                        SELECT
                            d.domain_name,
                            MAX(us.scan_timestamp) as last_checked,
                            COUNT(us.id) as scan_count
                        FROM user_scans us
                        JOIN domains d ON us.domain_id = d.id
                        WHERE us.user_id = %s AND LOWER(d.domain_name) LIKE %s
                        GROUP BY d.domain_name
                        ORDER BY MAX(us.scan_timestamp) DESC
                        LIMIT %s OFFSET %s
                    """
                    cursor.execute(data_sql, (user_id, f'%{query}%', per_page, offset))
                else:
                    data_sql = """
                        SELECT
                            d.domain_name,
                            MAX(us.scan_timestamp) as last_checked,
                            COUNT(us.id) as scan_count
                        FROM user_scans us
                        JOIN domains d ON us.domain_id = d.id
                        WHERE us.user_id = %s
                        GROUP BY d.domain_name
                        ORDER BY MAX(us.scan_timestamp) DESC
                        LIMIT %s OFFSET %s
                    """
                    cursor.execute(data_sql, (user_id, per_page, offset))

                domains_data = []
                for row in cursor.fetchall():
                    domains_data.append({
                        'domain_name': row['domain_name'],
                        'last_checked': row['last_checked'].isoformat() if row['last_checked'] else None,
                        'status': 'completed',
                        'scan_count': row['scan_count']
                    })

                return jsonify({
                    'count': total_count,
                    'domains': domains_data,
                    'page': page,
                    'total_pages': total_pages,
                    'per_page': per_page,
                    'source': 'database'
                })
        finally:
            db.return_connection(conn)
    else:
        # Anonymous user: use session-based history
        my_domains = session.get('my_scans', [])

        if not my_domains:
            return jsonify({
                'count': 0,
                'domains': [],
                'page': 1,
                'total_pages': 0,
                'per_page': 20,
                'source': 'session'
            })

        # Filter domains if query provided
        if query:
            filtered_domains = [d for d in my_domains if query in d.lower()]
        else:
            filtered_domains = my_domains

        # Calculate pagination
        total_count = len(filtered_domains)
        total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_domains = filtered_domains[start_idx:end_idx]

        # Get domain details from database
        scan_statuses = session.get('scan_status', {})
        domains_data = []
        for domain in paginated_domains:
            domain_info = db.get_latest_scan(domain)
            scan_status = scan_statuses.get(domain, 'completed')

            if domain_info:
                domains_data.append({
                    'domain_name': domain,
                    'last_checked': domain_info.get('scan_timestamp', domain_info.get('last_checked')),
                    'status': scan_status
                })
            else:
                # Domain scanned but no data in DB yet (still scanning or failed)
                domains_data.append({
                    'domain_name': domain,
                    'last_checked': None,
                    'status': scan_status
                })

        return jsonify({
            'count': total_count,
            'domains': domains_data,
            'page': page,
            'total_pages': total_pages,
            'per_page': per_page,
            'source': 'session'
        })


@app.route('/api/compare/<domain>', methods=['GET'])
def compare_scans(domain):
    """
    Compare two scans to detect drift.
    GET /api/compare/<domain>?from=<timestamp>&to=<timestamp>
    Or compare first and last if no timestamps provided
    """
    history = db.get_scan_history(domain, limit=1000)

    if len(history) < 2:
        return jsonify({'error': 'Not enough history to compare'}), 400

    # Get first and last scan by default
    from_scan = history[-1]  # Oldest
    to_scan = history[0]     # Newest

    # Calculate what changed
    changes = []

    # Check each field for changes
    fields_to_check = [
        ('dnssec_enabled', 'DNSSEC Enabled'),
        ('dnssec_valid', 'DNSSEC Valid'),
        ('spf_valid', 'SPF Valid'),
        ('dkim_valid', 'DKIM Valid'),
        ('mta_sts_enabled', 'MTA-STS Enabled'),
        ('smtp_starttls_25', 'STARTTLS Port 25'),
        ('smtp_starttls_587', 'STARTTLS Port 587'),
    ]

    for field, label in fields_to_check:
        old_value = from_scan.get(field)
        new_value = to_scan.get(field)

        if old_value != new_value:
            changes.append({
                'field': label,
                'old_value': old_value,
                'new_value': new_value,
                'old_timestamp': from_scan['scan_timestamp'],
                'new_timestamp': to_scan['scan_timestamp']
            })

    return jsonify({
        'domain': domain,
        'from_scan': from_scan,
        'to_scan': to_scan,
        'changes': changes,
        'drift_detected': len(changes) > 0
    })


# ============================================================================
# SSL Certificate Endpoints
# ============================================================================

@app.route('/api/domain/<domain>/certificates', methods=['GET'])
def get_domain_certificates(domain):
    """
    Get latest SSL certificates for a domain.
    GET /api/domain/<domain>/certificates
    """
    certificates = db.get_latest_certificates(domain)

    return jsonify({
        'domain': domain,
        'count': len(certificates),
        'certificates': certificates
    })


@app.route('/api/domain/<domain>/certificates/history', methods=['GET'])
def get_certificate_history(domain):
    """
    Get SSL certificate history for a domain.
    GET /api/domain/<domain>/certificates/history?port=443&limit=100
    """
    port = request.args.get('port', type=int)
    limit = request.args.get('limit', 100, type=int)

    history = db.get_certificate_history(domain, port=port, limit=limit)

    return jsonify({
        'domain': domain,
        'port': port,
        'count': len(history),
        'history': history
    })


@app.route('/api/certificates/expiring', methods=['GET'])
def get_expiring_certificates():
    """
    Get certificates expiring soon.
    GET /api/certificates/expiring?days=30
    """
    days = request.args.get('days', 30, type=int)

    certificates = db.get_expiring_certificates(days=days)

    return jsonify({
        'days': days,
        'count': len(certificates),
        'certificates': certificates
    })


@app.route('/api/certificates/expired', methods=['GET'])
def get_expired_certificates_endpoint():
    """
    Get expired certificates.
    GET /api/certificates/expired
    """
    certificates = db.get_expired_certificates()

    return jsonify({
        'count': len(certificates),
        'certificates': certificates
    })


# ============================================================================
# Reverse DNS / PTR Record Endpoints
# ============================================================================

@app.route('/api/reverse-dns', methods=['GET'])
def get_reverse_dns_records():
    """
    Get PTR records with validation status.
    GET /api/reverse-dns?page=1&limit=50&valid_only=false
    """
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    valid_only = request.args.get('valid_only', 'false').lower() == 'true'

    offset = (page - 1) * limit

    conn = db.get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            where_clause = "WHERE p.is_current = TRUE"
            if valid_only:
                where_clause += " AND p.is_valid = TRUE"

            cursor.execute(f"""
                SELECT
                    p.id,
                    p.ip_address,
                    p.ip_version,
                    p.ptr_name,
                    p.ptr_value,
                    p.is_valid,
                    p.forward_matches,
                    p.forward_lookup_result,
                    p.is_mail_server,
                    p.scan_timestamp,
                    d.domain_name
                FROM ptr_records p
                JOIN domains d ON p.domain_id = d.id
                {where_clause}
                ORDER BY p.scan_timestamp DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))

            records = [dict(row) for row in cursor.fetchall()]

            # Get total count
            cursor.execute(f"""
                SELECT COUNT(*) as total
                FROM ptr_records p
                {where_clause}
            """)
            total = cursor.fetchone()['total']

            return jsonify({
                'count': len(records),
                'total': total,
                'page': page,
                'limit': limit,
                'total_pages': (total + limit - 1) // limit,
                'ptr_records': records
            })
    finally:
        db.return_connection(conn)


@app.route('/api/reverse-dns/issues', methods=['GET'])
def get_reverse_dns_issues():
    """
    Get reverse DNS configuration issues.
    GET /api/reverse-dns/issues?severity=high&status=open
    """
    severity = request.args.get('severity')
    status = request.args.get('status', 'open')

    conn = db.get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            where_parts = ["i.status = %s"]
            params = [status]

            if severity:
                where_parts.append("i.severity = %s")
                params.append(severity)

            where_clause = " AND ".join(where_parts)

            cursor.execute(f"""
                SELECT
                    i.*,
                    d.domain_name
                FROM reverse_dns_issues i
                JOIN domains d ON i.domain_id = d.id
                WHERE {where_clause}
                ORDER BY
                    CASE i.severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        ELSE 4
                    END,
                    i.last_detected DESC
                LIMIT 100
            """, params)

            issues = [dict(row) for row in cursor.fetchall()]

            return jsonify({
                'count': len(issues),
                'issues': issues
            })
    finally:
        db.return_connection(conn)


@app.route('/api/certificates/changes', methods=['GET'])
def get_certificate_changes_endpoint():
    """
    Get certificate changes (drift detection).
    GET /api/certificates/changes?domain=example.com&days=30
    """
    domain = request.args.get('domain')
    days = request.args.get('days', 30, type=int)

    changes = db.get_certificate_changes(domain_name=domain, days=days)

    return jsonify({
        'domain': domain,
        'days': days,
        'count': len(changes),
        'changes': changes
    })


# ============================================
# DATA BROWSER ENDPOINTS
# ============================================

@app.route('/api/browse/tlds', methods=['GET'])
def api_browse_tlds():
    """Browse TLDs with statistics"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    result = browser.browse_tlds(page, per_page)
    return jsonify(result)


@app.route('/api/browse/tld/<tld>', methods=['GET'])
def api_browse_tld_domains(tld):
    """Browse domains by TLD"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    sort_by = request.args.get('sort_by', 'last_checked')
    result = browser.browse_tld_domains(tld, page, per_page, sort_by)
    return jsonify(result)


@app.route('/api/browse/ssl-status/<status>', methods=['GET'])
def api_browse_ssl_status(status):
    """Browse domains by SSL status/grade"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    result = browser.browse_ssl_status(status, page, per_page)
    return jsonify(result)


@app.route('/api/browse/threat-intel', methods=['GET'])
def api_browse_threat_intel():
    """Browse threat intelligence data"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    severity = request.args.get('severity')
    result = browser.browse_threat_intel(severity, page, per_page)
    return jsonify(result)


@app.route('/api/browse/blacklists', methods=['GET'])
def api_browse_blacklists():
    """Browse blacklist data"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    blacklist = request.args.get('blacklist')
    result = browser.browse_blacklists(blacklist, page, per_page)
    return jsonify(result)


@app.route('/api/domain/<domain>/complete-profile', methods=['GET'])
def api_domain_complete_profile(domain):
    """Get complete domain profile with full history"""
    profile = browser.get_domain_complete_profile(domain)
    if profile:
        return jsonify(profile)
    return jsonify({'error': 'Domain not found'}), 404


@app.route('/api/ip/<ip>/complete-profile', methods=['GET'])
def api_ip_complete_profile(ip):
    """Get complete IP profile"""
    profile = browser.get_ip_complete_profile(ip)
    if profile:
        return jsonify(profile)
    return jsonify({'error': 'IP not found'}), 404


@app.route('/api/domain/<domain>/timeline', methods=['GET'])
def api_domain_timeline(domain):
    """Get timeline of domain changes"""
    limit = request.args.get('limit', 100, type=int)
    timeline = browser.get_timeline(domain, limit)
    return jsonify({'domain': domain, 'timeline': timeline})


# ============================================
# CUSTOM SCANNER ENDPOINTS
# ============================================

def get_user_id_from_token():
    """Extract user ID from session"""
    return session.get('user_id')


@app.route('/api/scanners', methods=['POST'])
def api_create_scanner():
    """Create a new custom scanner"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    try:
        scanner = scanner_manager.create_scanner(
            user_id=user_id,
            scanner_name=data.get('scanner_name'),
            description=data.get('description'),
            scan_options=data.get('scan_options'),
            schedule_type=data.get('schedule_type', 'manual'),
            schedule_cron=data.get('schedule_cron'),
            alert_thresholds=data.get('alert_thresholds'),
            notification_emails=data.get('notification_emails'),
            notification_webhooks=data.get('notification_webhooks')
        )
        return jsonify({'success': True, 'scanner': scanner})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scanners', methods=['GET'])
def api_list_scanners():
    """List all scanners for authenticated user"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    include_stats = request.args.get('stats', 'false').lower() == 'true'
    scanners = scanner_manager.list_scanners(user_id, include_stats)
    return jsonify({'scanners': scanners})


@app.route('/api/scanners/<int:scanner_id>', methods=['GET'])
def api_get_scanner(scanner_id):
    """Get scanner by ID"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    scanner = scanner_manager.get_scanner(scanner_id, user_id)
    if scanner:
        return jsonify(scanner)
    return jsonify({'error': 'Scanner not found'}), 404


@app.route('/api/scanners/<int:scanner_id>', methods=['PUT'])
def api_update_scanner(scanner_id):
    """Update scanner settings"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    try:
        scanner = scanner_manager.update_scanner(scanner_id, user_id, data)
        return jsonify({'success': True, 'scanner': scanner})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scanners/<int:scanner_id>', methods=['DELETE'])
def api_delete_scanner(scanner_id):
    """Delete a scanner"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    success = scanner_manager.delete_scanner(scanner_id, user_id)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Scanner not found'}), 404


@app.route('/api/scanners/<int:scanner_id>/run', methods=['POST'])
def api_run_scanner(scanner_id):
    """Execute a scanner"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        result = scanner_manager.run_scanner(scanner_id, user_id, trigger_type='manual')
        return jsonify({'success': True, 'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scanners/<int:scanner_id>/targets', methods=['GET'])
def api_list_scanner_targets(scanner_id):
    """List scanner targets"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    # Verify ownership
    scanner = scanner_manager.get_scanner(scanner_id, user_id)
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404

    targets = scanner_manager.list_targets(scanner_id)
    return jsonify({'targets': targets})


@app.route('/api/scanners/<int:scanner_id>/targets', methods=['POST'])
def api_add_scanner_target(scanner_id):
    """Add target to scanner"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    domain_name = data.get('domain_name')

    if not domain_name:
        return jsonify({'error': 'domain_name required'}), 400

    try:
        target = scanner_manager.add_target(
            scanner_id=scanner_id,
            domain_name=domain_name,
            user_id=user_id,
            notes=data.get('notes'),
            tags=data.get('tags')
        )
        return jsonify({'success': True, 'target': target})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scanners/<int:scanner_id>/targets/<domain>', methods=['DELETE'])
def api_remove_scanner_target(scanner_id, domain):
    """Remove target from scanner"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    # Verify ownership
    scanner = scanner_manager.get_scanner(scanner_id, user_id)
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404

    success = scanner_manager.remove_target(scanner_id, domain)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Target not found'}), 404


@app.route('/api/scanners/<int:scanner_id>/results', methods=['GET'])
def api_get_scanner_results(scanner_id):
    """Get scanner execution history"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    # Verify ownership
    scanner = scanner_manager.get_scanner(scanner_id, user_id)
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404

    limit = request.args.get('limit', 100, type=int)
    results = scanner_manager.get_scanner_results(scanner_id, limit)
    return jsonify({'results': results})


@app.route('/api/scanners/<int:scanner_id>/alerts', methods=['GET'])
def api_get_scanner_alerts(scanner_id):
    """Get scanner alerts"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    # Verify ownership
    scanner = scanner_manager.get_scanner(scanner_id, user_id)
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404

    unacknowledged_only = request.args.get('unacknowledged', 'false').lower() == 'true'
    limit = request.args.get('limit', 100, type=int)
    alerts = scanner_manager.get_scanner_alerts(scanner_id, unacknowledged_only, limit)
    return jsonify({'alerts': alerts})


# ============================================
# ADVANCED SEARCH ENDPOINTS
# ============================================

@app.route('/api/search/advanced', methods=['GET'])
def api_advanced_search():
    """Advanced domain search with filters"""
    query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    filters = {}

    # Boolean filters
    if request.args.get('dnssec') is not None:
        filters['dnssec_enabled'] = request.args.get('dnssec').lower() == 'true'
    if request.args.get('spf') is not None:
        filters['spf_valid'] = request.args.get('spf').lower() == 'true'
    if request.args.get('dkim') is not None:
        filters['dkim_valid'] = request.args.get('dkim').lower() == 'true'
    if request.args.get('dmarc') is not None:
        filters['dmarc_enabled'] = request.args.get('dmarc').lower() == 'true'
    if request.args.get('has_threats') is not None:
        filters['has_threats'] = request.args.get('has_threats').lower() == 'true'
    if request.args.get('blacklisted') is not None:
        filters['blacklisted'] = request.args.get('blacklisted').lower() == 'true'

    # String filters
    if request.args.get('ssl_grade'):
        filters['ssl_grade'] = request.args.get('ssl_grade')

    # Numeric filters
    if request.args.get('security_score_min'):
        filters['security_score_min'] = int(request.args.get('security_score_min'))
    if request.args.get('security_score_max'):
        filters['security_score_max'] = int(request.args.get('security_score_max'))
    if request.args.get('cert_expiring_days'):
        filters['cert_expiring_days'] = int(request.args.get('cert_expiring_days'))

    # Tag filter (requires authentication)
    if request.args.get('tags'):
        user_id = get_user_id_from_token()
        if user_id:
            filters['tags'] = request.args.get('tags').split(',')

    results = search_manager.search_domains(query, filters, page, per_page, get_user_id_from_token())
    return jsonify(results)


@app.route('/api/search/web3', methods=['GET'])
def api_search_web3():
    """Search Web3 domains"""
    query = request.args.get('q', '')
    blockchain = request.args.get('blockchain')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    results = search_manager.search_web3_domains(query, blockchain, page, per_page)
    return jsonify(results)


@app.route('/api/search/autocomplete', methods=['GET'])
def api_search_autocomplete():
    """Autocomplete domain suggestions"""
    query = request.args.get('q', '')
    limit = request.args.get('limit', 10, type=int)

    suggestions = search_manager.autocomplete_domains(query, limit)
    return jsonify({'suggestions': suggestions})


# ============================================
# PAGE ROUTES
# ============================================

@app.route('/browse')
def browse_page():
    """Data browser page"""
    return render_template('browse.php')


@app.route('/settings')
def settings_page():
    """User settings page"""
    return render_template('settings.php')


@app.route('/scanners')
def scanners_page():
    """Custom scanners page"""
    return render_template('scanners.php')


@app.route('/domain/<domain>')
def domain_profile_page(domain):
    """Domain profile page"""
    return render_template('domain-profile.php', domain=domain)


# ============================================
# LIVE STATISTICS & THREAT FEED ENDPOINTS
# ============================================

@app.route('/api/stats', methods=['GET'])
@app.route('/api/stats/live', methods=['GET'])
def api_live_stats():
    """
    Get live platform statistics
    Returns real-time metrics that update as data is ingested
    """
    try:
        stats = db.get_live_statistics()
        return jsonify({
            'total_domains': stats.get('total_domains', 0),
            'ssl_certificates': stats.get('ssl_certificates', 0),
            'email_records': stats.get('email_records', 0),
            'drift_monitoring': stats.get('drift_monitoring', 0),
            'ips_tracked': stats.get('ips_tracked', 0),
            'active_feeds': stats.get('active_feeds', 20),  # Number of threat intel feeds
            'last_updated': stats.get('last_updated')
        })
    except Exception as e:
        return jsonify({
            'total_domains': 0,
            'ssl_certificates': 0,
            'email_records': 0,
            'drift_monitoring': 0,
            'ips_tracked': 0,
            'active_feeds': 20
        })


@app.route('/api/threats/recent', methods=['GET'])
def api_recent_threats():
    """
    Get recent threat intelligence detections
    Supports filtering by severity
    """
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity')

    try:
        threats = db.get_recent_threats(limit=limit, severity=severity)
        return jsonify({
            'threats': threats,
            'count': len(threats),
            'timestamp': db.get_current_timestamp()
        })
    except Exception as e:
        return jsonify({
            'threats': [],
            'count': 0,
            'error': str(e)
        }), 500


@app.route('/api/stats/dashboard', methods=['GET'])
def api_dashboard_stats():
    """
    Get comprehensive dashboard statistics
    Includes trends and historical data
    """
    try:
        stats = db.get_dashboard_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/threat/<threat_id>')
def threat_detail_page(threat_id):
    """Threat detail page"""
    return render_template('threat-detail.php', threat_id=threat_id)


# ============================================================================
# DNS CONFIGURATION VALIDATION API - PREMIUM FEATURES
# ============================================================================

@app.route('/api/validate/dns-config', methods=['POST'])
@require_premium
def validate_dns_config():
    """
    Validate uploaded DNS configuration file.
    Supports BIND9, djbdns, Unbound, NSD configurations.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Get server type from request or auto-detect
        server_type = request.form.get('server_type', None)

        # Validate configuration
        results = config_validator.validate_uploaded_files(filepath, server_type)

        # Clean up uploaded file
        os.remove(filepath)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/validate/dns-cache', methods=['GET'])
@require_premium
def inspect_dns_cache():
    """
    Inspect DNS cache from Unbound daemon.
    Returns cache statistics and entries.
    """
    try:
        domain_filter = request.args.get('domain', None)

        if domain_filter:
            # Lookup specific domain in cache
            result = cache_inspector.lookup_cache(domain_filter)
        else:
            # Get overall cache stats
            result = cache_inspector.get_cache_stats()

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/validate/dns-cache/dump', methods=['GET'])
@require_premium
def dump_dns_cache():
    """Dump all DNS cache entries"""
    try:
        domain_filter = request.args.get('domain', None)
        entries = cache_inspector.dump_cache(domain_filter)
        return jsonify({'entries': entries, 'count': len(entries)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/validate/dnssec/<domain>', methods=['GET'])
def validate_dnssec(domain):
    """
    Validate DNSSEC for a domain.
    Public API - no authentication required.
    """
    try:
        results = dnssec_validator.validate_dnssec(domain)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/validate/dane/<domain>', methods=['GET'])
def validate_dane(domain):
    """
    Validate DANE/TLSA records for a domain.
    Public API - no authentication required.
    """
    try:
        port = request.args.get('port', 443, type=int)
        results = dnssec_validator.validate_dane(domain, port)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/validate/zone-transfer/<domain>', methods=['GET'])
@require_premium
def check_zone_transfer(domain):
    """
    Check if zone transfer is allowed for a domain.
    Premium feature for security testing.
    """
    try:
        nameserver = request.args.get('nameserver', None)
        results = zone_checker.check_zone_transfer(domain, nameserver)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/validate/hijacking/<domain>', methods=['GET'])
@require_premium
def check_domain_hijacking(domain):
    """
    Check domain for potential hijacking indicators.
    Premium feature for domain security monitoring.
    """
    try:
        results = hijack_validator.check_hijacking_indicators(domain)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# CONFIGURATION VALIDATION WEB PAGES
# ============================================================================

@app.route('/tools/dns-config-validator')
def dns_config_validator_page():
    """DNS Configuration Validator tool page"""
    return render_template('tools/dns-config-validator.php')


@app.route('/tools/dns-cache-inspector')
def dns_cache_inspector_page():
    """DNS Cache Inspector tool page"""
    return render_template('tools/dns-cache-inspector.php')


@app.route('/tools/dnssec-validator')
def dnssec_validator_page():
    """DNSSEC/DANE Validator tool page"""
    return render_template('tools/dnssec-validator.php')


@app.route('/tools/zone-transfer-check')
def zone_transfer_check_page():
    """Zone Transfer Security Check tool page"""
    return render_template('tools/zone-transfer-check.php')


@app.route('/tools/hijacking-detector')
def hijacking_detector_page():
    """Domain Hijacking Detector tool page"""
    return render_template('tools/hijacking-detector.php')


# ============================================================================
# CERTIFICATE TOOLS API - PREMIUM FEATURES
# ============================================================================

@app.route('/api/cert/resolve-chain', methods=['POST'])
@require_premium
def resolve_certificate_chain():
    """
    Resolve complete certificate chain from uploaded leaf certificate.
    Automatically fetches missing intermediate and root certificates.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No certificate file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Resolve chain
        resolver = CertificateChainResolver()
        results = resolver.resolve_chain(filepath)

        # Export full chain if requested
        export_format = request.form.get('export_format', None)
        if export_format and results['success']:
            export_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                f"chain.{export_format}"
            )
            if resolver.export_chain(export_path, export_format):
                results['download_url'] = f'/api/cert/download/{os.path.basename(export_path)}'

        # Clean up uploaded file
        os.remove(filepath)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cert/check-revocation', methods=['POST'])
@require_premium
def check_certificate_revocation():
    """
    Check certificate revocation status via OCSP and CRL.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No certificate file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Check revocation
        validator = CertificateRevocationValidator()
        results = validator.check_revocation(filepath)

        # Clean up
        os.remove(filepath)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cert/check-expiry', methods=['POST'])
def check_certificate_expiry():
    """
    Check certificate expiration status.
    Public API - no authentication required.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No certificate file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Check expiry
        validator = CertificateExpiryValidator()
        results = validator.check_expiry(filepath)

        # Clean up
        os.remove(filepath)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cert/convert', methods=['POST'])
@require_premium
def convert_certificate_format():
    """
    Convert certificate between different formats.
    Supports: PEM, DER, PKCS7, PKCS12
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No certificate file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Get conversion parameters
        input_format = request.form.get('input_format', 'pem')
        output_format = request.form.get('output_format', 'der')
        password = request.form.get('password', None)

        # Save uploaded file
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)

        # Output path
        output_filename = f"converted.{output_format}"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        # Convert
        converter = CertificateConverter()
        results = converter.convert(
            input_path, output_path,
            input_format, output_format,
            password
        )

        if results['success']:
            results['download_url'] = f'/api/cert/download/{output_filename}'

        # Clean up input
        os.remove(input_path)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cert/download/<filename>')
@require_premium
def download_certificate(filename):
    """Download generated certificate file"""
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 404


@app.route('/api/cert/openssl-command', methods=['POST'])
def build_openssl_command():
    """
    Build OpenSSL command for specified operation.
    Public API for users who don't want to upload files.
    """
    try:
        data = request.get_json()
        operation = data.get('operation')

        if not operation:
            return jsonify({'error': 'Operation not specified'}), 400

        # Remove 'operation' from data, pass rest as kwargs
        params = {k: v for k, v in data.items() if k != 'operation'}

        builder = OpenSSLCommandBuilder()
        result = builder.build_command(operation, **params)

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# JKS (JAVA KEYSTORE) TOOLS API - PREMIUM FEATURES
# ============================================================================

@app.route('/api/jks/validate', methods=['POST'])
@require_premium
def validate_jks_keystore():
    """
    Validate JKS keystore and check chain integrity.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No JKS file uploaded'}), 400

    file = request.files['file']
    password = request.form.get('password', '')

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Validate JKS
        manager = JKSManager()
        results = manager.validate_jks(filepath, password)

        # Clean up
        os.remove(filepath)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/jks/convert-to-pkcs12', methods=['POST'])
@require_premium
def convert_jks_to_pkcs12():
    """
    Convert JKS keystore to PKCS12 format.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No JKS file uploaded'}), 400

    file = request.files['file']
    password = request.form.get('password', '')
    alias = request.form.get('alias', None)

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Save uploaded JKS file
        filename = secure_filename(file.filename)
        jks_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(jks_path)

        # Output PKCS12 path
        pkcs12_filename = f"{filename.rsplit('.', 1)[0]}.p12"
        pkcs12_path = os.path.join(app.config['UPLOAD_FOLDER'], pkcs12_filename)

        # Convert
        manager = JKSManager()
        results = manager.convert_jks_to_pkcs12(jks_path, pkcs12_path, password, alias)

        if results['success']:
            results['download_url'] = f'/api/cert/download/{pkcs12_filename}'

        # Clean up input file
        os.remove(jks_path)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/jks/convert-from-pkcs12', methods=['POST'])
@require_premium
def convert_pkcs12_to_jks():
    """
    Convert PKCS12 file to JKS keystore.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No PKCS12 file uploaded'}), 400

    file = request.files['file']
    password = request.form.get('password', '')

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Save uploaded PKCS12 file
        filename = secure_filename(file.filename)
        pkcs12_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(pkcs12_path)

        # Output JKS path
        jks_filename = f"{filename.rsplit('.', 1)[0]}.jks"
        jks_path = os.path.join(app.config['UPLOAD_FOLDER'], jks_filename)

        # Convert
        manager = JKSManager()
        results = manager.convert_pkcs12_to_jks(pkcs12_path, jks_path, password)

        if results['success']:
            results['download_url'] = f'/api/jks/download/{jks_filename}'

        # Clean up input file
        os.remove(pkcs12_path)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/jks/update-chain', methods=['POST'])
@require_premium
def update_jks_chain():
    """
    Update certificate chain for an alias in JKS keystore.
    """
    if 'jks_file' not in request.files or 'chain_file' not in request.files:
        return jsonify({'error': 'Both JKS file and chain file required'}), 400

    jks_file = request.files['jks_file']
    chain_file = request.files['chain_file']
    password = request.form.get('password', '')
    alias = request.form.get('alias', '')

    if not alias:
        return jsonify({'error': 'Alias is required'}), 400

    try:
        # Save files
        jks_filename = secure_filename(jks_file.filename)
        jks_path = os.path.join(app.config['UPLOAD_FOLDER'], jks_filename)
        jks_file.save(jks_path)

        chain_filename = secure_filename(chain_file.filename)
        chain_path = os.path.join(app.config['UPLOAD_FOLDER'], chain_filename)
        chain_file.save(chain_path)

        # Update chain
        manager = JKSManager()
        results = manager.update_jks_chain(jks_path, password, alias, chain_path)

        if results['success']:
            results['download_url'] = f'/api/jks/download/{jks_filename}'

        # Clean up chain file, keep JKS for download
        os.remove(chain_path)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/jks/add-cert', methods=['POST'])
@require_premium
def add_cert_to_jks():
    """
    Add a certificate to JKS keystore.
    """
    if 'jks_file' not in request.files or 'cert_file' not in request.files:
        return jsonify({'error': 'Both JKS file and certificate file required'}), 400

    jks_file = request.files['jks_file']
    cert_file = request.files['cert_file']
    password = request.form.get('password', '')
    alias = request.form.get('alias', '')
    is_trusted = request.form.get('is_trusted', 'true').lower() == 'true'

    if not alias:
        return jsonify({'error': 'Alias is required'}), 400

    try:
        # Save files
        jks_filename = secure_filename(jks_file.filename)
        jks_path = os.path.join(app.config['UPLOAD_FOLDER'], jks_filename)
        jks_file.save(jks_path)

        cert_filename = secure_filename(cert_file.filename)
        cert_path = os.path.join(app.config['UPLOAD_FOLDER'], cert_filename)
        cert_file.save(cert_path)

        # Add certificate
        manager = JKSManager()
        results = manager.add_certificate_to_jks(jks_path, password, alias, cert_path, is_trusted)

        if results['success']:
            results['download_url'] = f'/api/jks/download/{jks_filename}'

        # Clean up cert file
        os.remove(cert_path)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/jks/remove-entry', methods=['POST'])
@require_premium
def remove_jks_entry():
    """
    Remove an entry from JKS keystore.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No JKS file uploaded'}), 400

    file = request.files['file']
    password = request.form.get('password', '')
    alias = request.form.get('alias', '')

    if not alias:
        return jsonify({'error': 'Alias is required'}), 400

    try:
        # Save file
        filename = secure_filename(file.filename)
        jks_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(jks_path)

        # Remove entry
        manager = JKSManager()
        results = manager.remove_entry_from_jks(jks_path, password, alias)

        if results['success']:
            results['download_url'] = f'/api/jks/download/{filename}'

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/jks/fix-chain', methods=['POST'])
@require_premium
def fix_jks_chain():
    """
    Fix incomplete certificate chain in JKS keystore.
    Automatically resolves and updates with complete chain.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No JKS file uploaded'}), 400

    file = request.files['file']
    password = request.form.get('password', '')
    alias = request.form.get('alias', '')

    if not alias:
        return jsonify({'error': 'Alias is required'}), 400

    try:
        # Save file
        filename = secure_filename(file.filename)
        jks_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(jks_path)

        # Fix chain
        manager = JKSManager()
        results = manager.fix_jks_chain(jks_path, password, alias)

        if results['success']:
            results['download_url'] = f'/api/jks/download/{filename}'

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/jks/download/<filename>')
@require_premium
def download_jks(filename):
    """Download JKS keystore file"""
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 404


# ============================================================================
# CERTIFICATE TOOLS WEB PAGES
# ============================================================================

@app.route('/tools/cert-chain-resolver')
def cert_chain_resolver_page():
    """Certificate Chain Resolver tool page"""
    return render_template('tools/cert-chain-resolver.php')


@app.route('/tools/cert-validator')
def cert_validator_page():
    """Certificate Validator tool page (revocation, expiry)"""
    return render_template('tools/cert-validator.php')


@app.route('/tools/cert-converter')
def cert_converter_page():
    """Certificate Format Converter tool page"""
    return render_template('tools/cert-converter.php')


@app.route('/tools/openssl-builder')
def openssl_builder_page():
    """OpenSSL Command Builder tool page"""
    return render_template('tools/openssl-builder.php')


@app.route('/tools/jks-manager')
def jks_manager_page():
    """JKS Keystore Manager tool page"""
    return render_template('tools/jks-manager.php')


# Page Routes
@app.route('/login')
def login_page():
    """Login page"""
    return render_template('login.html')


@app.route('/signup')
def signup_page():
    """Signup page"""
    return render_template('signup.html')


@app.route('/docs/api')
def api_docs_page():
    """API documentation page"""
    return render_template('api_docs.html')


@app.route('/docs/cli')
def cli_docs_page():
    """CLI documentation page"""
    return render_template('cli_docs.html')


@app.route('/docs/architecture')
def architecture_docs_page():
    """Platform architecture documentation page"""
    return render_template('architecture.html')


@app.route('/explorer')
def explorer_page():
    """Data explorer page"""
    return render_template('explorer.html')


@app.route('/about')
def about_page():
    """About Us page"""
    return render_template('about.html')


@app.route('/pricing')
def pricing_page():
    """Pricing page"""
    return render_template('pricing.html')


@app.route('/services')
def services_page():
    """Professional Services page"""
    return render_template('services.html')


@app.route('/tools/darkweb')
def darkweb_lookup_page():
    """Dark Web DNS Monitoring Tool"""
    return render_template('tools/darkweb_lookup.html')


@app.route('/registrar')
def registrar_page():
    """Domain Registrar - Register, Transfer, and Purchase SSL"""
    return render_template('registrar.html')


@app.route('/dashboard/domains')
@login_required
def domains_dashboard():
    """User domain management dashboard"""
    return render_template('dashboard/domains.html')


@app.route('/marketplace')
def marketplace_page():
    """Domain Marketplace - Buy and Sell Domains"""
    return render_template('marketplace/browse.html')


@app.route('/acquisition')
def acquisition_page():
    """Domain Acquisition Service (Manual Broker)"""
    domain = request.args.get('domain', '')
    return render_template('acquisition.html', domain=domain)


@app.route('/acquisition/priority')
def priority_acquisition_page():
    """Priority Expiration Registration Service (Automated)"""
    domain = request.args.get('domain', '')
    stripe_public_key = os.getenv('STRIPE_PUBLISHABLE_KEY', '')
    return render_template('priority_acquisition.html',
                         domain=domain,
                         stripe_public_key=stripe_public_key)


@app.route('/acquisition/dashboard')
@login_required
def acquisition_dashboard():
    """User dashboard to track domain acquisition requests"""
    return render_template('acquisition_dashboard.html')


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user account"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    email = data.get('email', '').strip()
    password = data.get('password', '')
    full_name = data.get('full_name', '').strip()
    company = data.get('company', '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user_id, error = user_auth.register_user(
        email=email,
        password=password,
        full_name=full_name if full_name else None,
        company=company if company else None
    )

    if error:
        return jsonify({'error': error}), 400

    # Auto-login after registration
    user_data, login_error = user_auth.login_user(email, password)
    if login_error:
        return jsonify({
            'success': True,
            'user_id': user_id,
            'message': 'Account created successfully. Please log in.'
        }), 201

    return jsonify({
        'success': True,
        'user': {
            'id': user_data['id'],
            'email': user_data['email'],
            'full_name': user_data.get('full_name')
        }
    }), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login with email and password"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    email = data.get('email', '').strip()
    password = data.get('password', '')
    remember_me = data.get('remember_me', False)

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user_data, error = user_auth.login_user(email, password, remember_me)
    if error:
        return jsonify({'error': error}), 401

    plan = user_auth.get_user_plan(user_data['id'])
    return jsonify({
        'success': True,
        'user': {
            'id': user_data['id'],
            'email': user_data['email'],
            'full_name': user_data.get('full_name'),
            'plan': plan['name'] if plan else 'free'
        }
    }), 200


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout current user"""
    user_auth.logout_user()
    return jsonify({'success': True}), 200


@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user_info():
    """Get current logged-in user information"""
    user = user_auth.get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    allowed, remaining, limit_type = user_auth.check_rate_limit(user['id'])
    return jsonify({
        'user': {
            'id': user['id'],
            'email': user['email'],
            'full_name': user.get('full_name'),
            'company': user.get('company'),
            'plan': user.get('plan_name', 'free'),
            'plan_display_name': user.get('plan_display_name', 'Free')
        },
        'usage': {
            'scans_remaining_today': remaining,
            'rate_limit_exceeded': not allowed
        }
    }), 200


@app.route('/api/auth/check', methods=['GET'])
def check_authentication():
    """Check if user is authenticated (no @login_required to avoid redirect)"""
    user = user_auth.get_current_user()
    if user:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': user['id'],
                'username': user.get('username', user.get('email', '').split('@')[0]),
                'email': user['email'],
                'full_name': user.get('full_name'),
                'plan': user.get('plan_name', 'free')
            }
        }), 200
    else:
        return jsonify({
            'authenticated': False,
            'user': None
        }), 200


# ============================================================================
# ACCOUNT MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/account/plan', methods=['GET'])
@login_required
def get_account_plan():
    """Get user's subscription plan details"""
    user_id = session.get('user_id')
    plan = user_auth.get_user_plan(user_id)
    if not plan:
        return jsonify({'error': 'No active subscription'}), 404

    return jsonify({'plan': plan}), 200


@app.route('/api/account/api-keys', methods=['GET'])
@login_required
def list_api_keys():
    """List all API keys for current user"""
    user_id = session.get('user_id')
    keys = api_key_manager.list_api_keys(user_id)
    return jsonify({'api_keys': keys}), 200


@app.route('/api/account/api-keys', methods=['POST'])
@login_required
def create_api_key():
    """Create a new API key"""
    user_id = session.get('user_id')
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    if not name:
        return jsonify({'error': 'API key name is required'}), 400

    api_key, key_id, error = api_key_manager.create_api_key(
        user_id=user_id,
        name=name,
        description=description if description else None
    )

    if error:
        return jsonify({'error': error}), 400

    return jsonify({
        'success': True,
        'api_key': api_key,
        'key_id': key_id,
        'message': 'API key created. Save this - you won\'t see it again!'
    }), 201


@app.route('/api/account/api-keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    """Delete an API key"""
    user_id = session.get('user_id')
    success, error = api_key_manager.delete_api_key(user_id, key_id)
    if error:
        return jsonify({'error': error}), 404
    return jsonify({'success': True}), 200


@app.route('/api/domain/<domain>/valuation', methods=['GET'])
def get_domain_valuation(domain):
    """
    Get domain valuation/appraisal.
    GET /api/domain/<domain>/valuation

    Query params:
    - force_refresh: Force new valuation instead of using cached (true/false)

    Returns:
    {
        "domain_name": "example.com",
        "estimated_value_low": 500,
        "estimated_value_mid": 1200,
        "estimated_value_high": 2500,
        "overall_score": 75,
        "scores": {
            "length_score": 80,
            "tld_score": 100,
            "age_score": 50,
            "activity_score": 85,
            "keyword_score": 60
        },
        "factors": {...},
        "created_at": "2025-01-01T12:00:00"
    }
    """
    domain = domain.strip().lower()
    force_refresh = request.args.get('force_refresh', 'false').lower() == 'true'

    try:
        # Check for cached valuation first (unless force_refresh)
        if not force_refresh:
            cached_valuation = db.get_latest_valuation(domain)
            if cached_valuation:
                return jsonify(cached_valuation)

        # Get latest scan data for activity scoring
        scan_data = db.get_latest_scan(domain)

        # Get domain age if available (from scan data or WHOIS)
        domain_age_years = None
        if scan_data and scan_data.get('domain_age'):
            domain_age_years = scan_data['domain_age']

        # Calculate valuation
        valuation_result = valuation_engine.estimate_value(
            domain_name=domain,
            domain_age_years=domain_age_years,
            scan_data=scan_data
        )

        # Save to database
        db.save_domain_valuation(domain, valuation_result)

        # Get the saved record (includes timestamp)
        saved_valuation = db.get_latest_valuation(domain)

        return jsonify(saved_valuation)
    except Exception as e:
        return jsonify({'error': str(e), 'domain': domain}), 500


@app.route('/api/valuations/top', methods=['GET'])
def get_top_valuations():
    """
    Get domains with highest valuations.
    GET /api/valuations/top

    Query params:
    - limit: Max results (default 100)

    Returns list of domain valuations sorted by score/value
    """
    limit = request.args.get('limit', 100, type=int)
    limit = min(limit, 1000)  # Cap at 1000

    try:
        top_domains = db.get_top_valued_domains(limit=limit)
        return jsonify({
            'count': len(top_domains),
            'domains': top_domains
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/domain/<domain>/valuation/history', methods=['GET'])
def get_valuation_history(domain):
    """
    Get valuation history for a domain.
    GET /api/domain/<domain>/valuation/history

    Query params:
    - limit: Max results (default 10)
    """
    domain = domain.strip().lower()
    limit = request.args.get('limit', 10, type=int)
    limit = min(limit, 100)  # Cap at 100

    try:
        history = db.get_valuation_history(domain, limit=limit)
        return jsonify({
            'domain': domain,
            'count': len(history),
            'history': history
        })
    except Exception as e:
        return jsonify({'error': str(e), 'domain': domain}), 500


# ============================================================================
# IP Intelligence API Routes
# ============================================================================

# Import IP intelligence engine
from ip_intelligence import IPIntelligenceEngine

# Initialize IP intelligence engine
ip_engine = IPIntelligenceEngine({
    'ipinfo_token': os.getenv('IPINFO_TOKEN'),
    'abuseipdb_key': os.getenv('ABUSEIPDB_KEY'),
    'cloudflare_token': os.getenv('CLOUDFLARE_TOKEN')
})


@app.route('/api/ip/<ip>/scan', methods=['GET'])
def scan_ip_address(ip):
    """
    Comprehensive IP address scan

    GET /api/ip/<ip>/scan

    Query Parameters:
        force_refresh: If true, bypass cache and perform fresh scan
        full_scan: If true, include all data sources (default: true)
        advanced: If true, include additional deep analysis (Cloudflare, advanced BGP, etc.)
        expert: If true, enable expert mode with custom options
        options: JSON string with expert mode options (e.g., {"geo":["ipinfo","maxmind"],"security":["abuseipdb","rbl"]})

    Returns:
        JSON with complete IP intelligence

    Advanced Mode Features:
        - Cloudflare DNS intelligence (if API key configured)
        - Enhanced BGP path analysis
        - RPKI validation
        - Additional RBL databases
        - Network topology mapping

    Expert Mode Features:
        - Customizable intelligence source selection
        - Granular control over scan components
        - Optional port scanning, traceroute, SSL checks
    """
    try:
        # Validate IP address
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address format'}), 400

        # Check for cached scan
        force_refresh = request.args.get('force_refresh', 'false').lower() == 'true'
        full_scan = request.args.get('full_scan', 'true').lower() == 'true'
        advanced = request.args.get('advanced', 'false').lower() == 'true'
        expert = request.args.get('expert', 'false').lower() == 'true'
        expert_options_str = request.args.get('options', '{}')

        # Parse expert options if provided
        expert_options = {}
        if expert and expert_options_str:
            try:
                import json as json_module
                expert_options = json_module.loads(expert_options_str)
            except:
                expert_options = {}

        if not force_refresh and not advanced:
            cached_scan = db.get_latest_ip_scan(ip, max_age_hours=24)
            if cached_scan:
                # Remove database-specific fields
                cached_scan.pop('id', None)
                cached_scan.pop('scan_timestamp', None)
                return jsonify(cached_scan)

        # Perform fresh scan
        scan_result = ip_engine.scan_ip(ip, full_scan=full_scan)

        # Add advanced features if requested
        if advanced:
            scan_result['scan_mode'] = 'advanced'
            # The advanced features are already included in full_scan mode
            # But we can add a flag to indicate this was an advanced scan
            scan_result['advanced_features'] = {
                'cloudflare_enabled': bool(os.getenv('CLOUDFLARE_API_TOKEN')),
                'ipinfo_privacy_detection': bool(os.getenv('IPINFO_TOKEN')),
                'abuseipdb_threat_intel': bool(os.getenv('ABUSEIPDB_API_KEY')),
                'bgp_analysis': True,
                'rbl_comprehensive': True
            }

        # Save to database
        try:
            db.save_ip_scan(ip, scan_result)
        except Exception as db_error:
            # Log but don't fail the request
            app.logger.error(f"Failed to save IP scan: {db_error}")

        return jsonify(scan_result)

    except Exception as e:
        app.logger.error(f"IP scan error: {str(e)}")
        return jsonify({'error': str(e), 'ip': ip}), 500


@app.route('/api/ip/<ip>/history', methods=['GET'])
def get_ip_scan_history(ip):
    """
    Get scan history for an IP address

    GET /api/ip/<ip>/history

    Query Parameters:
        limit: Maximum results to return (default: 10)

    Returns:
        JSON array of historical scans
    """
    try:
        # Validate IP address
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address format'}), 400

        limit = int(request.args.get('limit', 10))
        limit = min(limit, 100)  # Cap at 100

        history = db.get_ip_scan_history(ip, limit=limit)

        return jsonify({
            'ip': ip,
            'count': len(history),
            'history': history
        })

    except Exception as e:
        return jsonify({'error': str(e), 'ip': ip}), 500


@app.route('/api/global-lookup', methods=['POST'])
def global_dns_lookup():
    """
    Perform DNS lookups from multiple global locations using parallel queries

    POST /api/global-lookup
    Body: {"query": "example.com", "location": "US", "limit": 50}

    Returns:
        JSON with lookup results from global DNS resolvers
    """
    try:
        data = request.get_json()

        if not data or 'query' not in data:
            return jsonify({'error': 'Query (domain or IP) is required'}), 400

        query = data['query'].strip()
        location_filter = data.get('location', '').strip()
        limit = data.get('limit', 50)

        if not query:
            return jsonify({'error': 'Invalid query'}), 400

        # Load DNS resolvers from data file
        resolvers_file = os.path.join(os.path.dirname(__file__), 'data', 'dns_resolvers.json')

        if not os.path.exists(resolvers_file):
            return jsonify({'error': 'DNS resolvers configuration not found'}), 500

        with open(resolvers_file, 'r') as f:
            resolvers_data = json.load(f)

        resolvers = resolvers_data.get('resolvers', [])

        # Filter by location if specified
        if location_filter:
            resolvers = [r for r in resolvers if r.get('country_code') == location_filter]

        if not resolvers:
            return jsonify({'error': 'No resolvers found for specified location'}), 404

        # Apply user-specified limit (0 means all)
        if limit > 0:
            resolvers = resolvers[:limit]

        # Determine if this is a reverse lookup (IP address)
        import ipaddress
        is_reverse_lookup = False
        try:
            ipaddress.ip_address(query)
            is_reverse_lookup = True
        except ValueError:
            pass

        # Perform DNS lookups in parallel using ThreadPoolExecutor
        import dns.resolver
        import dns.reversename
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def query_resolver(resolver_info):
            """Query a single DNS resolver with retry logic"""
            resolver_ip = resolver_info.get('ip')
            country = resolver_info.get('country', 'Unknown')
            city = resolver_info.get('city', 'Unknown')
            provider = resolver_info.get('provider', 'Unknown')

            # Retry configuration
            max_retries = 2
            base_timeout = 5  # seconds

            for attempt in range(max_retries + 1):
                try:
                    # Create DNS resolver
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]

                    # Increase timeout with each retry (5s, 7s, 10s)
                    current_timeout = base_timeout + (attempt * 2)
                    resolver.timeout = current_timeout
                    resolver.lifetime = current_timeout

                    start_time = time.time()

                    if is_reverse_lookup:
                        # Reverse DNS lookup
                        rev_name = dns.reversename.from_address(query)
                        answers = resolver.resolve(rev_name, 'PTR')
                        result_str = ', '.join([str(rdata) for rdata in answers])
                    else:
                        # Forward DNS lookup (A record)
                        answers = resolver.resolve(query, 'A')
                        result_str = ', '.join([str(rdata) for rdata in answers])

                    response_time = round((time.time() - start_time) * 1000, 2)  # ms

                    return {
                        'country': country,
                        'city': city,
                        'resolver': f"{provider} ({resolver_ip})",
                        'query': query,
                        'result': result_str,
                        'response_time': f"{response_time}ms" + (f" (retry {attempt})" if attempt > 0 else "")
                    }

                except dns.exception.Timeout:
                    # If this is not the last retry, wait before trying again
                    if attempt < max_retries:
                        time.sleep(0.5 * (attempt + 1))  # Exponential backoff: 0.5s, 1s
                        continue

                    # Final timeout after all retries
                    return {
                        'country': country,
                        'city': city,
                        'resolver': f"{provider} ({resolver_ip})",
                        'query': query,
                        'result': 'Timeout (after 3 attempts)',
                        'response_time': 'N/A'
                    }

                except dns.resolver.NXDOMAIN:
                    # Domain doesn't exist - no need to retry
                    return {
                        'country': country,
                        'city': city,
                        'resolver': f"{provider} ({resolver_ip})",
                        'query': query,
                        'result': 'NXDOMAIN',
                        'response_time': 'N/A'
                    }

                except dns.resolver.NoAnswer:
                    # DNS server responded but has no answer for this query type
                    return {
                        'country': country,
                        'city': city,
                        'resolver': f"{provider} ({resolver_ip})",
                        'query': query,
                        'result': 'No Answer',
                        'response_time': 'N/A'
                    }

                except Exception as e:
                    # Other errors - no retry
                    return {
                        'country': country,
                        'city': city,
                        'resolver': f"{provider} ({resolver_ip})",
                        'query': query,
                        'result': f'Error: {str(e)[:50]}',
                        'response_time': 'N/A'
                    }

        # Execute queries in parallel
        # Limit concurrent queries to avoid overwhelming network
        max_workers = min(30, len(resolvers))
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_resolver = {executor.submit(query_resolver, r): r for r in resolvers}

            for future in as_completed(future_to_resolver):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    # Handle any unexpected errors
                    pass

        # Save lookup to history table for drift tracking
        try:
            conn = db.get_connection()
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO global_lookup_history
                    (query, query_type, location_filter, resolvers_queried, results)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    query,
                    'reverse' if is_reverse_lookup else 'forward',
                    location_filter if location_filter else None,
                    len(resolvers),
                    json.dumps(results)
                ))
                conn.commit()
            db.return_connection(conn)
        except Exception as e:
            # Log error but don't fail the request
            print(f"Failed to save lookup history: {e}")

        return jsonify({
            'query': query,
            'location': location_filter or 'Global',
            'resolvers_queried': len(resolvers),
            'results': results
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/global-lookup/history/<query>', methods=['GET'])
def get_global_lookup_history(query):
    """
    Get historical global DNS lookups for a query (last 14 days)

    GET /api/global-lookup/history/<query>

    Returns:
        JSON with historical lookups and drift analysis
    """
    try:
        conn = db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Get history records
                cursor.execute("""
                    SELECT
                        id,
                        query,
                        query_type,
                        location_filter,
                        resolvers_queried,
                        lookup_timestamp,
                        results
                    FROM global_lookup_history
                    WHERE query = %s
                    AND lookup_timestamp >= NOW() - INTERVAL '14 days'
                    ORDER BY lookup_timestamp DESC
                """, (query,))

                history = cursor.fetchall()

                # Get drift analysis using database function
                cursor.execute("SELECT * FROM get_dns_drift(%s, 14)", (query,))
                drift_data = cursor.fetchall()

                return jsonify({
                    'query': query,
                    'history': [dict(row) for row in history],
                    'drift_analysis': [dict(row) for row in drift_data]
                })
        finally:
            db.return_connection(conn)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/global-lookup/drift/<query>', methods=['GET'])
def get_global_lookup_drift(query):
    """
    Get DNS drift analysis comparing current vs historical results

    GET /api/global-lookup/drift/<query>

    Returns:
        JSON with drift detection results (added/removed IPs, change percentage)
    """
    try:
        conn = db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Call drift detection function
                cursor.execute("SELECT * FROM detect_dns_drift(%s, 0.3)", (query,))
                drift = cursor.fetchone()

                if drift:
                    return jsonify({
                        'query': query,
                        'drift_detected': drift['drift_detected'],
                        'previous_ips': drift['previous_ips'] or [],
                        'current_ips': drift['current_ips'] or [],
                        'added_ips': drift['added_ips'] or [],
                        'removed_ips': drift['removed_ips'] or [],
                        'change_percentage': round(drift['change_percentage'] * 100, 2)
                    })
                else:
                    return jsonify({
                        'query': query,
                        'drift_detected': False,
                        'message': 'Insufficient historical data for drift analysis'
                    })
        finally:
            db.return_connection(conn)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ip/<ip>/reputation', methods=['GET'])
def get_ip_reputation(ip):
    """
    Get IP reputation data only (fast check)

    GET /api/ip/<ip>/reputation

    Returns:
        JSON with reputation and threat intelligence
    """
    try:
        # Validate IP address
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address format'}), 400

        # Check cache first
        cached = db.get_latest_ip_scan(ip, max_age_hours=6)
        if cached:
            return jsonify({
                'ip': ip,
                'abuse_confidence': cached.get('abuse_confidence'),
                'total_reports': cached.get('total_reports'),
                'is_whitelisted': cached.get('is_whitelisted'),
                'threat_categories': cached.get('threat_categories'),
                'rbl_hit_count': cached.get('rbl_hit_count'),
                'blacklists': {
                    'spamhaus': cached.get('in_spamhaus'),
                    'sorbs': cached.get('in_sorbs'),
                    'barracuda': cached.get('in_barracuda'),
                    'spamcop': cached.get('in_spamcop')
                },
                'cached': True,
                'scan_timestamp': cached.get('scan_timestamp')
            })

        # Perform fresh scan (reputation only)
        scan_result = ip_engine.scan_ip(ip, full_scan=False)

        # Save to database
        try:
            db.save_ip_scan(ip, scan_result)
        except Exception:
            pass

        rep = scan_result.get('reputation', {})
        return jsonify({
            'ip': ip,
            'abuse_confidence': rep.get('abuse_confidence'),
            'total_reports': rep.get('total_reports'),
            'is_whitelisted': rep.get('is_whitelisted'),
            'threat_categories': rep.get('threat_categories'),
            'rbl_hit_count': rep.get('blacklists', {}).get('hit_count'),
            'blacklists': rep.get('blacklists', {}),
            'cached': False
        })

    except Exception as e:
        return jsonify({'error': str(e), 'ip': ip}), 500


@app.route('/api/range/<path:cidr>/scan', methods=['GET'])
def scan_ip_range(cidr):
    """
    Scan an IP range (CIDR notation)

    GET /api/range/<cidr>/scan
    Example: /api/range/8.8.8.0/28/scan

    Query Parameters:
        max_ips: Maximum IPs to scan (default: 256, max: 1024)

    Returns:
        JSON with range scan results

    Access Control:
        - Anonymous users: Limited to /24 (256 IPs) or smaller
        - Authenticated users: Can scan larger ranges up to 65536 IPs
    """
    try:
        import ipaddress

        # Validate CIDR format
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return jsonify({'error': 'Invalid CIDR format. Use format like: 192.168.1.0/24'}), 400

        # Check authentication status
        is_authenticated = 'user_id' in session

        # Apply limits based on authentication
        total_ips = network.num_addresses

        if not is_authenticated:
            # Anonymous users: /24 or smaller (256 IPs max)
            if total_ips > 256:
                return jsonify({
                    'error': 'Range too large. Anonymous users are limited to /24 (256 IPs) or smaller. Please login for larger scans.',
                    'total_ips': total_ips,
                    'max_allowed': 256,
                    'requires_auth': True
                }), 403
            max_ips = 256
        else:
            # Authenticated users: up to 65536 IPs
            max_ips = int(request.args.get('max_ips', 256))
            max_ips = min(max_ips, 65536)  # Safety limit for authenticated users

            if total_ips > max_ips:
                return jsonify({
                    'error': f'Range too large ({total_ips} IPs). Maximum allowed for authenticated users: {max_ips}',
                    'total_ips': total_ips,
                    'max_allowed': max_ips
                }), 400

        # Perform range scan
        scan_result = ip_engine.scan_ip_range(cidr, max_ips=max_ips)

        if 'error' in scan_result:
            return jsonify(scan_result), 400

        return jsonify(scan_result)

    except Exception as e:
        return jsonify({'error': str(e), 'cidr': cidr}), 500


@app.route('/api/asn/<int:asn>', methods=['GET'])
def get_asn_info(asn):
    """
    Get Autonomous System (AS) information

    GET /api/asn/<asn>

    Query Parameters:
        force_refresh: If true, fetch fresh data

    Returns:
        JSON with AS information
    """
    try:
        force_refresh = request.args.get('force_refresh', 'false').lower() == 'true'

        # Check cache
        if not force_refresh:
            cached = db.get_asn_info(asn)
            if cached:
                return jsonify(cached)

        # Fetch fresh AS info
        asn_info = ip_engine.get_asn_info(asn)

        # Save to database
        try:
            db.save_asn_info(asn, asn_info)
        except Exception:
            pass

        return jsonify(asn_info)

    except Exception as e:
        return jsonify({'error': str(e), 'asn': asn}), 500


@app.route('/api/ips/high-risk', methods=['GET'])
def get_high_risk_ips():
    """
    Get list of high-risk IPs detected

    GET /api/ips/high-risk

    Query Parameters:
        limit: Maximum results (default: 100)
        min_confidence: Minimum abuse confidence (default: 75)

    Returns:
        JSON array of high-risk IPs
    """
    try:
        limit = int(request.args.get('limit', 100))
        min_confidence = int(request.args.get('min_confidence', 75))

        limit = min(limit, 500)  # Cap at 500

        high_risk = db.get_high_risk_ips(limit=limit, min_confidence=min_confidence)

        return jsonify({
            'count': len(high_risk),
            'min_confidence': min_confidence,
            'ips': high_risk
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ip/<ip>/bgp', methods=['GET'])
def get_ip_bgp(ip):
    """
    Get BGP routing information for an IP

    GET /api/ip/<ip>/bgp

    Returns:
        JSON with BGP routing data
    """
    try:
        # Validate IP address
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address format'}), 400

        # Check for cached scan with BGP data
        cached = db.get_latest_ip_scan(ip, max_age_hours=12)
        if cached and cached.get('prefix'):
            return jsonify({
                'ip': ip,
                'prefix': cached.get('prefix'),
                'origin_asn': cached.get('origin_asn'),
                'as_path': cached.get('as_path'),
                'is_announced': cached.get('is_announced'),
                'rpki_status': cached.get('rpki_status'),
                'cached': True
            })

        # Perform fresh scan
        scan_result = ip_engine.scan_ip(ip, full_scan=True)

        bgp = scan_result.get('bgp', {})
        return jsonify({
            'ip': ip,
            'bgp': bgp,
            'cached': False
        })

    except Exception as e:
        return jsonify({'error': str(e), 'ip': ip}), 500


@app.route('/api/mtr/<target>', methods=['GET'])
def api_mtr(target):
    """
    Perform MTR (My Traceroute) to a target IP or domain

    GET /api/mtr/<target>

    Returns:
        JSON with traceroute path information
    """
    try:
        import subprocess
        import re

        # Validate target (basic validation)
        if not re.match(r'^[a-zA-Z0-9\-\.]+$', target):
            return jsonify({'error': 'Invalid target format'}), 400

        # Run mtr command (report mode, 10 cycles, no DNS for speed)
        cmd = ['mtr', '-n', '-c', '10', '--report', '--json', target]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                # Fall back to regular traceroute if mtr not available
                cmd = ['traceroute', '-n', '-m', '30', target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                # Parse traceroute output
                hops = []
                for line in result.stdout.split('\n'):
                    if not line.strip() or line.startswith('traceroute'):
                        continue

                    parts = line.strip().split()
                    if len(parts) >= 2:
                        hop_num = parts[0].rstrip('.')
                        if hop_num.isdigit():
                            ip_addr = parts[1] if parts[1] != '*' else None
                            rtt = parts[2] if len(parts) > 2 and parts[2] != '*' else None

                            hops.append({
                                'hop': int(hop_num),
                                'ip': ip_addr,
                                'rtt_ms': float(rtt.rstrip('ms')) if rtt and rtt.replace('.', '', 1).isdigit() else None
                            })

                return jsonify({
                    'target': target,
                    'hops': hops,
                    'method': 'traceroute'
                })
            else:
                # MTR succeeded, parse JSON output
                import json as json_module
                try:
                    mtr_data = json_module.loads(result.stdout)
                    hops = []

                    for hub in mtr_data.get('report', {}).get('hubs', []):
                        hops.append({
                            'hop': hub.get('count'),
                            'ip': hub.get('host'),
                            'loss_pct': hub.get('Loss%'),
                            'sent': hub.get('Snt'),
                            'last_ms': hub.get('Last'),
                            'avg_ms': hub.get('Avg'),
                            'best_ms': hub.get('Best'),
                            'worst_ms': hub.get('Wrst'),
                            'stddev_ms': hub.get('StDev')
                        })

                    return jsonify({
                        'target': target,
                        'hops': hops,
                        'method': 'mtr'
                    })
                except:
                    # Fallback to text parsing
                    hops = []
                    for line in result.stdout.split('\n'):
                        if '|--' in line or '`--' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                hop_ip = parts[1]
                                hops.append({'ip': hop_ip})

                    return jsonify({
                        'target': target,
                        'hops': hops,
                        'method': 'mtr-text'
                    })

        except subprocess.TimeoutExpired:
            return jsonify({'error': 'MTR/Traceroute timed out'}), 504

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats/charts', methods=['GET'])
def api_stats_charts():
    """
    Get comprehensive statistics for dashboard charts:
    - Domain status distribution
    - TLD distribution
    - New registrations today
    - Domains pending expiration timeline
    - Total market value
    """
    try:
        conn = db.get_connection()
        cursor = conn.cursor()

        # Global Domain Status
        cursor.execute("""
            SELECT
                CASE
                    WHEN is_active THEN 'active'
                    ELSE 'inactive'
                END as status,
                COUNT(*) as count
            FROM domains
            GROUP BY is_active
        """)
        domain_status = {row[0]: row[1] for row in cursor.fetchall()}

        # TLD Distribution (top 20)
        cursor.execute("""
            SELECT
                SUBSTRING(domain_name FROM '\.([^.]+)$') as tld,
                COUNT(*) as count
            FROM domains
            WHERE is_active = TRUE
            GROUP BY tld
            ORDER BY count DESC
            LIMIT 20
        """)
        tld_distribution = [{'tld': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Domains Added Today (discovered/added to our platform)
        # Use domains.created_at since RDAP data may be stale
        cursor.execute("""
            SELECT
                COUNT(*) FILTER (WHERE created_at::date = CURRENT_DATE) as added_today,
                COUNT(*) FILTER (WHERE created_at::date >= CURRENT_DATE - INTERVAL '7 days') as added_last_week,
                COUNT(*) FILTER (WHERE created_at::date >= CURRENT_DATE - INTERVAL '30 days') as added_last_month
            FROM domains
            WHERE is_active = TRUE
        """)
        activity_row = cursor.fetchone()
        domains_added_today = activity_row[0] or 0
        domains_added_week = activity_row[1] or 0
        domains_added_month = activity_row[2] or 0

        # Domains Pending Expiration (from RDAP expiration date)
        cursor.execute("""
            SELECT
                COUNT(DISTINCT d.id) FILTER (WHERE r.expiration_date BETWEEN NOW() AND NOW() + INTERVAL '24 hours') as h24,
                COUNT(DISTINCT d.id) FILTER (WHERE r.expiration_date BETWEEN NOW() AND NOW() + INTERVAL '48 hours') as h48,
                COUNT(DISTINCT d.id) FILTER (WHERE r.expiration_date BETWEEN NOW() AND NOW() + INTERVAL '72 hours') as h72,
                COUNT(DISTINCT d.id) FILTER (WHERE r.expiration_date BETWEEN NOW() AND NOW() + INTERVAL '120 hours') as h120,
                COUNT(DISTINCT d.id) FILTER (WHERE r.expiration_date BETWEEN NOW() AND NOW() + INTERVAL '168 hours') as h168,
                COUNT(DISTINCT d.id) FILTER (WHERE r.expiration_date BETWEEN NOW() AND NOW() + INTERVAL '336 hours') as h336,
                COUNT(DISTINCT d.id) FILTER (WHERE r.expiration_date BETWEEN NOW() AND NOW() + INTERVAL '672 hours') as h672
            FROM domains d
            JOIN rdap_domains r ON d.id = r.domain_id
            WHERE d.is_active = TRUE AND r.expiration_date IS NOT NULL
        """)
        expiration_row = cursor.fetchone()
        expiration_timeline = {
            '24h': expiration_row[0] or 0,
            '48h': expiration_row[1] or 0,
            '72h': expiration_row[2] or 0,
            '5d': expiration_row[3] or 0,
            '1w': expiration_row[4] or 0,
            '2w': expiration_row[5] or 0,
            '4w': expiration_row[6] or 0
        }

        # Total Market Value - Calculate estimated value for all domains
        # For domains with explicit valuations, use those
        # For domains without valuations, estimate based on domain characteristics
        cursor.execute("""
            WITH valued_domains AS (
                -- Domains with explicit valuations
                SELECT
                    d.id,
                    v.estimated_value_mid as value
                FROM domains d
                JOIN domain_valuations v ON d.id = v.domain_id
                WHERE d.is_active = TRUE AND v.estimated_value_mid IS NOT NULL
            ),
            unvalued_domains AS (
                -- Domains without valuations - estimate based on characteristics
                SELECT
                    d.id,
                    CASE
                        -- Premium gTLDs
                        WHEN d.domain_name ~ '\\.(com|net|org)$' THEN
                            CASE
                                WHEN LENGTH(REGEXP_REPLACE(d.domain_name, '\\.[^.]+$', '')) <= 4 THEN 5000.00
                                WHEN LENGTH(REGEXP_REPLACE(d.domain_name, '\\.[^.]+$', '')) <= 6 THEN 1500.00
                                WHEN LENGTH(REGEXP_REPLACE(d.domain_name, '\\.[^.]+$', '')) <= 8 THEN 800.00
                                ELSE 300.00
                            END
                        -- Tech TLDs
                        WHEN d.domain_name ~ '\\.(io|ai|app|dev)$' THEN
                            CASE
                                WHEN LENGTH(REGEXP_REPLACE(d.domain_name, '\\.[^.]+$', '')) <= 4 THEN 3000.00
                                WHEN LENGTH(REGEXP_REPLACE(d.domain_name, '\\.[^.]+$', '')) <= 6 THEN 1000.00
                                ELSE 400.00
                            END
                        -- Country TLDs
                        WHEN d.domain_name ~ '\\.(uk|de|ca|au)$' THEN 250.00
                        -- Other TLDs
                        ELSE 150.00
                    END as value
                FROM domains d
                LEFT JOIN domain_valuations v ON d.id = v.domain_id
                WHERE d.is_active = TRUE AND v.id IS NULL
            )
            SELECT
                COALESCE(SUM(value), 0) as total_value,
                COUNT(*) as total_domains,
                (SELECT COUNT(*) FROM valued_domains) as explicitly_valued
            FROM (
                SELECT value FROM valued_domains
                UNION ALL
                SELECT value FROM unvalued_domains
            ) all_values
        """)
        value_row = cursor.fetchone()
        total_market_value = float(value_row[0] or 0)
        total_valued = value_row[1] or 0
        explicitly_valued = value_row[2] or 0

        cursor.close()
        conn.close()

        return jsonify({
            'domain_status': domain_status,
            'tld_distribution': tld_distribution,
            'domains_added_today': domains_added_today,
            'domains_added_week': domains_added_week,
            'domains_added_month': domains_added_month,
            'expiration_timeline': expiration_timeline,
            'total_market_value': total_market_value,
            'valued_domains': total_valued,
            'explicitly_valued': explicitly_valued,
            'timestamp': db.get_current_timestamp()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats/security-glance', methods=['GET'])
def api_security_glance_stats():
    """
    Get quick glance security statistics:
    - DNSSEC enabled domains
    - DMARC configured domains
    - DANE records
    - MTA-STS enabled
    - TLSA records
    - IPs per country (GeoIP from reverse data)
    """
    try:
        conn = db.get_connection()
        cursor = conn.cursor()

        # Count domains with DNSSEC (from any scan)
        cursor.execute("""
            SELECT COUNT(DISTINCT domain_id)
            FROM scan_history
            WHERE dnssec_enabled = TRUE
        """)
        dnssec_count = cursor.fetchone()[0] or 0

        # Count domains with DMARC (from any scan)
        cursor.execute("""
            SELECT COUNT(DISTINCT domain_id)
            FROM scan_history
            WHERE dmarc_record IS NOT NULL AND dmarc_record != ''
        """)
        dmarc_count = cursor.fetchone()[0] or 0

        # Count domains with DANE/TLSA records (from dns_records table)
        cursor.execute("""
            SELECT COUNT(DISTINCT domain_id)
            FROM dns_records
            WHERE record_type = 'TLSA'
        """)
        tlsa_count = cursor.fetchone()[0] or 0
        dane_count = tlsa_count  # DANE uses TLSA records

        # Count domains with MTA-STS policy (from TXT records containing mta-sts)
        cursor.execute("""
            SELECT COUNT(DISTINCT domain_id)
            FROM dns_records
            WHERE record_type = 'TXT'
            AND record_value LIKE '%mta-sts%'
        """)
        mta_sts_count = cursor.fetchone()[0] or 0

        # Get IPs per country from PTR records (simplified - just count unique IPs for now)
        # TODO: Add GeoIP lookup in future
        cursor.execute("""
            SELECT
                'Unknown' as country,
                COUNT(DISTINCT ip_address) as ip_count
            FROM ptr_records
            LIMIT 1
        """)
        ips_by_country = [{'country': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Get total domain count for percentages
        cursor.execute("SELECT COUNT(*) FROM domains WHERE is_active = TRUE")
        total_domains = cursor.fetchone()[0] or 1

        cursor.close()
        conn.close()

        return jsonify({
            'dnssec_enabled': dnssec_count,
            'dnssec_percentage': round((dnssec_count / total_domains) * 100, 1),
            'dmarc_configured': dmarc_count,
            'dmarc_percentage': round((dmarc_count / total_domains) * 100, 1),
            'dane_enabled': dane_count,
            'dane_percentage': round((dane_count / total_domains) * 100, 1),
            'mta_sts_enabled': mta_sts_count,
            'mta_sts_percentage': round((mta_sts_count / total_domains) * 100, 1),
            'tlsa_records': tlsa_count,
            'tlsa_percentage': round((tlsa_count / total_domains) * 100, 1),
            'ips_by_country': ips_by_country,
            'total_domains': total_domains,
            'timestamp': db.get_current_timestamp()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/search/advanced', methods=['GET'])
def api_advanced_domain_search():
    """
    Advanced domain search with gTLD, ccTLD, and country filtering
    Query params: q (search term), gtld, cctld, country, page, limit
    """
    try:
        search_query = request.args.get('q', '')
        gtld = request.args.get('gtld')
        cctld = request.args.get('cctld')
        country = request.args.get('country')
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 50, type=int)
        offset = (page - 1) * limit

        conn = db.get_connection()
        cursor = conn.cursor()

        # Build dynamic query
        where_clauses = ["d.is_active = TRUE"]
        params = []

        if search_query:
            where_clauses.append("d.domain_name ILIKE %s")
            params.append(f"%{search_query}%")

        if gtld:
            where_clauses.append("d.domain_name ~ %s")
            params.append(f'\\.{gtld}$')

        if cctld:
            where_clauses.append("d.domain_name ~ %s")
            params.append(f'\\.{cctld}$')

        if country:
            where_clauses.append("r.country_code = %s")
            params.append(country.upper())

        where_sql = " AND ".join(where_clauses)

        # Get total count
        count_query = f"""
            SELECT COUNT(DISTINCT d.id)
            FROM domains d
            LEFT JOIN rdap_domains r ON d.id = r.domain_id
            WHERE {where_sql}
        """
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]

        # Get paginated results
        search_query_sql = f"""
            SELECT DISTINCT
                d.id,
                d.domain_name,
                d.last_checked,
                d.created_at,
                r.country_code,
                r.registrar_name
            FROM domains d
            LEFT JOIN rdap_domains r ON d.id = r.domain_id
            WHERE {where_sql}
            ORDER BY d.last_checked DESC NULLS LAST
            LIMIT %s OFFSET %s
        """
        cursor.execute(search_query_sql, params + [limit, offset])

        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'domain': row[1],
                'last_checked': row[2].isoformat() if row[2] else None,
                'created_at': row[3].isoformat() if row[3] else None,
                'country': row[4],
                'registrar': row[5]
            })

        cursor.close()
        conn.close()

        return jsonify({
            'results': results,
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================================
# STRIPE INTEGRATION & FREE TRIALS
# =============================================================================

@app.route('/api/checkout/create', methods=['POST'])
@login_required
def create_checkout():
    """Create Stripe checkout session"""
    from stripe_integration import StripeManager

    try:
        data = request.get_json()
        plan = data.get('plan')  # starter, professional, business, enterprise
        cycle = data.get('cycle', 'monthly')  # monthly or annual

        # Get price ID
        stripe_mgr = StripeManager()
        price_key = f"{plan}_{cycle}"
        price_id = stripe_mgr.PRICE_IDS.get(price_key)

        if not price_id:
            return jsonify({'error': 'Invalid plan or cycle'}), 400

        # Get trial days for this plan
        trial_days = stripe_mgr.TRIAL_PERIODS.get(plan)

        # Create checkout session
        result = stripe_mgr.create_checkout_session(
            user_id=session['user_id'],
            price_id=price_id,
            success_url=request.host_url + 'subscribe/success',
            cancel_url=request.host_url + 'pricing',
            trial_days=trial_days
        )

        if result['success']:
            return jsonify({
                'checkout_url': result['checkout_url'],
                'session_id': result['session_id']
            })
        else:
            return jsonify({'error': result.get('error', 'Failed to create checkout')}), 400

    except Exception as e:
        logger.error(f"Error creating checkout: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/subscription/status', methods=['GET'])
@login_required
def subscription_status():
    """Get user's subscription status"""
    from stripe_integration import StripeManager

    try:
        stripe_mgr = StripeManager()
        status = stripe_mgr.get_subscription_status(session['user_id'])
        return jsonify(status)

    except Exception as e:
        logger.error(f"Error getting subscription status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/subscription/portal', methods=['POST'])
@login_required
def customer_portal():
    """Create customer portal session"""
    from stripe_integration import StripeManager

    try:
        stripe_mgr = StripeManager()
        result = stripe_mgr.create_customer_portal_session(
            user_id=session['user_id'],
            return_url=request.host_url + 'dashboard'
        )

        if result['success']:
            return jsonify({'portal_url': result['portal_url']})
        else:
            return jsonify({'error': result.get('error', 'Failed to create portal')}), 400

    except Exception as e:
        logger.error(f"Error creating portal: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/subscription/cancel', methods=['POST'])
@login_required
def cancel_subscription():
    """Cancel user's subscription"""
    from stripe_integration import StripeManager

    try:
        data = request.get_json() or {}
        immediate = data.get('immediate', False)

        stripe_mgr = StripeManager()
        result = stripe_mgr.cancel_subscription(
            user_id=session['user_id'],
            immediate=immediate
        )

        if result['success']:
            return jsonify({'message': 'Subscription canceled'})
        else:
            return jsonify({'error': result.get('error', 'Failed to cancel')}), 400

    except Exception as e:
        logger.error(f"Error canceling subscription: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhooks"""
    from stripe_integration import StripeManager

    try:
        payload = request.data
        sig_header = request.headers.get('Stripe-Signature')

        stripe_mgr = StripeManager()
        result = stripe_mgr.handle_webhook(payload, sig_header)

        if result['success']:
            return jsonify({'received': True}), 200
        else:
            return jsonify({'error': result.get('error', 'Webhook failed')}), 400

    except Exception as e:
        logger.error(f"Error handling webhook: {e}")
        return jsonify({'error': str(e)}), 400


@app.route('/api/trial/start', methods=['POST'])
@login_required
def start_trial():
    """Start free trial"""
    from trial_manager import TrialManager

    try:
        data = request.get_json()
        plan_name = data.get('plan')  # starter, professional, business, enterprise

        if not plan_name:
            return jsonify({'error': 'Plan name required'}), 400

        trial_mgr = TrialManager()
        result = trial_mgr.start_trial(
            user_id=session['user_id'],
            plan_name=plan_name
        )

        if result['success']:
            return jsonify({
                'message': 'Trial started',
                'trial_id': result['trial_id'],
                'ends_at': result['ends_at'].isoformat(),
                'trial_days': result['trial_days']
            })
        else:
            return jsonify({'error': result.get('error', 'Failed to start trial')}), 400

    except Exception as e:
        logger.error(f"Error starting trial: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/trial/status', methods=['GET'])
@login_required
def trial_status():
    """Get trial status"""
    from trial_manager import TrialManager

    try:
        trial_mgr = TrialManager()
        status = trial_mgr.get_trial_status(session['user_id'])
        return jsonify(status)

    except Exception as e:
        logger.error(f"Error getting trial status: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# OPENSRS DOMAIN & SSL CERTIFICATE API ENDPOINTS
# ============================================================================

@app.route('/api/domains/search/public', methods=['POST'])
def search_domains_public():
    """Public domain availability search (no authentication required)"""
    try:
        from opensrs_integration import create_opensrs_client
        from config import Config
        import time

        data = request.get_json()
        if not data or 'domains' not in data:
            return jsonify({'error': 'Missing domains array'}), 400

        domains = data['domains']
        if not isinstance(domains, list) or len(domains) == 0:
            return jsonify({'error': 'Domains must be a non-empty array'}), 400

        if len(domains) > 10:  # Limit to 10 for public searches
            return jsonify({'error': 'Maximum 10 domains per public search'}), 400

        start_time = time.time()

        # Initialize OpenSRS client with credentials from config
        if not Config.OPENSRS_USERNAME or not Config.OPENSRS_API_KEY:
            # Fallback: use RDAP then WHOIS lookups if OpenSRS not configured
            logger.warning("OpenSRS credentials not configured, using RDAP/WHOIS fallback")
            import requests as fallback_requests
            import socket
            results = []
            for domain in domains:
                domain = domain.strip().lower()
                available = False

                try:
                    # Try RDAP first (modern standard)
                    tld = domain.split('.')[-1]
                    rdap_urls = {
                        'com': 'https://rdap.verisign.com/com/v1/domain/',
                        'net': 'https://rdap.verisign.com/net/v1/domain/',
                        'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
                        'io': 'https://rdap.identitydigital.services/rdap/domain/',
                        'ai': 'https://rdap.nic.ai/domain/',
                        'co': 'https://rdap.nic.co/domain/'
                    }

                    rdap_base_url = rdap_urls.get(tld)
                    if rdap_base_url:
                        try:
                            rdap_response = fallback_requests.get(
                                f"{rdap_base_url}{domain}",
                                timeout=5,
                                headers={'Accept': 'application/json'}
                            )
                            if rdap_response.status_code == 404:
                                # Domain not found = available
                                available = True
                            elif rdap_response.status_code == 200:
                                # Domain found = not available
                                available = False
                            else:
                                # Fall through to WHOIS
                                raise Exception("RDAP inconclusive")
                        except:
                            # RDAP failed, try WHOIS
                            raise Exception("RDAP failed, trying WHOIS")
                    else:
                        # No RDAP for this TLD, use WHOIS
                        raise Exception("No RDAP for TLD")

                except Exception as e:
                    # Fallback to WHOIS
                    try:
                        whois_server = f"whois.nic.{tld}"
                        if tld == 'com' or tld == 'net':
                            whois_server = "whois.verisign-grs.com"
                        elif tld == 'org':
                            whois_server = "whois.pir.org"
                        elif tld == 'io':
                            whois_server = "whois.nic.io"
                        elif tld == 'ai':
                            whois_server = "whois.nic.ai"

                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(10)
                        sock.connect((whois_server, 43))
                        sock.send(f"{domain}\r\n".encode())
                        response = b""
                        while True:
                            data = sock.recv(4096)
                            if not data:
                                break
                            response += data
                        sock.close()

                        whois_output = response.decode('utf-8', errors='ignore').lower()

                        # Check for common "not found" indicators
                        not_found_indicators = [
                            'no match',
                            'not found',
                            'no entries found',
                            'no data found',
                            'status: available',
                            'domain not found',
                            'not registered',
                            'no data was found'
                        ]

                        available = any(indicator in whois_output for indicator in not_found_indicators)
                    except Exception as whois_error:
                        logger.error(f"Both RDAP and WHOIS failed for {domain}: {whois_error}")
                        available = False  # Assume taken if we can't verify

                # Get TLD-based pricing
                tld = domain.split('.')[-1]
                price_map = {
                    'com': 12.99, 'net': 14.99, 'org': 14.99,
                    'io': 39.99, 'ai': 99.99, 'co': 29.99,
                    'app': 19.99, 'dev': 19.99
                }
                price = price_map.get(tld, 19.99)

                result = {
                    'domain': domain,
                    'available': available,
                    'is_premium': False,
                    'price': price,
                    'currency': 'USD'
                }

                # Add domain valuation/appraisal
                try:
                    valuation = valuation_engine.estimate_value(domain)
                    if valuation and valuation.get('estimated_value_mid'):
                        result['appraisal'] = {
                            'estimated_value': valuation['estimated_value_mid'],
                            'value_range': {
                                'min': valuation.get('estimated_value_low', 0),
                                'max': valuation.get('estimated_value_high', 0)
                            },
                            'confidence': valuation.get('overall_score', 0) / 100.0,
                            'factors': valuation.get('factors', {})
                        }
                except Exception as e:
                    logger.warning(f"Valuation failed for {domain}: {str(e)}")

                results.append(result)

            return jsonify({
                'success': True,
                'results': results,
                'search_time': time.time() - start_time,
                'count': len(results),
                'whois_mode': True
            })

        # Create OpenSRS client and managers
        client, domain_mgr, ssl_mgr, dns_mgr = create_opensrs_client(
            Config.OPENSRS_USERNAME,
            Config.OPENSRS_API_KEY,
            Config.OPENSRS_ENVIRONMENT
        )

        # Check availability using DomainManager
        availability_results = domain_mgr.check_availability(domains)

        results = []
        for avail in availability_results:
            result = {
                'domain': avail.domain,
                'available': avail.available,
                'is_premium': avail.is_premium,
                'price': avail.standard_price or 12.99,  # Default price if not returned
                'currency': 'USD'
            }
            if avail.error:
                result['error'] = avail.error
            if avail.is_premium and avail.premium_price:
                result['premium_price'] = avail.premium_price

            # Add domain valuation/appraisal
            try:
                valuation = valuation_engine.estimate_value(avail.domain)
                if valuation and valuation.get('estimated_value_mid'):
                    result['appraisal'] = {
                        'estimated_value': valuation['estimated_value_mid'],
                        'value_range': {
                            'min': valuation.get('estimated_value_low', 0),
                            'max': valuation.get('estimated_value_high', 0)
                        },
                        'confidence': valuation.get('overall_score', 0) / 100.0,
                        'factors': valuation.get('factors', {})
                    }
            except Exception as e:
                logger.warning(f"Valuation failed for {avail.domain}: {str(e)}")
                # Don't fail the search if valuation fails

            results.append(result)

        search_time = time.time() - start_time

        return jsonify({
            'success': True,
            'results': results,
            'search_time': round(search_time, 3),
            'count': len(results)
        })

    except Exception as e:
        logger.error(f"Public domain search error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Search failed. Please try again.'}), 500


@app.route('/api/domains/search', methods=['POST'])
@login_required
def search_domains_opensrs():
    """Search domain availability via OpenSRS (authenticated users get higher limits)"""
    try:
        from opensrs_integration import create_opensrs_client
        from config import Config
        import time

        data = request.get_json()
        if not data or 'domains' not in data:
            return jsonify({'error': 'Missing domains array'}), 400

        domains = data['domains']
        if not isinstance(domains, list) or len(domains) == 0:
            return jsonify({'error': 'Domains must be a non-empty array'}), 400

        if len(domains) > 20:
            return jsonify({'error': 'Maximum 20 domains per search'}), 400

        start_time = time.time()

        # Initialize OpenSRS client with credentials from config
        if not Config.OPENSRS_USERNAME or not Config.OPENSRS_API_KEY:
            logger.warning("OpenSRS credentials not configured, returning mock data")
            results = []
            for domain in domains:
                domain = domain.strip().lower()
                results.append({
                    'domain': domain,
                    'available': True,
                    'is_premium': False,
                    'price_1_year': 12.99,
                    'price_2_years': 24.99,
                    'price_3_years': 35.99,
                    'note': 'Demo mode - OpenSRS not configured'
                })
            return jsonify({
                'success': True,
                'results': results,
                'search_time': 0.1,
                'count': len(results),
                'demo_mode': True
            })

        # Create OpenSRS client and managers
        client, domain_mgr, ssl_mgr, dns_mgr = create_opensrs_client(
            Config.OPENSRS_USERNAME,
            Config.OPENSRS_API_KEY,
            Config.OPENSRS_ENVIRONMENT
        )

        # Check availability using DomainManager
        availability_results = domain_mgr.check_availability(domains)

        results = []
        for avail in availability_results:
            result = {
                'domain': avail.domain,
                'available': avail.available,
                'is_premium': avail.is_premium,
                'price_1_year': avail.standard_price or 12.99,
                'price_2_years': (avail.standard_price or 12.99) * 2 * 0.95,  # 5% discount for multi-year
                'price_3_years': (avail.standard_price or 12.99) * 3 * 0.90,  # 10% discount
            }
            if avail.error:
                result['error'] = avail.error
            if avail.is_premium and avail.premium_price:
                result['premium_price'] = avail.premium_price

            results.append(result)

        search_time = time.time() - start_time

        # Log to audit table if it exists
        try:
            conn = db.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO opensrs_audit_log (
                    user_id, action, resource_type, request_data,
                    response_data, status, duration_ms, ip_address
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
            """, (
                session['user_id'], 'search_domains', 'domain',
                json.dumps({'domains': domains}), json.dumps({'results': results}),
                'success', int(search_time * 1000), request.remote_addr
            ))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as log_error:
            logger.warning(f"Could not log to opensrs_audit_log: {log_error}")

        return jsonify({
            'success': True,
            'results': results,
            'search_time': round(search_time, 3),
            'count': len(results)
        })

    except Exception as e:
        logger.error(f"Domain search error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/register', methods=['POST'])
@login_required
def register_domain():
    """Register a new domain via OpenSRS"""
    try:
        from domain_payment_processor import DomainPaymentProcessor

        data = request.get_json()
        required = ['domain', 'years', 'contacts', 'payment_method']
        for field in required:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        contact_required = ['first_name', 'last_name', 'email', 'phone',
                           'address1', 'city', 'state', 'postal_code', 'country']
        for field in contact_required:
            if field not in data['contacts']:
                return jsonify({'error': f'Missing contact field: {field}'}), 400

        processor = DomainPaymentProcessor()
        result = processor.process_domain_registration(
            user_id=session['user_id'],
            domain=data['domain'],
            years=data['years'],
            contacts=data['contacts'],
            nameservers=data.get('nameservers', ['ns1.opensrs.net', 'ns2.opensrs.net']),
            auto_renew=data.get('auto_renew', True),
            whois_privacy=data.get('whois_privacy', True),
            payment_method=data['payment_method'],
            stripe_payment_method_id=data.get('stripe_payment_method_id')
        )

        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400

    except Exception as e:
        logger.error(f"Domain registration error: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/domains/list', methods=['GET'])
@login_required
def list_user_domains():
    """Get user's domain portfolio"""
    try:
        user_id = session['user_id']
        status_filter = request.args.get('status')

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Get domains
        if status_filter:
            cursor.execute("""
                SELECT
                    id, domain_name, status, registration_type,
                    registered_at, expires_at, auto_renew, whois_privacy_enabled,
                    purchase_price, currency, nameservers, notes,
                    EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
                FROM user_domains
                WHERE user_id = %s AND status = %s
                ORDER BY registered_at DESC;
            """, (user_id, status_filter))
        else:
            cursor.execute("""
                SELECT
                    id, domain_name, status, registration_type,
                    registered_at, expires_at, auto_renew, whois_privacy_enabled,
                    purchase_price, currency, nameservers, notes,
                    EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
                FROM user_domains
                WHERE user_id = %s
                ORDER BY registered_at DESC;
            """, (user_id,))

        domains = cursor.fetchall()

        # Get stats
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'active') as active,
                COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at < NOW() + INTERVAL '30 days') as expiring_soon
            FROM user_domains
            WHERE user_id = %s
        """, (user_id,))
        stats = cursor.fetchone()

        # Get SSL certificate count
        cursor.execute("""
            SELECT COUNT(*) as ssl_count
            FROM domain_ssl_certificates
            WHERE user_id = %s
        """, (user_id,))
        ssl_data = cursor.fetchone()

        cursor.close()
        conn.close()

        domains_list = []
        for domain in domains:
            domain_dict = dict(domain)
            if domain_dict.get('registered_at'):
                domain_dict['registered_at'] = domain_dict['registered_at'].isoformat()
            if domain_dict.get('expires_at'):
                domain_dict['expires_at'] = domain_dict['expires_at'].isoformat()
            if domain_dict.get('purchase_price'):
                domain_dict['purchase_price'] = float(domain_dict['purchase_price'])
            domains_list.append(domain_dict)

        return jsonify({
            'success': True,
            'domains': domains_list,
            'total': len(domains_list),
            'stats': {
                'total': stats.get('total', 0),
                'active': stats.get('active', 0),
                'expiring_soon': stats.get('expiring_soon', 0),
                'ssl_certificates': ssl_data.get('ssl_count', 0)
            }
        })

    except Exception as e:
        logger.error(f"List domains error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/<int:domain_id>/manage', methods=['POST'])
@login_required
def manage_domain(domain_id):
    """Update domain settings"""
    try:
        from opensrs_integration import OpenSRSIntegration

        data = request.get_json()
        user_id = session['user_id']

        if not data or 'action' not in data:
            return jsonify({'error': 'Missing action parameter'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT * FROM domains_owned
            WHERE id = %s AND user_id = %s;
        """, (domain_id, user_id))
        domain = cursor.fetchone()

        if not domain:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Domain not found or access denied'}), 404

        action = data['action']
        opensrs = OpenSRSIntegration()

        if action == 'update_nameservers':
            nameservers = data.get('nameservers')
            if not nameservers or len(nameservers) < 2:
                return jsonify({'error': 'At least 2 nameservers required'}), 400

            result = opensrs.update_nameservers(domain['domain_name'], nameservers)

            if result['success']:
                cursor.execute("""
                    UPDATE domains_owned
                    SET nameservers = %s, updated_at = NOW()
                    WHERE id = %s;
                """, (nameservers, domain_id))
                conn.commit()
                message = f"Nameservers updated for {domain['domain_name']}"
            else:
                cursor.close()
                conn.close()
                return jsonify({'error': result.get('error')}), 400

        elif action == 'toggle_auto_renew':
            auto_renew = data.get('auto_renew', True)
            cursor.execute("""
                UPDATE domains_owned
                SET auto_renew_enabled = %s, updated_at = NOW()
                WHERE id = %s;
            """, (auto_renew, domain_id))
            conn.commit()
            message = f"Auto-renewal {'enabled' if auto_renew else 'disabled'} for {domain['domain_name']}"

        elif action == 'toggle_whois_privacy':
            whois_privacy = data.get('whois_privacy', True)
            result = opensrs.update_whois_privacy(domain['domain_name'], whois_privacy)

            if result['success']:
                cursor.execute("""
                    UPDATE domains_owned
                    SET whois_privacy_enabled = %s, updated_at = NOW()
                    WHERE id = %s;
                """, (whois_privacy, domain_id))
                conn.commit()
                message = f"WHOIS privacy {'enabled' if whois_privacy else 'disabled'} for {domain['domain_name']}"
            else:
                cursor.close()
                conn.close()
                return jsonify({'error': result.get('error')}), 400

        else:
            cursor.close()
            conn.close()
            return jsonify({'error': f'Unknown action: {action}'}), 400

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': message
        })

    except Exception as e:
        logger.error(f"Domain management error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/checkout', methods=['POST'])
@login_required
def domain_checkout():
    """Create Stripe checkout session for domain purchases"""
    try:
        from stripe_integration import StripeManager
        import stripe

        user_id = session['user_id']
        data = request.get_json()

        if not data or 'items' not in data:
            return jsonify({'error': 'Missing items in request'}), 400

        items = data['items']
        if not items or len(items) == 0:
            return jsonify({'error': 'Cart is empty'}), 400

        # Get user info
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT email, full_name FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Initialize Stripe
        stripe_mgr = StripeManager()

        # Prepare line items for Stripe
        line_items = []
        metadata = {
            'user_id': str(user_id),
            'type': 'domain_purchase'
        }

        # Track items for metadata
        domain_list = []
        transfer_list = []
        ssl_list = []

        for idx, item in enumerate(items):
            item_type = item.get('type')
            item_name = item.get('name')
            item_price = item.get('price', 0)

            if item_type == 'domain':
                domain_list.append(item_name)
                description = f"Domain Registration: {item_name}"
            elif item_type == 'transfer':
                transfer_list.append(item_name)
                description = f"Domain Transfer: {item_name}"
            elif item_type == 'ssl':
                ssl_list.append(item.get('domain', item_name))
                ssl_type = item.get('sslType', 'standard')
                description = f"{ssl_type.upper()} SSL Certificate for {item.get('domain')}"
            else:
                description = item_name

            # Create Stripe price for this item
            line_items.append({
                'price_data': {
                    'currency': 'usd',
                    'unit_amount': int(item_price * 100),  # Convert to cents
                    'product_data': {
                        'name': description,
                        'description': description
                    }
                },
                'quantity': 1
            })

        # Add domain info to metadata
        if domain_list:
            metadata['domains'] = ','.join(domain_list)
        if transfer_list:
            metadata['transfers'] = ','.join(transfer_list)
        if ssl_list:
            metadata['ssl_domains'] = ','.join(ssl_list)

        # Create checkout session
        success_url = f"{request.host_url}registrar/success?session_id={{CHECKOUT_SESSION_ID}}"
        cancel_url = f"{request.host_url}registrar?cancelled=true"

        checkout_session = stripe.checkout.Session.create(
            customer_email=user['email'],
            mode='payment',
            payment_method_types=['card'],
            line_items=line_items,
            metadata=metadata,
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=str(user_id)
        )

        # Store checkout session info in database for later processing
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO domain_transactions
            (user_id, domain_name, transaction_type, amount, currency, payment_status, stripe_payment_intent_id, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user_id,
            ','.join(domain_list + transfer_list) if (domain_list + transfer_list) else 'multiple',
            'purchase',
            sum(item['price'] for item in items),
            'USD',
            'pending',
            checkout_session.id,
            json.dumps({'items': items, 'session_id': checkout_session.id})
        ))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'checkout_url': checkout_session.url,
            'session_id': checkout_session.id
        })

    except Exception as e:
        logger.error(f"Domain checkout error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Checkout failed. Please try again.'}), 500


# =============================================================================
# TLD PRICING AND RENEWAL APIs
# =============================================================================

@app.route('/api/domains/pricing/all', methods=['GET'])
def get_all_tld_pricing():
    """Get pricing for all available TLDs"""
    try:
        from tld_pricing_manager import TLDPricingManager
        pricing_mgr = TLDPricingManager(db)
        prices = pricing_mgr.get_all_prices()

        return jsonify({
            'success': True,
            'tlds': prices,
            'count': len(prices),
            'currency': 'USD'
        })
    except Exception as e:
        logger.error(f"Error getting TLD pricing: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/renewal/pricing', methods=['GET'])
@login_required
def get_renewal_pricing():
    """Get renewal pricing for a domain with multi-year options"""
    domain = request.args.get('domain')

    if not domain:
        return jsonify({'error': 'Domain parameter required'}), 400

    try:
        from domain_renewal_system import DomainRenewalSystem
        renewal_system = DomainRenewalSystem(db)

        # Generate pricing for 1-10 years
        pricing = {}
        for years in range(1, 11):
            price = renewal_system.get_renewal_price(domain, years)
            per_year = price / years
            savings = (renewal_system.get_renewal_price(domain, 1) * years) - price

            pricing[years] = {
                'total': round(price, 2),
                'per_year': round(per_year, 2),
                'savings': round(savings, 2) if savings > 0 else 0
            }

        return jsonify({
            'success': True,
            'domain': domain,
            'pricing': pricing,
            'currency': 'USD'
        })
    except Exception as e:
        logger.error(f"Error getting renewal pricing: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/renewal/checkout', methods=['POST'])
@login_required
def create_renewal_checkout():
    """Create Stripe checkout for domain renewal (1-10 years)"""
    try:
        user_id = session['user_id']
        data = request.get_json()

        domain = data.get('domain')
        years = data.get('years', 1)
        auto_renew = data.get('auto_renew', True)

        if not domain:
            return jsonify({'error': 'Domain required'}), 400

        # Validate years
        try:
            years = int(years)
            if years < 1 or years > 10:
                return jsonify({'error': 'Years must be between 1 and 10'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid years value'}), 400

        # Verify user owns this domain
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id FROM user_domains
            WHERE user_id = %s AND domain_name = %s
        """, (user_id, domain))

        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Domain not found or not owned by user'}), 404

        cursor.close()
        conn.close()

        # Create renewal checkout
        from domain_renewal_system import DomainRenewalSystem
        renewal_system = DomainRenewalSystem(db)

        result = renewal_system.create_renewal_checkout(
            user_id=user_id,
            domain=domain,
            years=years,
            auto_renew=auto_renew
        )

        if result.get('success'):
            return jsonify(result)
        else:
            return jsonify(result), 400

    except Exception as e:
        logger.error(f"Error creating renewal checkout: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/renewal/upcoming', methods=['GET'])
@login_required
def get_upcoming_renewals():
    """Get domains expiring soon for the current user"""
    try:
        user_id = session['user_id']
        days_ahead = request.args.get('days', 30, type=int)

        from domain_renewal_system import DomainRenewalSystem
        renewal_system = DomainRenewalSystem(db)

        renewals = renewal_system.get_upcoming_renewals(user_id, days_ahead)

        return jsonify({
            'success': True,
            'renewals': renewals,
            'count': len(renewals)
        })

    except Exception as e:
        logger.error(f"Error getting upcoming renewals: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/renewal/auto-renew', methods=['POST'])
@login_required
def toggle_auto_renew():
    """Enable/disable auto-renewal for a domain"""
    try:
        user_id = session['user_id']
        data = request.get_json()

        domain = data.get('domain')
        enabled = data.get('enabled', True)

        if not domain:
            return jsonify({'error': 'Domain required'}), 400

        # Update auto-renewal setting
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE user_domains
            SET auto_renew = %s, updated_at = NOW()
            WHERE user_id = %s AND domain_name = %s
        """, (enabled, user_id, domain))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Domain not found'}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'domain': domain,
            'auto_renew': enabled
        })

    except Exception as e:
        logger.error(f"Error toggling auto-renew: {e}")
        return jsonify({'error': str(e)}), 500


# =============================================================================
# SSL CERTIFICATE APIs
# =============================================================================

@app.route('/api/ssl/products', methods=['GET'])
def list_ssl_products():
    """List available SSL certificate products"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT
                product_code, product_name, product_type,
                retail_1_year as price_1_year,
                retail_2_years as price_2_years,
                retail_3_years as price_3_years,
                is_available
            FROM opensrs_pricing_cache
            WHERE product_type = 'ssl' AND is_available = true
            ORDER BY retail_1_year ASC;
        """)

        products = cursor.fetchall()
        cursor.close()
        conn.close()

        products_list = []
        for product in products:
            product_dict = dict(product)
            for key in ['price_1_year', 'price_2_years', 'price_3_years']:
                if product_dict.get(key):
                    product_dict[key] = float(product_dict[key])
            products_list.append(product_dict)

        return jsonify({
            'success': True,
            'products': products_list,
            'total': len(products_list)
        })

    except Exception as e:
        logger.error(f"List SSL products error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ssl/list', methods=['GET'])
@login_required
def list_user_ssl_certificates():
    """Get user's SSL certificate inventory"""
    try:
        user_id = session['user_id']
        status_filter = request.args.get('status', 'active')

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        if status_filter == 'all':
            cursor.execute("""
                SELECT
                    id, domain_name, certificate_type, product_code,
                    ordered_at, issued_at, expires_at, auto_renew_enabled,
                    validation_method, validation_status, status, purchase_price,
                    EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
                FROM ssl_certificates_owned
                WHERE user_id = %s
                ORDER BY expires_at ASC;
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT
                    id, domain_name, certificate_type, product_code,
                    ordered_at, issued_at, expires_at, auto_renew_enabled,
                    validation_method, validation_status, status, purchase_price,
                    EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
                FROM ssl_certificates_owned
                WHERE user_id = %s AND status = %s
                ORDER BY expires_at ASC;
            """, (user_id, status_filter))

        certificates = cursor.fetchall()
        cursor.close()
        conn.close()

        certificates_list = []
        for cert in certificates:
            cert_dict = dict(cert)
            for key in ['ordered_at', 'issued_at', 'expires_at']:
                if cert_dict.get(key):
                    cert_dict[key] = cert_dict[key].isoformat()
            if cert_dict.get('purchase_price'):
                cert_dict['purchase_price'] = float(cert_dict['purchase_price'])
            certificates_list.append(cert_dict)

        return jsonify({
            'success': True,
            'certificates': certificates_list,
            'total': len(certificates_list)
        })

    except Exception as e:
        logger.error(f"List SSL certificates error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/orders/history', methods=['GET'])
@login_required
def get_order_history():
    """Get user's complete order history"""
    try:
        user_id = session['user_id']
        limit = int(request.args.get('limit', 20))
        offset = int(request.args.get('offset', 0))

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT COUNT(*) as total
            FROM opensrs_orders
            WHERE user_id = %s;
        """, (user_id,))
        total = cursor.fetchone()['total']

        cursor.execute("""
            SELECT
                id, order_number, order_type, domain_name, product_type,
                years, subtotal, tax, discount, total, payment_method,
                status, error_message, created_at, completed_at
            FROM opensrs_orders
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s;
        """, (user_id, limit, offset))

        orders = cursor.fetchall()
        cursor.close()
        conn.close()

        orders_list = []
        for order in orders:
            order_dict = dict(order)
            for key in ['created_at', 'completed_at']:
                if order_dict.get(key):
                    order_dict[key] = order_dict[key].isoformat()
            for key in ['subtotal', 'tax', 'discount', 'total']:
                if order_dict.get(key):
                    order_dict[key] = float(order_dict[key])
            orders_list.append(order_dict)

        return jsonify({
            'success': True,
            'orders': orders_list,
            'total': total,
            'limit': limit,
            'offset': offset
        })

    except Exception as e:
        logger.error(f"Order history error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/webhooks/opensrs', methods=['POST'])
def opensrs_webhook():
    """Handle OpenSRS webhooks for domain/SSL status updates"""
    try:
        import hmac
        import hashlib

        signature = request.headers.get('X-OpenSRS-Signature')
        webhook_secret = os.getenv('OPENSRS_WEBHOOK_SECRET')

        if not signature or not webhook_secret:
            logger.warning("OpenSRS webhook received without proper signature")
            return jsonify({'error': 'Invalid signature'}), 401

        payload = request.get_data()
        expected_signature = hmac.new(
            webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("OpenSRS webhook signature mismatch")
            return jsonify({'error': 'Invalid signature'}), 401

        data = request.get_json()
        event = data.get('event')

        logger.info(f"OpenSRS webhook received: {event}")

        if event == 'domain.registered':
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE domains_owned
                SET status = 'active', last_synced_at = NOW()
                WHERE opensrs_order_id = %s;
            """, (data.get('order_id'),))
            conn.commit()
            cursor.close()
            conn.close()

        elif event == 'domain.expired':
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE domains_owned
                SET status = 'expired', last_synced_at = NOW()
                WHERE domain_name = %s;
            """, (data.get('domain'),))
            conn.commit()
            cursor.close()
            conn.close()

        elif event == 'ssl.issued':
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE ssl_certificates_owned
                SET status = 'active',
                    issued_at = NOW(),
                    validation_status = 'completed',
                    last_synced_at = NOW()
                WHERE opensrs_order_id = %s;
            """, (data.get('order_id'),))
            conn.commit()
            cursor.close()
            conn.close()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO opensrs_audit_log (
                action, resource_type, resource_id,
                request_data, status, created_at
            ) VALUES (%s, %s, %s, %s, %s, NOW());
        """, (
            f'webhook_{event}',
            'webhook',
            data.get('order_id'),
            json.dumps(data),
            'success'
        ))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Webhook processed'
        }), 200

    except Exception as e:
        logger.error(f"OpenSRS webhook error: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# DARK WEB DNS MONITORING API ENDPOINTS
# ============================================================================

# Initialize Dark Web Monitor
import logging
logger = logging.getLogger(__name__)

darkweb_monitor = None
try:
    from darkweb_monitor import DarkWebMonitor

    # Get database connection string from environment
    darkweb_db_string = os.getenv('DATABASE_URL', 'postgresql://localhost/dnsscience')
    darkweb_config = {
        'TOR_ENABLED': os.getenv('TOR_ENABLED', 'false').lower() == 'true',
        'TOR_SOCKS_PROXY': os.getenv('TOR_SOCKS_PROXY', 'socks5h://127.0.0.1:9050'),
        'AHMIA_API': os.getenv('AHMIA_API', 'https://ahmia.fi/api'),
        'NAMECOIN_RPC': os.getenv('NAMECOIN_RPC'),
        'HANDSHAKE_RPC': os.getenv('HANDSHAKE_RPC')
    }

    darkweb_monitor = DarkWebMonitor(darkweb_db_string, darkweb_config)
    logger.info("Dark Web Monitor initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Dark Web Monitor: {e}")
    import traceback
    traceback.print_exc()


def check_darkweb_available():
    """Check if dark web monitoring is available"""
    if darkweb_monitor is None:
        return jsonify({
            'error': 'Dark Web Monitoring service is currently unavailable',
            'message': 'The service is temporarily disabled or experiencing issues'
        }), 503
    return None


@app.route('/api/darkweb/lookup', methods=['POST'])
@optional_auth
def darkweb_lookup():
    """
    Comprehensive dark web DNS lookup

    POST /api/darkweb/lookup
    Body: {
        "domain": "example.com",
        "checks": ["onion", "i2p", "blockchain", "tor_nodes", "certificates"]
    }

    Returns: {
        "domain": "example.com",
        "has_onion": true,
        "onion": {
            "has_onion": true,
            "onion_addresses": [...]
        },
        "has_i2p": false,
        "i2p": {...},
        "blockchain_dns": {
            "has_blockchain_dns": true,
            "namecoin": {...},
            "handshake": {...}
        },
        "tor_exit_nodes": [...],
        "certificates": {...},
        "rate_limit": {
            "remaining": 2,
            "reset_at": "2025-11-14T00:00:00Z"
        }
    }
    """
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'Domain required'}), 400

        domain = data['domain']
        checks = data.get('checks', ['onion', 'i2p', 'blockchain', 'tor_nodes', 'certificates'])

        # Validate domain
        if not domain or len(domain) > 255:
            return jsonify({'error': 'Invalid domain'}), 400

        # Get user info
        user_id = g.get('user_id') if hasattr(g, 'user_id') else None
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()

        user_agent = request.headers.get('User-Agent', 'Unknown')

        # Perform comprehensive lookup
        results = darkweb_monitor.comprehensive_lookup(
            domain=domain,
            user_id=user_id,
            ip_address=ip_address,
            checks=checks,
            user_agent=user_agent
        )

        # Check if rate limited
        if 'error' in results and 'rate limit' in results['error'].lower():
            return jsonify(results), 429

        return jsonify(results), 200

    except Exception as e:
        logger.error(f"Dark web lookup error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/onion/<domain>', methods=['GET'])
@optional_auth
def check_onion_alternative(domain):
    """
    Check if a domain has a .onion alternative

    GET /api/darkweb/onion/example.com

    Returns: {
        "has_onion": true,
        "onion_addresses": [
            {
                "address": "exampleabcd.onion",
                "version": 3,
                "verified": true,
                "active": true,
                "last_seen": "2025-11-13T10:00:00Z"
            }
        ]
    }
    """
    try:
        # Get user info for rate limiting
        user_id = g.get('user_id') if hasattr(g, 'user_id') else None
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()

        # Check rate limit
        rate_limit = darkweb_monitor.check_rate_limit(user_id, ip_address)
        if not rate_limit['allowed']:
            return jsonify({
                'error': 'Rate limit exceeded',
                'rate_limit': rate_limit
            }), 429

        # Perform lookup
        result = darkweb_monitor.check_onion_alternative(domain)

        # Log the lookup
        darkweb_monitor.log_lookup(
            user_id, ip_address, domain, 'onion',
            result, 0, request.headers.get('User-Agent')
        )

        # Add rate limit info
        rate_limit['remaining'] -= 1
        result['rate_limit'] = rate_limit

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Onion lookup error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/i2p/<domain>', methods=['GET'])
@optional_auth
def check_i2p_alternative(domain):
    """
    Check if a domain has a .i2p alternative

    GET /api/darkweb/i2p/example.com
    """
    try:
        # Get user info for rate limiting
        user_id = g.get('user_id') if hasattr(g, 'user_id') else None
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()

        # Check rate limit
        rate_limit = darkweb_monitor.check_rate_limit(user_id, ip_address)
        if not rate_limit['allowed']:
            return jsonify({
                'error': 'Rate limit exceeded',
                'rate_limit': rate_limit
            }), 429

        # Perform lookup
        result = darkweb_monitor.check_i2p_alternative(domain)

        # Log the lookup
        darkweb_monitor.log_lookup(
            user_id, ip_address, domain, 'i2p',
            result, 0, request.headers.get('User-Agent')
        )

        # Add rate limit info
        rate_limit['remaining'] -= 1
        result['rate_limit'] = rate_limit

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"I2P lookup error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/blockchain/<domain>', methods=['GET'])
@optional_auth
def check_blockchain_dns(domain):
    """
    Check for blockchain DNS registrations (.bit, .hns, .eth, etc.)

    GET /api/darkweb/blockchain/example

    Returns: {
        "has_blockchain_dns": true,
        "namecoin": {...},
        "handshake": {...},
        "ens": {...},
        "unstoppable": {...}
    }
    """
    try:
        # Get user info for rate limiting
        user_id = g.get('user_id') if hasattr(g, 'user_id') else None
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()

        # Check rate limit
        rate_limit = darkweb_monitor.check_rate_limit(user_id, ip_address)
        if not rate_limit['allowed']:
            return jsonify({
                'error': 'Rate limit exceeded',
                'rate_limit': rate_limit
            }), 429

        # Perform lookup
        result = darkweb_monitor.check_blockchain_dns(domain)

        # Log the lookup
        darkweb_monitor.log_lookup(
            user_id, ip_address, domain, 'blockchain',
            result, 0, request.headers.get('User-Agent')
        )

        # Add rate limit info
        rate_limit['remaining'] -= 1
        result['rate_limit'] = rate_limit

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Blockchain DNS lookup error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/tor-exit/<ip>', methods=['GET'])
@optional_auth
def check_tor_exit_node(ip):
    """
    Check if an IP address is a Tor exit node

    GET /api/darkweb/tor-exit/1.2.3.4

    Returns: {
        "is_tor_exit": true,
        "details": {
            "fingerprint": "...",
            "nickname": "...",
            "country": "DE",
            "bandwidth_class": "high"
        }
    }
    """
    try:
        # Validate IP address
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address'}), 400

        # Get user info for rate limiting
        user_id = g.get('user_id') if hasattr(g, 'user_id') else None
        request_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in request_ip:
            request_ip = request_ip.split(',')[0].strip()

        # Check rate limit
        rate_limit = darkweb_monitor.check_rate_limit(user_id, request_ip)
        if not rate_limit['allowed']:
            return jsonify({
                'error': 'Rate limit exceeded',
                'rate_limit': rate_limit
            }), 429

        # Perform lookup
        result = darkweb_monitor.is_tor_exit_node(ip)

        # Log the lookup
        darkweb_monitor.log_lookup(
            user_id, request_ip, ip, 'tor_exit',
            result, 0, request.headers.get('User-Agent')
        )

        # Add rate limit info
        rate_limit['remaining'] -= 1
        result['rate_limit'] = rate_limit

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Tor exit check error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/certificates/<domain>', methods=['GET'])
@optional_auth
def analyze_dark_certificates(domain):
    """
    Analyze certificates for dark web indicators

    GET /api/darkweb/certificates/example.com

    Returns: {
        "certificates": [...],
        "hidden_service_indicators": false,
        "anomalies": [...],
        "risk_score": 15
    }
    """
    try:
        # Get user info for rate limiting
        user_id = g.get('user_id') if hasattr(g, 'user_id') else None
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()

        # Check rate limit
        rate_limit = darkweb_monitor.check_rate_limit(user_id, ip_address)
        if not rate_limit['allowed']:
            return jsonify({
                'error': 'Rate limit exceeded',
                'rate_limit': rate_limit
            }), 429

        # Perform analysis
        result = darkweb_monitor.analyze_dark_certificates(domain)

        # Log the lookup
        darkweb_monitor.log_lookup(
            user_id, ip_address, domain, 'certificate',
            result, 0, request.headers.get('User-Agent')
        )

        # Add rate limit info
        rate_limit['remaining'] -= 1
        result['rate_limit'] = rate_limit

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Certificate analysis error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/tor-exits', methods=['GET'])
@optional_auth
def get_tor_exits():
    """
    Get list of known Tor exit nodes

    GET /api/darkweb/tor-exits?country=DE&limit=100

    Returns: {
        "count": 50,
        "exits": [
            {
                "ip": "1.2.3.4",
                "fingerprint": "...",
                "nickname": "...",
                "country": "DE",
                "bandwidth_class": "high"
            }
        ]
    }
    """
    try:
        # Get filters
        country = request.args.get('country')
        bandwidth_class = request.args.get('bandwidth')
        limit = min(int(request.args.get('limit', 100)), 1000)
        offset = int(request.args.get('offset', 0))

        # Build query
        conn = db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                where_parts = ["is_active = TRUE"]
                params = []

                if country:
                    where_parts.append("country_code = %s")
                    params.append(country.upper())

                if bandwidth_class:
                    where_parts.append("bandwidth_class = %s")
                    params.append(bandwidth_class)

                where_clause = " AND ".join(where_parts)

                # Get total count
                cursor.execute(f"""
                    SELECT COUNT(*) as total
                    FROM tor_exit_nodes
                    WHERE {where_clause}
                """, params)
                total = cursor.fetchone()['total']

                # Get exits
                cursor.execute(f"""
                    SELECT
                        ip_address,
                        fingerprint,
                        nickname,
                        country_code,
                        country_name,
                        bandwidth_class,
                        allows_http,
                        allows_https,
                        last_seen
                    FROM tor_exit_nodes
                    WHERE {where_clause}
                    ORDER BY bandwidth_bytes DESC
                    LIMIT %s OFFSET %s
                """, params + [limit, offset])

                exits = [dict(row) for row in cursor.fetchall()]

                # Format dates
                for exit_node in exits:
                    if exit_node.get('last_seen'):
                        exit_node['last_seen'] = exit_node['last_seen'].isoformat()

                return jsonify({
                    'count': len(exits),
                    'total': total,
                    'exits': exits,
                    'limit': limit,
                    'offset': offset
                }), 200
        finally:
            db.return_connection(conn)

    except Exception as e:
        logger.error(f"Tor exits list error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/stats', methods=['GET'])
def darkweb_statistics():
    """
    Get dark web monitoring statistics

    GET /api/darkweb/stats

    Returns: {
        "active_onion_addresses": 1234,
        "active_i2p_addresses": 567,
        "active_tor_exits": 890,
        "verified_blockchain_domains": 345,
        "last_24h_lookups": {...},
        "top_tor_exit_countries": [...]
    }
    """
    try:
        stats = darkweb_monitor.get_darkweb_statistics()
        return jsonify(stats), 200

    except Exception as e:
        logger.error(f"Dark web stats error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/history', methods=['GET'])
@login_required
def darkweb_lookup_history():
    """
    Get user's dark web lookup history

    GET /api/darkweb/history?limit=50

    Returns: {
        "count": 10,
        "history": [
            {
                "lookup_id": "...",
                "domain": "example.com",
                "lookup_type": "comprehensive",
                "has_onion": true,
                "created_at": "..."
            }
        ]
    }
    """
    try:
        user_id = g.get('user_id')
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401

        limit = min(int(request.args.get('limit', 50)), 500)

        history = darkweb_monitor.get_user_lookup_history(user_id, limit)

        # Format dates
        for item in history:
            if item.get('created_at'):
                item['created_at'] = item['created_at'].isoformat()

        return jsonify({
            'count': len(history),
            'history': history
        }), 200

    except Exception as e:
        logger.error(f"Lookup history error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/verify-onion', methods=['POST'])
@login_required
def verify_onion_service():
    """
    Verify if an onion service is reachable (requires Tor)

    POST /api/darkweb/verify-onion
    Body: {
        "onion_address": "exampleabcd.onion"
    }

    Returns: {
        "reachable": true,
        "response_time_ms": 1234,
        "error": null
    }
    """
    try:
        data = request.get_json()
        if not data or 'onion_address' not in data:
            return jsonify({'error': 'onion_address required'}), 400

        onion_address = data['onion_address']

        # Validate onion address format
        from darkweb_monitor import validate_onion_address
        if not validate_onion_address(onion_address):
            return jsonify({'error': 'Invalid .onion address format'}), 400

        # Perform verification
        result = darkweb_monitor.verify_onion_service(onion_address)

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Onion verification error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/darkweb/rate-limit', methods=['GET'])
@optional_auth
def check_darkweb_rate_limit():
    """
    Check current rate limit status

    GET /api/darkweb/rate-limit

    Returns: {
        "allowed": true,
        "remaining": 3,
        "reset_at": "2025-11-14T00:00:00Z",
        "tier": "free",
        "limit": 5
    }
    """
    try:
        # Get user info
        user_id = g.get('user_id') if hasattr(g, 'user_id') else None
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()

        # Check rate limit (without incrementing)
        rate_limit = darkweb_monitor.check_rate_limit(user_id, ip_address)

        return jsonify(rate_limit), 200

    except Exception as e:
        logger.error(f"Rate limit check error: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# END DARK WEB DNS MONITORING API ENDPOINTS
# ============================================================================


# ============================================================================
# DOMAIN ACQUISITION & MARKETPLACE API ENDPOINTS
# ============================================================================

# Import and register domain acquisition API
from domain_acquisition_api import acquisition_bp
app.register_blueprint(acquisition_bp)

# Import and register marketplace API
from domain_marketplace_api import marketplace_bp
app.register_blueprint(marketplace_bp)

# Import and register priority acquisition API
from priority_acquisition_api import priority_acquisition_bp
app.register_blueprint(priority_acquisition_bp)

# ============================================================================
# END DOMAIN ACQUISITION & MARKETPLACE API ENDPOINTS
# ============================================================================


# ============================================================================
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


if __name__ == '__main__':
    # Start WebSocket background tasks
    ws_manager.start_background_tasks()

    # Run with SocketIO support
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
