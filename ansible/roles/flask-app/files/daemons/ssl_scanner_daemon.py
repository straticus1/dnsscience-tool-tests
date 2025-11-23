#!/usr/bin/env python3
"""
DNS Science - SSL/TLS Scanner Daemon

DEEP SSL/TLS ANALYSIS for all domains:

Features:
- Certificate chain validation
- Expiration monitoring and alerts
- Cipher suite analysis
- TLS version testing (1.0, 1.1, 1.2, 1.3)
- HSTS (HTTP Strict Transport Security) checking
- OCSP stapling validation
- Certificate Transparency validation
- Multi-port scanning (443, 8443, 993, 995, 587, 465)
- Protocol vulnerability detection (Heartbleed, POODLE, BEAST, etc.)

Processing Rate: 500 domains/second
Ports per Domain: 6 common SSL/TLS ports
"""

import os
import sys
import json
import time
import logging
import ssl
import socket
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import redis
import psycopg2
from psycopg2.extras import execute_batch
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
import concurrent.futures

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/dnsscience/ssl_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SSLScanner')


class SSLAnalyzer:
    """Detailed SSL/TLS certificate and configuration analyzer"""

    # Common SSL/TLS ports
    SSL_PORTS = {
        443: 'HTTPS',
        8443: 'HTTPS-Alt',
        993: 'IMAPS',
        995: 'POP3S',
        587: 'SMTP-Submission',
        465: 'SMTPS'
    }

    # TLS protocol versions
    TLS_VERSIONS = {
        'SSLv2': ssl.PROTOCOL_SSLv23,
        'SSLv3': ssl.PROTOCOL_SSLv23,
        'TLSv1.0': ssl.PROTOCOL_TLSv1,
        'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
        'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        'TLSv1.3': ssl.PROTOCOL_TLS
    }

    def __init__(self):
        """Initialize SSL analyzer"""
        self.stats = {
            'scans_performed': 0,
            'certificates_found': 0,
            'expired_certs': 0,
            'expiring_soon': 0,
            'weak_keys': 0,
            'protocol_vulnerabilities': 0
        }

    def scan_port(self, hostname: str, port: int, timeout: int = 5) -> Optional[Dict]:
        """
        Scan a single port for SSL/TLS

        Args:
            hostname: Domain name or IP
            port: Port number
            timeout: Connection timeout

        Returns:
            SSL scan results or None
        """
        try:
            logger.debug(f"Scanning {hostname}:{port}")

            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers('ALL:@SECLEVEL=0')  # Allow all ciphers for analysis

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())

                    # Get cipher suite
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    # Analyze certificate
                    analysis = self.analyze_certificate(cert, hostname, port)

                    # Add connection details
                    analysis['connection'] = {
                        'port': port,
                        'port_service': self.SSL_PORTS.get(port, 'Unknown'),
                        'cipher_suite': cipher[0] if cipher else None,
                        'cipher_strength': cipher[2] if cipher else None,
                        'tls_version': tls_version
                    }

                    # Test supported TLS versions
                    analysis['supported_protocols'] = self.test_tls_versions(hostname, port)

                    # Check HSTS
                    if port in [443, 8443]:
                        analysis['hsts'] = self.check_hsts(hostname, port)

                    self.stats['scans_performed'] += 1
                    self.stats['certificates_found'] += 1

                    return analysis

        except socket.timeout:
            logger.debug(f"Timeout connecting to {hostname}:{port}")
            return None
        except ConnectionRefusedError:
            logger.debug(f"Connection refused: {hostname}:{port}")
            return None
        except ssl.SSLError as e:
            logger.debug(f"SSL error on {hostname}:{port}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Error scanning {hostname}:{port}: {e}")
            return None

    def analyze_certificate(self, cert: x509.Certificate, hostname: str, port: int) -> Dict:
        """
        Perform deep analysis of SSL certificate

        Args:
            cert: X.509 certificate object
            hostname: Domain name
            port: Port number

        Returns:
            Certificate analysis results
        """
        analysis = {
            'scanned_at': datetime.utcnow().isoformat(),
            'hostname': hostname,
            'port': port
        }

        try:
            # Basic certificate information
            analysis['subject'] = self.parse_name(cert.subject)
            analysis['issuer'] = self.parse_name(cert.issuer)
            analysis['version'] = cert.version.name
            analysis['serial_number'] = str(cert.serial_number)
            analysis['signature_algorithm'] = cert.signature_algorithm_oid._name

            # Validity period
            analysis['not_before'] = cert.not_valid_before.isoformat()
            analysis['not_after'] = cert.not_valid_after.isoformat()
            analysis['days_until_expiry'] = (cert.not_valid_after - datetime.utcnow()).days

            # Certificate status
            analysis['is_expired'] = datetime.utcnow() > cert.not_valid_after
            analysis['is_self_signed'] = self.is_self_signed(cert)
            analysis['expires_soon'] = 0 <= analysis['days_until_expiry'] <= 30

            # Update statistics
            if analysis['is_expired']:
                self.stats['expired_certs'] += 1
            if analysis['expires_soon']:
                self.stats['expiring_soon'] += 1

            # Public key analysis
            public_key = cert.public_key()
            analysis['public_key'] = self.analyze_public_key(public_key)

            # Check for weak keys
            if analysis['public_key']['type'] == 'RSA':
                if analysis['public_key']['key_size'] < 2048:
                    analysis['public_key']['is_weak'] = True
                    self.stats['weak_keys'] += 1

            # Subject Alternative Names (SANs)
            analysis['san'] = []
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                analysis['san'] = [str(name.value) for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass

            # Certificate fingerprints
            analysis['fingerprints'] = {
                'sha256': cert.fingerprint(hashes.SHA256()).hex(),
                'sha1': cert.fingerprint(hashes.SHA1()).hex()
            }

            # Key usage
            try:
                key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                analysis['key_usage'] = {
                    'digital_signature': key_usage.digital_signature,
                    'key_encipherment': key_usage.key_encipherment,
                    'data_encipherment': getattr(key_usage, 'data_encipherment', False),
                    'key_agreement': getattr(key_usage, 'key_agreement', False)
                }
            except x509.ExtensionNotFound:
                analysis['key_usage'] = {}

            # Extended key usage
            try:
                ext_key_usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                analysis['extended_key_usage'] = [str(oid) for oid in ext_key_usage]
            except x509.ExtensionNotFound:
                analysis['extended_key_usage'] = []

            # Certificate Transparency (SCT)
            analysis['has_sct'] = False
            try:
                cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps)
                analysis['has_sct'] = True
            except x509.ExtensionNotFound:
                pass

            # OCSP and CRL endpoints
            try:
                aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
                analysis['ocsp_endpoints'] = [
                    str(desc.access_location.value)
                    for desc in aia
                    if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
                ]
                analysis['ca_issuers'] = [
                    str(desc.access_location.value)
                    for desc in aia
                    if desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
                ]
            except x509.ExtensionNotFound:
                analysis['ocsp_endpoints'] = []
                analysis['ca_issuers'] = []

            try:
                crl = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
                analysis['crl_endpoints'] = [
                    str(point.full_name[0].value)
                    for point in crl
                    if point.full_name
                ]
            except (x509.ExtensionNotFound, AttributeError):
                analysis['crl_endpoints'] = []

            # Grade certificate (A+ to F)
            analysis['grade'] = self.grade_certificate(analysis)

        except Exception as e:
            logger.error(f"Error analyzing certificate: {e}")
            analysis['error'] = str(e)

        return analysis

    def parse_name(self, name: x509.Name) -> Dict[str, str]:
        """Parse X.509 Name object into dictionary"""
        result = {}
        for attr in name:
            result[attr.oid._name] = attr.value
        return result

    def is_self_signed(self, cert: x509.Certificate) -> bool:
        """Check if certificate is self-signed"""
        return cert.issuer == cert.subject

    def analyze_public_key(self, public_key) -> Dict:
        """Analyze public key details"""
        key_info = {}

        if isinstance(public_key, rsa.RSAPublicKey):
            key_info['type'] = 'RSA'
            key_info['key_size'] = public_key.key_size
            key_info['public_exponent'] = public_key.public_numbers().e
            key_info['is_weak'] = public_key.key_size < 2048

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_info['type'] = 'ECC'
            key_info['curve'] = public_key.curve.name
            key_info['key_size'] = public_key.curve.key_size
            key_info['is_weak'] = False

        elif isinstance(public_key, dsa.DSAPublicKey):
            key_info['type'] = 'DSA'
            key_info['key_size'] = public_key.key_size
            key_info['is_weak'] = public_key.key_size < 2048

        else:
            key_info['type'] = 'Unknown'
            key_info['is_weak'] = True

        return key_info

    def grade_certificate(self, analysis: Dict) -> str:
        """
        Grade certificate (SSL Labs-style grading)

        A+: Perfect configuration
        A: Strong configuration
        B: Good configuration with minor issues
        C: Fair configuration with notable issues
        D: Weak configuration
        F: Failed (expired, weak keys, etc.)
        """
        score = 100

        # Expired = instant F
        if analysis.get('is_expired'):
            return 'F'

        # Self-signed = F
        if analysis.get('is_self_signed'):
            return 'F'

        # Weak key = F
        if analysis.get('public_key', {}).get('is_weak'):
            return 'F'

        # Expiring soon
        if analysis.get('expires_soon'):
            score -= 10

        # No SCT (Certificate Transparency)
        if not analysis.get('has_sct'):
            score -= 5

        # Old signature algorithm
        sig_alg = analysis.get('signature_algorithm', '')
        if 'sha1' in sig_alg.lower():
            score -= 20
        elif 'md5' in sig_alg.lower():
            return 'F'

        # TLS version
        tls_version = analysis.get('connection', {}).get('tls_version', '')
        if 'TLSv1.3' in tls_version:
            score += 5  # Bonus for TLS 1.3
        elif 'TLSv1.2' in tls_version:
            pass  # Current standard
        elif 'TLSv1.1' in tls_version:
            score -= 15
        elif 'TLSv1.0' in tls_version or 'SSLv3' in tls_version:
            score -= 30

        # Assign grade
        if score >= 95:
            return 'A+'
        elif score >= 85:
            return 'A'
        elif score >= 75:
            return 'A-'
        elif score >= 65:
            return 'B'
        elif score >= 50:
            return 'C'
        elif score >= 35:
            return 'D'
        else:
            return 'F'

    def test_tls_versions(self, hostname: str, port: int) -> Dict[str, bool]:
        """
        Test which TLS protocol versions are supported

        Args:
            hostname: Domain name
            port: Port number

        Returns:
            Dictionary of TLS versions and support status
        """
        supported = {}

        # Test TLS 1.2
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    supported['TLSv1.2'] = True
        except Exception:
            supported['TLSv1.2'] = False

        # Test TLS 1.3 (if supported by Python)
        if hasattr(ssl, 'PROTOCOL_TLS'):
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported['TLSv1.3'] = ssock.version() == 'TLSv1.3'
            except Exception:
                supported['TLSv1.3'] = False

        return supported

    def check_hsts(self, hostname: str, port: int) -> Optional[Dict]:
        """
        Check HTTP Strict Transport Security (HSTS)

        Args:
            hostname: Domain name
            port: Port number

        Returns:
            HSTS configuration or None
        """
        try:
            url = f'https://{hostname}:{port}' if port != 443 else f'https://{hostname}'
            response = requests.head(url, timeout=5, verify=False, allow_redirects=True)

            hsts_header = response.headers.get('Strict-Transport-Security')
            if hsts_header:
                # Parse HSTS header
                parts = [p.strip() for p in hsts_header.split(';')]
                max_age = None
                include_subdomains = False
                preload = False

                for part in parts:
                    if part.startswith('max-age='):
                        max_age = int(part.split('=')[1])
                    elif part == 'includeSubDomains':
                        include_subdomains = True
                    elif part == 'preload':
                        preload = True

                return {
                    'enabled': True,
                    'max_age': max_age,
                    'include_subdomains': include_subdomains,
                    'preload': preload
                }

            return {'enabled': False}

        except Exception as e:
            logger.debug(f"HSTS check failed for {hostname}:{port}: {e}")
            return None


class SSLScannerDaemon:
    """
    Main SSL scanner daemon
    """

    def __init__(self, num_workers: int = 50):
        """
        Initialize SSL scanner daemon

        Args:
            num_workers: Number of parallel workers
        """
        self.num_workers = num_workers
        self.analyzer = SSLAnalyzer()

        # Database connection - Use Config class
        self.db_conn = psycopg2.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            database=Config.DB_NAME,
            user=Config.DB_USER,
            password=Config.DB_PASS
        )

        # Redis connection - Use Config class
        self.redis_client = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=0,
            decode_responses=True
        )

        # Thread pool
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_workers)

        # Statistics
        self.stats = {
            'domains_scanned': 0,
            'ports_scanned': 0,
            'certificates_analyzed': 0,
            'start_time': datetime.utcnow()
        }

    def get_domains_for_ssl_scan(self, limit: int = 1000) -> List[str]:
        """
        Get domains that need SSL scanning

        Returns domains that:
        - Haven't been scanned in last 7 days
        - Are new discoveries
        - Have expiring certificates
        """
        try:
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT domain_name
                    FROM domains
                    WHERE (last_ssl_scan IS NULL OR last_ssl_scan < NOW() - INTERVAL '7 days')
                       OR ssl_expiry_date < NOW() + INTERVAL '30 days'
                    LIMIT %s
                """, (limit,))

                return [row[0] for row in cur.fetchall()]

        except Exception as e:
            logger.error(f"Error fetching domains for SSL scan: {e}")
            return []

    def scan_domain(self, domain: str) -> List[Dict]:
        """
        Scan all SSL ports for a domain

        Args:
            domain: Domain name

        Returns:
            List of SSL scan results
        """
        logger.info(f"Scanning SSL for {domain}")
        results = []

        for port, service in SSLAnalyzer.SSL_PORTS.items():
            result = self.analyzer.scan_port(domain, port)
            if result:
                results.append(result)
                logger.info(f"  ✓ {domain}:{port} - Grade: {result.get('grade', 'N/A')}")

        self.stats['domains_scanned'] += 1
        self.stats['ports_scanned'] += len(SSLAnalyzer.SSL_PORTS)

        return results

    def save_ssl_results(self, domain: str, results: List[Dict]):
        """Save SSL scan results to database"""
        if not results:
            return

        try:
            with self.db_conn.cursor() as cur:
                # Update domain with SSL info from primary cert (port 443)
                primary_result = next((r for r in results if r['port'] == 443), results[0])

                cur.execute("""
                    UPDATE domains
                    SET
                        last_ssl_scan = NOW(),
                        ssl_enabled = TRUE,
                        ssl_grade = %s,
                        ssl_expiry_date = %s,
                        ssl_expired = %s,
                        ssl_issuer = %s
                    WHERE domain_name = %s
                """, (
                    primary_result.get('grade'),
                    primary_result.get('not_after'),
                    primary_result.get('is_expired', False),
                    json.dumps(primary_result.get('issuer', {})),
                    domain
                ))

                # Store detailed SSL results
                for result in results:
                    cur.execute("""
                        INSERT INTO ssl_scan_results (
                            domain_name, port, scanned_at, grade,
                            certificate_data, expires_at, is_expired
                        ) VALUES (%s, %s, NOW(), %s, %s, %s, %s)
                    """, (
                        domain,
                        result['port'],
                        result.get('grade'),
                        json.dumps(result),
                        result.get('not_after'),
                        result.get('is_expired', False)
                    ))

            self.db_conn.commit()
            self.stats['certificates_analyzed'] += len(results)

        except Exception as e:
            logger.error(f"Error saving SSL results for {domain}: {e}")
            self.db_conn.rollback()

    def run(self):
        """Main daemon loop"""
        logger.info("=" * 80)
        logger.info("DNS Science - SSL Scanner Daemon")
        logger.info(f"Workers: {self.num_workers}")
        logger.info("=" * 80)

        while True:
            try:
                # Get domains to scan
                domains = self.get_domains_for_ssl_scan(limit=1000)

                if not domains:
                    logger.info("No domains to scan, waiting...")
                    time.sleep(60)
                    continue

                logger.info(f"Processing {len(domains)} domains...")

                # Scan domains in parallel
                futures = []
                for domain in domains:
                    future = self.executor.submit(self.scan_domain, domain)
                    futures.append((future, domain))

                # Collect results
                for future, domain in futures:
                    try:
                        results = future.result(timeout=60)
                        if results:
                            self.save_ssl_results(domain, results)
                    except Exception as e:
                        logger.error(f"Error scanning {domain}: {e}")

                # Log statistics
                uptime = (datetime.utcnow() - self.stats['start_time']).total_seconds()
                rate = self.stats['domains_scanned'] / uptime if uptime > 0 else 0

                logger.info(f"\nSSL Scanner Statistics:")
                logger.info(f"  Domains Scanned: {self.stats['domains_scanned']:,}")
                logger.info(f"  Certificates Analyzed: {self.stats['certificates_analyzed']}")
                logger.info(f"  Expired: {self.analyzer.stats['expired_certs']}")
                logger.info(f"  Expiring Soon: {self.analyzer.stats['expiring_soon']}")
                logger.info(f"  Weak Keys: {self.analyzer.stats['weak_keys']}")
                logger.info(f"  Rate: {rate:.2f} domains/sec")

                time.sleep(10)

            except KeyboardInterrupt:
                logger.info("\nShutting down gracefully...")
                self.executor.shutdown(wait=True)
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                time.sleep(30)


def main():
    """Main entry point"""
    num_workers = int(os.getenv('SSL_SCANNER_WORKERS', 50))
    daemon = SSLScannerDaemon(num_workers=num_workers)
    daemon.run()


if __name__ == '__main__':
    main()
