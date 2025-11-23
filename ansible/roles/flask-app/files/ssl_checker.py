#!/usr/bin/env python3
"""
SSL/TLS Certificate Checker

Connects to various ports and extracts certificate metadata for security tracking.
Supports: HTTPS (443), SMTP (25, 587), IMAPS (993), POP3S (995), LDAPS (636)
"""
import ssl
import socket
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
import logging
from config import Config

try:
    from OpenSSL import crypto
    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False
    logger.warning("pyOpenSSL not installed. SSL certificate parsing may be limited. Install with: pip install pyopenssl")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SSLCertificateChecker:
    """Extract and analyze SSL/TLS certificates from various services"""

    # Ports to check for SSL/TLS certificates
    SSL_PORTS = {
        443: 'https',
        25: 'smtp',
        587: 'smtp-submission',
        993: 'imaps',
        995: 'pop3s',
        636: 'ldaps'
    }

    def __init__(self, timeout=10):
        self.timeout = timeout

    def get_certificate(self, hostname: str, port: int, starttls_protocol: Optional[str] = None) -> Optional[Dict]:
        """
        Retrieve SSL certificate from a specific port.

        Args:
            hostname: Domain or hostname to check
            port: Port number to connect to
            starttls_protocol: Protocol for STARTTLS (smtp, imap, pop3, ldap)

        Returns:
            Dictionary with certificate information or None if failed
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We want to get cert even if invalid

            # Handle STARTTLS for protocols that need it
            if starttls_protocol == 'smtp' and port in [25, 587]:
                # Create socket connection
                sock = socket.create_connection((hostname, port), timeout=self.timeout)
                sock = self._smtp_starttls(sock, hostname)
                # Wrap with SSL
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    if cert_der:
                        return self._parse_certificate(cert_der, cert_dict if cert_dict else {}, hostname, port)
            else:
                # Direct SSL/TLS connection (HTTPS, IMAPS, POP3S, LDAPS)
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert_dict = ssock.getpeercert()
                        if cert_der:
                            return self._parse_certificate(cert_der, cert_dict if cert_dict else {}, hostname, port)

        except socket.timeout:
            logger.debug(f"Timeout connecting to {hostname}:{port}")
        except socket.error as e:
            logger.debug(f"Socket error on {hostname}:{port}: {e}")
        except ssl.SSLError as e:
            logger.debug(f"SSL error on {hostname}:{port}: {e}")
        except Exception as e:
            logger.debug(f"Error getting certificate from {hostname}:{port}: {e}")

        return None

    def _smtp_starttls(self, sock: socket.socket, hostname: str) -> socket.socket:
        """Perform SMTP STARTTLS handshake"""
        sock.recv(1024)  # Welcome banner
        sock.send(f"EHLO {hostname}\r\n".encode())
        sock.recv(1024)  # EHLO response
        sock.send(b"STARTTLS\r\n")
        sock.recv(1024)  # STARTTLS response
        return sock

    def _imap_starttls(self, sock: socket.socket) -> socket.socket:
        """Perform IMAP STARTTLS handshake"""
        sock.recv(1024)  # Welcome banner
        sock.send(b"a001 STARTTLS\r\n")
        sock.recv(1024)  # STARTTLS response
        return sock

    def _pop3_starttls(self, sock: socket.socket) -> socket.socket:
        """Perform POP3 STLS handshake"""
        sock.recv(1024)  # Welcome banner
        sock.send(b"STLS\r\n")
        sock.recv(1024)  # STLS response
        return sock

    def _parse_certificate(self, cert_der: bytes, cert_dict: Dict, hostname: str, port: int) -> Dict:
        """
        Parse certificate data into structured format.

        Args:
            cert_der: Certificate in DER binary format
            cert_dict: Certificate dictionary from getpeercert() (may be empty)
            hostname: Hostname the cert was retrieved from
            port: Port number

        Returns:
            Structured certificate metadata
        """
        # Calculate fingerprints
        sha1_fingerprint = hashlib.sha1(cert_der).hexdigest()
        sha256_fingerprint = hashlib.sha256(cert_der).hexdigest()

        # Use pyOpenSSL if available for more reliable parsing
        if HAS_PYOPENSSL:
            return self._parse_with_pyopenssl(cert_der, hostname, port, sha1_fingerprint, sha256_fingerprint)

        # Fallback to standard library (requires cert_dict to be populated)
        if not cert_dict:
            # Minimal info if cert_dict is empty
            return {
                'hostname': hostname,
                'port': port,
                'service': self.SSL_PORTS.get(port, 'unknown'),
                'sha1_fingerprint': sha1_fingerprint,
                'sha256_fingerprint': sha256_fingerprint,
                'cert_pem': ssl.DER_cert_to_PEM_cert(cert_der),
                'subject_cn': 'Unknown (install pyopenssl)',
                'issuer_cn': 'Unknown (install pyopenssl)',
                'san': [],
                'san_count': 0
            }

        # Standard library parsing
        issuer = dict(x[0] for x in cert_dict.get('issuer', []))
        subject = dict(x[0] for x in cert_dict.get('subject', []))

        # Extract SAN (Subject Alternative Names)
        san_list = []
        if 'subjectAltName' in cert_dict:
            san_list = [name[1] for name in cert_dict['subjectAltName']]

        # Parse dates
        not_before = cert_dict.get('notBefore', '')
        not_after = cert_dict.get('notAfter', '')

        # Convert to ISO format
        not_before_dt = None
        not_after_dt = None
        try:
            if not_before:
                not_before_dt = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            if not_after:
                not_after_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
        except ValueError:
            pass

        # Calculate days until expiration
        days_until_expiry = None
        is_expired = False
        if not_after_dt:
            days_until_expiry = (not_after_dt - datetime.now()).days
            is_expired = days_until_expiry < 0

        # Extract serial number
        serial_number = cert_dict.get('serialNumber', '')

        # Extract version
        version = cert_dict.get('version', 0)

        return {
            'hostname': hostname,
            'port': port,
            'service': self.SSL_PORTS.get(port, 'unknown'),

            # Certificate identity
            'subject_cn': subject.get('commonName', ''),
            'subject_o': subject.get('organizationName', ''),
            'subject_ou': subject.get('organizationalUnitName', ''),
            'subject_c': subject.get('countryName', ''),
            'subject_st': subject.get('stateOrProvinceName', ''),
            'subject_l': subject.get('localityName', ''),

            # Issuer
            'issuer_cn': issuer.get('commonName', ''),
            'issuer_o': issuer.get('organizationName', ''),
            'issuer_c': issuer.get('countryName', ''),

            # Fingerprints
            'sha1_fingerprint': sha1_fingerprint,
            'sha256_fingerprint': sha256_fingerprint,

            # Subject Alternative Names
            'san': san_list,
            'san_count': len(san_list),

            # Validity
            'not_before': not_before_dt.isoformat() if not_before_dt else None,
            'not_after': not_after_dt.isoformat() if not_after_dt else None,
            'days_until_expiry': days_until_expiry,
            'is_expired': is_expired,

            # Other metadata
            'serial_number': serial_number,
            'version': version,

            # Certificate details
            'cert_pem': ssl.DER_cert_to_PEM_cert(cert_der),
        }

    def _parse_with_pyopenssl(self, cert_der: bytes, hostname: str, port: int,
                              sha1_fp: str, sha256_fp: str) -> Dict:
        """Parse certificate using pyOpenSSL library"""
        try:
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)

            # Extract subject
            subject = x509.get_subject()
            subject_cn = subject.CN if hasattr(subject, 'CN') else ''
            subject_o = subject.O if hasattr(subject, 'O') else ''
            subject_ou = subject.OU if hasattr(subject, 'OU') else ''
            subject_c = subject.C if hasattr(subject, 'C') else ''
            subject_st = subject.ST if hasattr(subject, 'ST') else ''
            subject_l = subject.L if hasattr(subject, 'L') else ''

            # Extract issuer
            issuer = x509.get_issuer()
            issuer_cn = issuer.CN if hasattr(issuer, 'CN') else ''
            issuer_o = issuer.O if hasattr(issuer, 'O') else ''
            issuer_c = issuer.C if hasattr(issuer, 'C') else ''

            # Extract SANs
            san_list = []
            try:
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if ext.get_short_name() == b'subjectAltName':
                        san_str = str(ext)
                        # Parse "DNS:example.com, DNS:www.example.com"
                        for san in san_str.split(','):
                            san = san.strip()
                            if san.startswith('DNS:'):
                                san_list.append(san[4:])
            except:
                pass

            # Extract dates
            not_before_str = x509.get_notBefore().decode('ascii')
            not_after_str = x509.get_notAfter().decode('ascii')

            # Parse dates (format: YYYYMMDDHHmmssZ)
            not_before_dt = datetime.strptime(not_before_str, '%Y%m%d%H%M%SZ')
            not_after_dt = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')

            # Calculate expiry
            days_until_expiry = (not_after_dt - datetime.now()).days
            is_expired = days_until_expiry < 0

            # Serial number
            serial_number = format(x509.get_serial_number(), 'X')

            # Version
            version = x509.get_version() + 1  # pyOpenSSL uses 0-indexed versions

            # Convert to PEM
            cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, x509).decode('ascii')

            return {
                'hostname': hostname,
                'port': port,
                'service': self.SSL_PORTS.get(port, 'unknown'),

                # Subject
                'subject_cn': subject_cn,
                'subject_o': subject_o,
                'subject_ou': subject_ou,
                'subject_c': subject_c,
                'subject_st': subject_st,
                'subject_l': subject_l,

                # Issuer
                'issuer_cn': issuer_cn,
                'issuer_o': issuer_o,
                'issuer_c': issuer_c,

                # Fingerprints
                'sha1_fingerprint': sha1_fp,
                'sha256_fingerprint': sha256_fp,

                # SANs
                'san': san_list,
                'san_count': len(san_list),

                # Validity
                'not_before': not_before_dt.isoformat(),
                'not_after': not_after_dt.isoformat(),
                'days_until_expiry': days_until_expiry,
                'is_expired': is_expired,

                # Metadata
                'serial_number': serial_number,
                'version': version,

                # PEM
                'cert_pem': cert_pem
            }
        except Exception as e:
            logger.error(f"Error parsing certificate with pyOpenSSL: {e}")
            # Return minimal info
            return {
                'hostname': hostname,
                'port': port,
                'service': self.SSL_PORTS.get(port, 'unknown'),
                'sha1_fingerprint': sha1_fp,
                'sha256_fingerprint': sha256_fp,
                'cert_pem': ssl.DER_cert_to_PEM_cert(cert_der),
                'error': str(e)
            }

    def check_domain(self, domain: str) -> Dict:
        """
        Check all SSL ports for a domain.

        Args:
            domain: Domain name to check

        Returns:
            Dictionary with certificates found on each port
        """
        logger.info(f"Checking SSL certificates for {domain}")

        results = {
            'domain': domain,
            'certificates': [],
            'ports_checked': list(self.SSL_PORTS.keys()),
            'ports_with_ssl': [],
            'total_certificates': 0,
            'has_expired_certs': False,
            'expiring_soon': []  # Certs expiring in < 30 days
        }

        for port, service in self.SSL_PORTS.items():
            # Determine if STARTTLS is needed
            starttls = None
            if port in [25, 587]:
                starttls = 'smtp'

            cert_info = self.get_certificate(domain, port, starttls_protocol=starttls)

            if cert_info:
                results['certificates'].append(cert_info)
                results['ports_with_ssl'].append(port)
                results['total_certificates'] += 1

                # Track expiry issues
                if cert_info.get('is_expired'):
                    results['has_expired_certs'] = True

                if cert_info.get('days_until_expiry') is not None:
                    if 0 < cert_info['days_until_expiry'] < 30:
                        results['expiring_soon'].append({
                            'port': port,
                            'days': cert_info['days_until_expiry']
                        })

        return results

    def check_certificate_chain(self, hostname: str, port: int = 443) -> Optional[Dict]:
        """
        Get full certificate chain information.

        Args:
            hostname: Domain to check
            port: Port to connect to (default 443)

        Returns:
            Certificate chain information
        """
        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get full chain
                    cert_chain = ssock.getpeercert(binary_form=False)

                    return {
                        'hostname': hostname,
                        'port': port,
                        'chain_valid': True,
                        'cert': cert_chain
                    }

        except ssl.SSLError as e:
            return {
                'hostname': hostname,
                'port': port,
                'chain_valid': False,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"Error checking certificate chain: {e}")
            return None


def main():
    """CLI for SSL certificate checking"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='SSL Certificate Checker')

    parser.add_argument('domain', help='Domain to check')
    parser.add_argument('-p', '--port', type=int, help='Specific port to check')
    parser.add_argument('--json', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    checker = SSLCertificateChecker()

    if args.port:
        # Check specific port
        cert = checker.get_certificate(args.domain, args.port)
        if args.json:
            print(json.dumps(cert, indent=2))
        else:
            if cert:
                print(f"\n📜 SSL Certificate for {args.domain}:{args.port}")
                print("=" * 70)
                print(f"Subject: {cert['subject_cn']}")
                print(f"Issuer: {cert['issuer_cn']} ({cert['issuer_o']})")
                print(f"Valid: {cert['not_before']} to {cert['not_after']}")
                print(f"SHA-256: {cert['sha256_fingerprint']}")
                if cert['san']:
                    print(f"SAN: {', '.join(cert['san'][:5])}")
                if cert['is_expired']:
                    print("⚠️  EXPIRED")
                elif cert['days_until_expiry'] and cert['days_until_expiry'] < 30:
                    print(f"⚠️  Expires in {cert['days_until_expiry']} days")
            else:
                print(f"No certificate found on {args.domain}:{args.port}")
    else:
        # Check all ports
        results = checker.check_domain(args.domain)

        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            print(f"\n📜 SSL Certificates for {args.domain}")
            print("=" * 70)
            print(f"Ports checked: {len(results['ports_checked'])}")
            print(f"Ports with SSL: {len(results['ports_with_ssl'])}")
            print(f"Total certificates: {results['total_certificates']}")

            if results['has_expired_certs']:
                print("\n⚠️  Found expired certificates!")

            if results['expiring_soon']:
                print(f"\n⚠️  {len(results['expiring_soon'])} certificate(s) expiring soon:")
                for exp in results['expiring_soon']:
                    print(f"  Port {exp['port']}: {exp['days']} days")

            print("\nCertificates Found:")
            for cert in results['certificates']:
                print(f"\n  Port {cert['port']} ({cert['service']}):")
                print(f"    Subject: {cert['subject_cn']}")
                print(f"    Issuer: {cert['issuer_cn']}")
                print(f"    Expires: {cert['not_after']}")
                if cert['san_count'] > 0:
                    print(f"    SANs: {cert['san_count']} domain(s)")


if __name__ == '__main__':
    main()
