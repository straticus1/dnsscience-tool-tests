#!/usr/bin/env python3
"""
DNS Science SSL Scout Daemon (dnsscience_sslscoutd)

A daemon that runs on internal client networks to monitor SSL certificates
and report them to DNS Science for centralized alerting and management.

Features:
- Scans internal hosts for SSL certificates
- Extracts X.509 certificate data
- Posts certificate data to DNS Science API
- Supports JSON configuration
- Configurable scan intervals
- API key authentication

Usage:
    dnsscience_sslscoutd.py --config /path/to/config.json
    dnsscience_sslscoutd.py --generate-config

Configuration file format:
{
    "api_key": "your-api-key",
    "api_endpoint": "https://www.dnsscience.io/api/sslscout/report",
    "scan_interval": 3600,
    "targets": [
        {"host": "internal-app.local", "port": 443},
        {"host": "192.168.1.100", "port": 8443},
        {"host": "10.0.0.0/24", "port": 443}
    ],
    "alert_days_before_expiry": [30, 14, 7, 1],
    "log_file": "/var/log/dnsscience_sslscout.log",
    "websocket_alerts": true
}

Copyright (c) 2025 DNS Science - After Dark Systems, LLC
"""

import argparse
import json
import logging
import os
import socket
import ssl
import sys
import time
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import hashlib
import base64

try:
    import requests
except ImportError:
    print("Error: requests library required. Install with: pip install requests")
    sys.exit(1)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization, hashes
except ImportError:
    print("Error: cryptography library required. Install with: pip install cryptography")
    sys.exit(1)

# Version
VERSION = "1.0.0"

# Default configuration
DEFAULT_CONFIG = {
    "api_key": "",
    "api_endpoint": "https://www.dnsscience.io/api/sslscout/report",
    "scan_interval": 3600,
    "targets": [],
    "alert_days_before_expiry": [30, 14, 7, 1],
    "log_file": "/var/log/dnsscience_sslscout.log",
    "websocket_alerts": True,
    "timeout": 10,
    "concurrent_scans": 10
}


class SSLScoutDaemon:
    """SSL Certificate Scanner and Reporter Daemon"""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        self._setup_logging()
        self.logger.info(f"DNS Science SSL Scout Daemon v{VERSION} initialized")

    def _load_config(self) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)

            # Merge with defaults
            merged = DEFAULT_CONFIG.copy()
            merged.update(config)
            return merged
        except FileNotFoundError:
            print(f"Error: Configuration file not found: {self.config_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in configuration file: {e}")
            sys.exit(1)

    def _setup_logging(self):
        """Configure logging"""
        log_file = self.config.get('log_file', '/var/log/dnsscience_sslscout.log')

        # Create logger
        self.logger = logging.getLogger('sslscout')
        self.logger.setLevel(logging.INFO)

        # File handler
        try:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)
        except PermissionError:
            pass  # Continue without file logging

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(ch)

    def _expand_targets(self) -> List[Dict]:
        """Expand CIDR notation in targets to individual hosts"""
        expanded = []

        for target in self.config.get('targets', []):
            host = target.get('host', '')
            port = target.get('port', 443)

            # Check if it's a CIDR notation
            if '/' in host:
                try:
                    network = ipaddress.ip_network(host, strict=False)
                    for ip in network.hosts():
                        expanded.append({'host': str(ip), 'port': port})
                except ValueError:
                    self.logger.warning(f"Invalid CIDR notation: {host}")
            else:
                expanded.append(target)

        return expanded

    def scan_certificate(self, host: str, port: int = 443) -> Optional[Dict]:
        """Scan a single host for SSL certificate"""
        timeout = self.config.get('timeout', 10)

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Allow self-signed certs

            # Connect and get certificate
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate in DER format
                    der_cert = ssock.getpeercert(binary_form=True)

                    if not der_cert:
                        return None

                    # Parse certificate using cryptography
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    # Extract certificate information
                    cert_data = self._extract_cert_info(cert, host, port)
                    cert_data['raw_certificate'] = base64.b64encode(der_cert).decode('utf-8')

                    return cert_data

        except socket.timeout:
            self.logger.debug(f"Timeout connecting to {host}:{port}")
            return None
        except socket.error as e:
            self.logger.debug(f"Socket error connecting to {host}:{port}: {e}")
            return None
        except ssl.SSLError as e:
            self.logger.debug(f"SSL error connecting to {host}:{port}: {e}")
            return None
        except Exception as e:
            self.logger.warning(f"Error scanning {host}:{port}: {e}")
            return None

    def _extract_cert_info(self, cert: x509.Certificate, host: str, port: int) -> Dict:
        """Extract relevant information from X.509 certificate"""

        # Get subject components
        subject_parts = {}
        for attribute in cert.subject:
            oid_name = attribute.oid._name
            subject_parts[oid_name] = attribute.value

        # Get issuer components
        issuer_parts = {}
        for attribute in cert.issuer:
            oid_name = attribute.oid._name
            issuer_parts[oid_name] = attribute.value

        # Get Subject Alternative Names
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append({'type': 'DNS', 'value': name.value})
                elif isinstance(name, x509.IPAddress):
                    san_list.append({'type': 'IP', 'value': str(name.value)})
        except x509.ExtensionNotFound:
            pass

        # Calculate fingerprints
        sha256_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        sha1_fingerprint = cert.fingerprint(hashes.SHA1()).hex()

        # Calculate days until expiry
        now = datetime.now(timezone.utc)
        expiry = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_until_expiry = (expiry - now).days

        # Check if self-signed
        is_self_signed = cert.issuer == cert.subject

        # Get key info
        public_key = cert.public_key()
        key_type = type(public_key).__name__.replace('_', ' ')
        key_size = getattr(public_key, 'key_size', 0)

        return {
            'scan_host': host,
            'scan_port': port,
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'subject': {
                'common_name': subject_parts.get('commonName', ''),
                'organization': subject_parts.get('organizationName', ''),
                'organizational_unit': subject_parts.get('organizationalUnitName', ''),
                'country': subject_parts.get('countryName', ''),
                'state': subject_parts.get('stateOrProvinceName', ''),
                'locality': subject_parts.get('localityName', '')
            },
            'issuer': {
                'common_name': issuer_parts.get('commonName', ''),
                'organization': issuer_parts.get('organizationName', ''),
                'country': issuer_parts.get('countryName', '')
            },
            'validity': {
                'not_before': cert.not_valid_before_utc.isoformat() + 'Z' if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat() + 'Z',
                'not_after': expiry.isoformat() + 'Z',
                'days_until_expiry': days_until_expiry,
                'is_expired': days_until_expiry < 0
            },
            'serial_number': format(cert.serial_number, 'x'),
            'version': cert.version.value,
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'fingerprints': {
                'sha256': sha256_fingerprint,
                'sha1': sha1_fingerprint
            },
            'subject_alternative_names': san_list,
            'key_info': {
                'type': key_type,
                'size': key_size
            },
            'is_self_signed': is_self_signed
        }

    def run_scan(self) -> List[Dict]:
        """Run certificate scan on all targets"""
        targets = self._expand_targets()
        results = []

        self.logger.info(f"Starting scan of {len(targets)} targets")

        for target in targets:
            host = target.get('host')
            port = target.get('port', 443)

            cert_data = self.scan_certificate(host, port)
            if cert_data:
                results.append(cert_data)

                # Log expiry warnings
                days = cert_data['validity']['days_until_expiry']
                if days < 0:
                    self.logger.error(f"EXPIRED: {host}:{port} - {cert_data['subject']['common_name']}")
                elif days <= 7:
                    self.logger.warning(f"CRITICAL: {host}:{port} expires in {days} days")
                elif days <= 30:
                    self.logger.info(f"WARNING: {host}:{port} expires in {days} days")

        self.logger.info(f"Scan complete. Found {len(results)} certificates")
        return results

    def report_to_api(self, certificates: List[Dict]) -> bool:
        """Report scanned certificates to DNS Science API"""
        api_key = self.config.get('api_key')
        endpoint = self.config.get('api_endpoint')

        if not api_key:
            self.logger.error("No API key configured")
            return False

        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': api_key,
            'User-Agent': f'DNSScience-SSLScout/{VERSION}'
        }

        payload = {
            'certificates': certificates,
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'daemon_version': VERSION,
            'websocket_alerts': self.config.get('websocket_alerts', True),
            'alert_thresholds': self.config.get('alert_days_before_expiry', [30, 14, 7, 1])
        }

        try:
            response = requests.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                self.logger.info(f"Successfully reported {len(certificates)} certificates to DNS Science")

                # Log any alerts generated
                alerts = result.get('alerts_generated', 0)
                if alerts > 0:
                    self.logger.info(f"Generated {alerts} expiry alerts")

                return True
            else:
                self.logger.error(f"API error: {response.status_code} - {response.text}")
                return False

        except requests.RequestException as e:
            self.logger.error(f"Failed to report to API: {e}")
            return False

    def run_once(self):
        """Run a single scan and report cycle"""
        certificates = self.run_scan()
        if certificates:
            self.report_to_api(certificates)

    def run_daemon(self):
        """Run as a daemon with continuous scanning"""
        interval = self.config.get('scan_interval', 3600)

        self.logger.info(f"Starting daemon mode with {interval}s interval")

        while True:
            try:
                self.run_once()
            except Exception as e:
                self.logger.error(f"Error during scan cycle: {e}")

            self.logger.info(f"Sleeping for {interval} seconds until next scan")
            time.sleep(interval)


def generate_sample_config():
    """Generate a sample configuration file"""
    sample_config = {
        "api_key": "YOUR_API_KEY_HERE",
        "api_endpoint": "https://www.dnsscience.io/api/sslscout/report",
        "scan_interval": 3600,
        "targets": [
            {"host": "internal-app.example.com", "port": 443},
            {"host": "192.168.1.100", "port": 8443},
            {"host": "mail.example.com", "port": 993},
            {"host": "ldaps.example.com", "port": 636}
        ],
        "alert_days_before_expiry": [30, 14, 7, 1],
        "log_file": "/var/log/dnsscience_sslscout.log",
        "websocket_alerts": True,
        "timeout": 10,
        "concurrent_scans": 10
    }

    print(json.dumps(sample_config, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description='DNS Science SSL Scout Daemon - Monitor internal SSL certificates',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generate sample config:
    %(prog)s --generate-config > /etc/dnsscience/sslscout.json

  Run single scan:
    %(prog)s --config /etc/dnsscience/sslscout.json --once

  Run as daemon:
    %(prog)s --config /etc/dnsscience/sslscout.json

  Scan specific host:
    %(prog)s --scan-host internal.example.com --port 443

For more information, visit: https://www.dnsscience.io/docs/sslscout
        """
    )

    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--generate-config', action='store_true', help='Generate sample configuration')
    parser.add_argument('--once', action='store_true', help='Run single scan and exit')
    parser.add_argument('--scan-host', help='Scan a single host (for testing)')
    parser.add_argument('--port', type=int, default=443, help='Port for single host scan')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    args = parser.parse_args()

    if args.generate_config:
        generate_sample_config()
        return

    if args.scan_host:
        # Quick single host scan
        daemon = SSLScoutDaemon.__new__(SSLScoutDaemon)
        daemon.config = DEFAULT_CONFIG.copy()
        daemon.logger = logging.getLogger('sslscout')
        daemon.logger.addHandler(logging.StreamHandler())
        daemon.logger.setLevel(logging.INFO)

        result = daemon.scan_certificate(args.scan_host, args.port)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print(f"Failed to scan {args.scan_host}:{args.port}")
        return

    if not args.config:
        parser.error("--config is required (or use --generate-config)")

    daemon = SSLScoutDaemon(args.config)

    if args.once:
        daemon.run_once()
    else:
        daemon.run_daemon()


if __name__ == '__main__':
    main()
