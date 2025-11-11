#!/usr/bin/env python3
"""
DNSScience Utility - The World's Most Advanced DNS Analysis, Security, Testing, and Debugging Tool

Combining the power of dig, ldns, and advanced DNS security analysis into a single comprehensive utility.

Version: 3.0.0
Author: DNSScience Team
License: MIT

Features:
- All dig features (query, trace, DNSSEC validation, zone transfers)
- All ldns features (zone walking, DANE validation, EDNS testing, RRSIG analysis)
- Global resolver testing (258+ resolvers worldwide)
- DNS security analysis (hijacking detection, cache poisoning, anomaly detection)
- DoH/DoT encrypted DNS support
- Advanced analytics and visualization
- Real-time monitoring and alerting
- Historical trending and comparison
- Comprehensive logging and reporting
"""

import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.flags
import dns.edns
import dns.zone
import dns.name
import dns.dnssec
import dns.reversename
import dns.update
import dns.tsig
import dns.rcode
import dns.opcode
import argparse
import sys
import time
import json
import yaml
import csv
import socket
import ipaddress
import ssl
import base64
import hashlib
import logging
import os
import re
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Version
__version__ = '3.0.0'

# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    @staticmethod
    def disable():
        """Disable all colors"""
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.END = ''


class Logger:
    """Enhanced logging with multiple levels and outputs"""

    def __init__(self, name: str = 'dnsscience', level: str = 'INFO',
                 log_file: Optional[str] = None, console: bool = True):
        """Initialize logger"""
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.handlers = []  # Clear existing handlers

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        if console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def debug(self, msg): self.logger.debug(msg)
    def info(self, msg): self.logger.info(msg)
    def warning(self, msg): self.logger.warning(msg)
    def error(self, msg): self.logger.error(msg)
    def critical(self, msg): self.logger.critical(msg)


class Config:
    """Configuration management with file support"""

    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration"""
        self.config = {
            'timeout': 5,
            'retries': 2,
            'max_workers': 50,
            'default_nameserver': None,
            'log_level': 'INFO',
            'output_format': 'text',
            'color': True,
            'resolvers_file': 'dns_resolvers.json'
        }

        if config_file and os.path.exists(config_file):
            self.load_config(config_file)

    def load_config(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.json'):
                    loaded = json.load(f)
                elif config_file.endswith(('.yml', '.yaml')):
                    loaded = yaml.safe_load(f)
                else:
                    return
                self.config.update(loaded)
        except Exception as e:
            print(f"Warning: Failed to load config from {config_file}: {e}")

    def get(self, key: str, default=None):
        """Get configuration value"""
        return self.config.get(key, default)

    def set(self, key: str, value):
        """Set configuration value"""
        self.config[key] = value


class DNSScienceAPI:
    """DNSScience.io Platform API Integration"""

    API_BASE_URL = 'https://dnsscience.com/api'
    CONFIG_DIR = Path.home() / '.dnsscience'
    CONFIG_FILE = CONFIG_DIR / 'config.json'

    def __init__(self, api_key: Optional[str] = None, logger: Optional[Logger] = None):
        """Initialize DNSScience API client"""
        self.api_key = api_key or self._load_api_key()
        self.logger = logger or Logger()
        self.session = requests.Session()

        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json',
                'User-Agent': f'dnsscience-util/{__version__}'
            })

    def _load_api_key(self) -> Optional[str]:
        """Load API key from config file"""
        try:
            if self.CONFIG_FILE.exists():
                with open(self.CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    return config.get('api_key')
        except Exception as e:
            self.logger.debug(f"Failed to load API key: {e}")
        return None

    def _save_api_key(self, api_key: str):
        """Save API key to config file"""
        try:
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

            config = {}
            if self.CONFIG_FILE.exists():
                with open(self.CONFIG_FILE, 'r') as f:
                    config = json.load(f)

            config['api_key'] = api_key

            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)

            # Set restrictive permissions (owner read/write only)
            self.CONFIG_FILE.chmod(0o600)

            self.logger.info(f"API key saved to {self.CONFIG_FILE}")
        except Exception as e:
            self.logger.error(f"Failed to save API key: {e}")
            raise

    def _remove_api_key(self):
        """Remove API key from config file"""
        try:
            if self.CONFIG_FILE.exists():
                with open(self.CONFIG_FILE, 'r') as f:
                    config = json.load(f)

                if 'api_key' in config:
                    del config['api_key']

                    with open(self.CONFIG_FILE, 'w') as f:
                        json.dump(config, f, indent=2)

                    self.logger.info("API key removed")
        except Exception as e:
            self.logger.error(f"Failed to remove API key: {e}")
            raise

    def set_api_key(self, api_key: str):
        """Set and save API key"""
        self.api_key = api_key
        self._save_api_key(api_key)
        self.session.headers.update({'Authorization': f'Bearer {api_key}'})

    def get_api_key(self) -> Optional[str]:
        """Get current API key (masked)"""
        if self.api_key:
            # Show only first 12 and last 12 characters
            if len(self.api_key) > 24:
                return f"{self.api_key[:12]}...{self.api_key[-12:]}"
            return self.api_key[:8] + "..." + self.api_key[-4:]
        return None

    def remove_api_key(self):
        """Remove stored API key"""
        self._remove_api_key()
        self.api_key = None
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']

    def scan_domain(self, domain: str, scan_types: Optional[List[str]] = None) -> Dict:
        """
        Perform comprehensive domain security scan

        Args:
            domain: Domain to scan
            scan_types: Optional list of scan types (dnssec, spf, dkim, dmarc, mtasts, starttls, ssl)

        Returns:
            Scan results dictionary
        """
        if not self.api_key:
            raise Exception("API key required. Use 'api add-key <key>' to configure.")

        self.logger.info(f"Scanning domain: {domain}")

        payload = {'domain': domain}
        if scan_types:
            payload['scan_types'] = scan_types

        try:
            response = self.session.post(
                f"{self.API_BASE_URL}/scan",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise Exception(f"Scan failed: {str(e)}")

    def get_domain_info(self, domain: str) -> Dict:
        """Get latest scan results for domain"""
        if not self.api_key:
            raise Exception("API key required. Use 'api add-key <key>' to configure.")

        self.logger.info(f"Getting domain info: {domain}")

        try:
            response = self.session.get(
                f"{self.API_BASE_URL}/domain/{domain}",
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise Exception(f"Failed to get domain info: {str(e)}")

    def get_domain_history(self, domain: str, limit: int = 10) -> Dict:
        """Get historical scan data for domain"""
        if not self.api_key:
            raise Exception("API key required. Use 'api add-key <key>' to configure.")

        self.logger.info(f"Getting domain history: {domain}")

        try:
            response = self.session.get(
                f"{self.API_BASE_URL}/domain/{domain}/history",
                params={'limit': limit},
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise Exception(f"Failed to get domain history: {str(e)}")

    def get_domain_enrichment(self, domain: str) -> Dict:
        """
        Get complete enriched domain profile with full data enrichment

        This endpoint provides comprehensive domain intelligence including:
        - DNS records and configuration
        - WHOIS/RDAP data
        - Security posture and threats
        - SSL/TLS certificate information
        - Email security (SPF, DKIM, DMARC)
        - Reputation and risk scores
        - Historical data and changes
        - Geolocation and hosting information

        Args:
            domain: Domain name to enrich

        Returns:
            Complete enriched domain profile dictionary
        """
        if not self.api_key:
            raise Exception("API key required. Use 'api add-key <key>' to configure.")

        self.logger.info(f"Getting enriched domain profile: {domain}")

        try:
            response = self.session.get(
                f"{self.API_BASE_URL}/domain/{domain}/complete-profile",
                timeout=15
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise Exception(f"Failed to get domain enrichment: {str(e)}")

    def list_domains(self) -> Dict:
        """List all tracked domains"""
        if not self.api_key:
            raise Exception("API key required. Use 'api add-key <key>' to configure.")

        self.logger.info("Listing tracked domains")

        try:
            response = self.session.get(
                f"{self.API_BASE_URL}/domains",
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise Exception(f"Failed to list domains: {str(e)}")

    def search_domains(self, pattern: str) -> Dict:
        """Search domains by name or pattern"""
        if not self.api_key:
            raise Exception("API key required. Use 'api add-key <key>' to configure.")

        self.logger.info(f"Searching domains: {pattern}")

        try:
            response = self.session.get(
                f"{self.API_BASE_URL}/search",
                params={'q': pattern},
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise Exception(f"Search failed: {str(e)}")

    def rdap_lookup(self, domain: str) -> Dict:
        """
        Perform RDAP (Registration Data Access Protocol) lookup for domain
        Modern replacement for WHOIS

        Args:
            domain: Domain name to lookup

        Returns:
            RDAP data dictionary containing registration information
        """
        self.logger.info(f"Performing RDAP lookup for: {domain}")

        try:
            response = self.session.get(
                f"{self.API_BASE_URL}/rdap",
                params={'domain': domain},
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"RDAP lookup failed: {e}")
            raise Exception(f"RDAP lookup failed: {str(e)}")

    def web3_domain_lookup(self, domain: str) -> Dict:
        """
        Lookup Web3 domain information (.eth, .crypto, etc.)

        Args:
            domain: Web3 domain name to lookup

        Returns:
            Web3 domain data dictionary
        """
        self.logger.info(f"Performing Web3 domain lookup for: {domain}")

        try:
            response = self.session.get(
                f"{self.API_BASE_URL}/web3-domains",
                params={'domain': domain},
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Web3 domain lookup failed: {e}")
            raise Exception(f"Web3 domain lookup failed: {str(e)}")

    def test_connection(self) -> bool:
        """Test API connection and authentication"""
        try:
            response = self.session.get(
                f"{self.API_BASE_URL}/domains",
                timeout=5
            )
            return response.status_code == 200
        except:
            return False


class DNSQuery:
    """Core DNS query engine with enhanced capabilities"""

    def __init__(
        self,
        nameserver: Optional[str] = None,
        port: int = 53,
        timeout: int = 5,
        use_tcp: bool = False,
        use_edns: bool = True,
        edns_version: int = 0,
        edns_bufsize: int = 4096,
        dnssec: bool = False,
        cd_flag: bool = False,
        ad_flag: bool = False,
        source_address: Optional[str] = None,
        source_port: Optional[int] = None,
        logger: Optional[Logger] = None
    ):
        """Initialize DNS query engine"""
        self.nameserver = nameserver
        self.port = port
        self.timeout = timeout
        self.use_tcp = use_tcp
        self.use_edns = use_edns
        self.edns_version = edns_version
        self.edns_bufsize = edns_bufsize
        self.dnssec = dnssec
        self.cd_flag = cd_flag
        self.ad_flag = ad_flag
        self.source_address = source_address
        self.source_port = source_port
        self.logger = logger or Logger()

        # Statistics
        self.query_time = 0
        self.server_queried = None
        self.message_size = 0

    def query(
        self,
        qname: str,
        qtype: str = 'A',
        qclass: str = 'IN'
    ) -> Tuple[dns.message.Message, Dict[str, Any]]:
        """Perform DNS query"""
        rdclass = dns.rdataclass.from_text(qclass)
        rdtype = dns.rdatatype.from_text(qtype)

        # Build query message
        query_msg = dns.message.make_query(
            qname,
            rdtype,
            rdclass=rdclass,
            want_dnssec=self.dnssec,
            use_edns=self.use_edns,
            ednsflags=dns.flags.DO if self.dnssec else 0,
            payload=self.edns_bufsize if self.use_edns else None
        )

        # Set flags
        if self.cd_flag:
            query_msg.flags |= dns.flags.CD
        if self.ad_flag:
            query_msg.flags |= dns.flags.AD

        # Determine nameserver
        if self.nameserver:
            ns = self.nameserver
        else:
            resolver = dns.resolver.Resolver()
            ns = resolver.nameservers[0]

        self.server_queried = f"{ns}#{self.port}"

        # Perform query
        start_time = time.time()

        try:
            if self.use_tcp:
                response = dns.query.tcp(
                    query_msg,
                    ns,
                    timeout=self.timeout,
                    port=self.port,
                    source=self.source_address,
                    source_port=self.source_port
                )
            else:
                response = dns.query.udp(
                    query_msg,
                    ns,
                    timeout=self.timeout,
                    port=self.port,
                    source=self.source_address,
                    source_port=self.source_port
                )

            self.query_time = (time.time() - start_time) * 1000
            self.message_size = len(response.to_wire())

            stats = {
                'query_time': self.query_time,
                'server': self.server_queried,
                'message_size': self.message_size,
                'protocol': 'TCP' if self.use_tcp else 'UDP',
                'flags': self._parse_flags(response),
                'status': dns.rcode.to_text(response.rcode())
            }

            return response, stats

        except dns.exception.Timeout:
            raise Exception(f"Query timeout after {self.timeout}s")
        except Exception as e:
            raise Exception(f"Query failed: {str(e)}")

    def _parse_flags(self, response: dns.message.Message) -> List[str]:
        """Parse response flags"""
        flags = []
        if response.flags & dns.flags.QR: flags.append('qr')
        if response.flags & dns.flags.AA: flags.append('aa')
        if response.flags & dns.flags.TC: flags.append('tc')
        if response.flags & dns.flags.RD: flags.append('rd')
        if response.flags & dns.flags.RA: flags.append('ra')
        if response.flags & dns.flags.AD: flags.append('ad')
        if response.flags & dns.flags.CD: flags.append('cd')
        return flags


class NSECWalker:
    """NSEC/NSEC3 zone walking (ldns-walk equivalent)"""

    def __init__(self, nameserver: str, timeout: int = 5, logger: Optional[Logger] = None):
        """Initialize NSEC walker"""
        self.nameserver = nameserver
        self.timeout = timeout
        self.logger = logger or Logger()
        self.records_found = []

    def walk_nsec(self, domain: str) -> List[str]:
        """Walk NSEC chain to enumerate zone"""
        self.logger.info(f"Starting NSEC walk for {domain}")
        self.records_found = []
        visited = set()
        current = domain

        try:
            while current not in visited:
                visited.add(current)

                # Query for NSEC record
                query = DNSQuery(nameserver=self.nameserver, dnssec=True, timeout=self.timeout)

                try:
                    response, _ = query.query(current, 'A')

                    # Look for NSEC in authority section
                    next_name = None
                    for rrset in response.authority:
                        if rrset.rdtype == dns.rdatatype.NSEC:
                            for rdata in rrset:
                                self.records_found.append(str(rrset.name))
                                next_name = str(rdata.next)
                                self.logger.debug(f"Found NSEC: {rrset.name} -> {next_name}")
                                break

                    if not next_name or next_name in visited:
                        break

                    current = next_name

                    # Safety limit
                    if len(visited) > 10000:
                        self.logger.warning("NSEC walk limit reached (10000 records)")
                        break

                except Exception as e:
                    self.logger.debug(f"Error during NSEC walk: {e}")
                    break

            self.logger.info(f"NSEC walk complete: {len(self.records_found)} unique records found")
            return list(set(self.records_found))

        except Exception as e:
            self.logger.error(f"NSEC walk failed: {e}")
            return []

    def walk_nsec3(self, domain: str) -> Dict:
        """Walk NSEC3 chain (more complex due to hashing)"""
        self.logger.info(f"Starting NSEC3 walk for {domain}")
        result = {
            'domain': domain,
            'nsec3_params': None,
            'hashes_found': [],
            'estimated_zone_size': 0
        }

        try:
            # Query for NSEC3PARAM
            query = DNSQuery(nameserver=self.nameserver, dnssec=True, timeout=self.timeout)
            response, _ = query.query(domain, 'NSEC3PARAM')

            if response.answer:
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.NSEC3PARAM:
                        for rdata in rrset:
                            result['nsec3_params'] = {
                                'algorithm': rdata.algorithm,
                                'flags': rdata.flags,
                                'iterations': rdata.iterations,
                                'salt': rdata.salt.hex() if rdata.salt else ''
                            }

            # Collect NSEC3 hashes from multiple queries
            test_names = [domain, f'www.{domain}', f'mail.{domain}', f'nonexistent.{domain}']

            for test_name in test_names:
                try:
                    response, _ = query.query(test_name, 'A')
                    for rrset in response.authority:
                        if rrset.rdtype == dns.rdatatype.NSEC3:
                            hash_name = str(rrset.name).split('.')[0]
                            result['hashes_found'].append(hash_name)
                except:
                    continue

            result['hashes_found'] = list(set(result['hashes_found']))
            result['estimated_zone_size'] = len(result['hashes_found'])

            self.logger.info(f"NSEC3 analysis complete: {len(result['hashes_found'])} hashes found")
            return result

        except Exception as e:
            self.logger.error(f"NSEC3 walk failed: {e}")
            return result


class DANEValidator:
    """DANE/TLSA validation (ldns-dane equivalent)"""

    def __init__(self, timeout: int = 5, logger: Optional[Logger] = None):
        """Initialize DANE validator"""
        self.timeout = timeout
        self.logger = logger or Logger()

    def validate_tlsa(self, hostname: str, port: int = 443, protocol: str = 'tcp',
                     nameserver: Optional[str] = None) -> Dict:
        """Validate TLSA records for a service"""
        result = {
            'hostname': hostname,
            'port': port,
            'protocol': protocol,
            'tlsa_records': [],
            'cert_obtained': False,
            'validation_status': 'FAILED',
            'errors': []
        }

        try:
            # Construct TLSA query name: _port._protocol.hostname
            tlsa_name = f"_{port}._{protocol}.{hostname}"
            self.logger.info(f"Querying TLSA records for {tlsa_name}")

            # Query TLSA records
            query = DNSQuery(nameserver=nameserver, dnssec=True, timeout=self.timeout)
            response, _ = query.query(tlsa_name, 'TLSA')

            if not response.answer:
                result['errors'].append('No TLSA records found')
                return result

            # Parse TLSA records
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.TLSA:
                    for rdata in rrset:
                        tlsa_record = {
                            'usage': rdata.usage,
                            'selector': rdata.selector,
                            'mtype': rdata.mtype,
                            'cert_data': rdata.cert.hex()
                        }
                        result['tlsa_records'].append(tlsa_record)
                        self.logger.debug(f"Found TLSA: {tlsa_record}")

            # Try to get actual certificate from server
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        result['cert_obtained'] = True

                        # Validate TLSA records against certificate
                        for tlsa in result['tlsa_records']:
                            if self._validate_tlsa_record(der_cert, tlsa):
                                result['validation_status'] = 'VALID'
                                self.logger.info(f"TLSA validation successful for {hostname}")
                                break
                        else:
                            result['validation_status'] = 'INVALID'
                            result['errors'].append('Certificate does not match any TLSA record')

            except Exception as e:
                result['errors'].append(f"Certificate retrieval failed: {e}")

            return result

        except Exception as e:
            result['errors'].append(str(e))
            self.logger.error(f"DANE validation failed: {e}")
            return result

    def _validate_tlsa_record(self, cert_der: bytes, tlsa: Dict) -> bool:
        """Validate certificate against TLSA record"""
        try:
            # Usage 3 = Domain-issued certificate (most common)
            # Selector 0 = Full certificate, 1 = SubjectPublicKeyInfo
            # Matching type 0 = Exact match, 1 = SHA-256, 2 = SHA-512

            if tlsa['mtype'] == 1:  # SHA-256
                cert_hash = hashlib.sha256(cert_der).hexdigest()
            elif tlsa['mtype'] == 2:  # SHA-512
                cert_hash = hashlib.sha512(cert_der).hexdigest()
            else:  # Exact match
                cert_hash = cert_der.hex()

            return cert_hash == tlsa['cert_data']

        except Exception as e:
            self.logger.debug(f"TLSA validation error: {e}")
            return False


class EDNSTester:
    """EDNS capability testing (ldns-test-edns equivalent)"""

    def __init__(self, timeout: int = 5, logger: Optional[Logger] = None):
        """Initialize EDNS tester"""
        self.timeout = timeout
        self.logger = logger or Logger()

    def test_resolver(self, resolver_ip: str) -> Dict:
        """Comprehensive EDNS testing"""
        result = {
            'resolver_ip': resolver_ip,
            'edns0_support': False,
            'edns1_support': False,
            'max_udp_payload': 512,
            'dnssec_ok': False,
            'nsid_support': False,
            'client_subnet_support': False,
            'cookie_support': False,
            'tcp_fallback': False,
            'errors': []
        }

        try:
            # Test basic EDNS0
            self.logger.info(f"Testing EDNS capabilities for {resolver_ip}")

            query = dns.message.make_query('example.com', 'A', use_edns=0, payload=4096)
            try:
                response = dns.query.udp(query, resolver_ip, timeout=self.timeout)
                result['edns0_support'] = response.edns >= 0
                if response.edns >= 0:
                    result['max_udp_payload'] = response.payload
                    self.logger.debug(f"EDNS0 supported, payload: {response.payload}")
            except:
                pass

            # Test DNSSEC OK bit
            query = dns.message.make_query('example.com', 'A', use_edns=0,
                                          payload=4096, want_dnssec=True)
            try:
                response = dns.query.udp(query, resolver_ip, timeout=self.timeout)
                result['dnssec_ok'] = bool(response.ednsflags & dns.flags.DO)
                self.logger.debug(f"DNSSEC OK: {result['dnssec_ok']}")
            except:
                pass

            # Test NSID (Name Server Identifier)
            query = dns.message.make_query('example.com', 'A', use_edns=0, payload=4096)
            query.use_edns(edns=0, payload=4096, options=[dns.edns.GenericOption(3, b'')])
            try:
                response = dns.query.udp(query, resolver_ip, timeout=self.timeout)
                if response.options:
                    result['nsid_support'] = True
                    self.logger.debug("NSID supported")
            except:
                pass

            # Test TCP fallback with truncated response
            result['tcp_fallback'] = self._test_tcp_fallback(resolver_ip)

            self.logger.info(f"EDNS testing complete for {resolver_ip}")
            return result

        except Exception as e:
            result['errors'].append(str(e))
            self.logger.error(f"EDNS testing failed: {e}")
            return result

    def _test_tcp_fallback(self, resolver_ip: str) -> bool:
        """Test TCP fallback capability"""
        try:
            query = dns.message.make_query('example.com', 'A')
            response = dns.query.tcp(query, resolver_ip, timeout=self.timeout)
            return True
        except:
            return False


class RRSIGAnalyzer:
    """RRSIG expiration analysis (ldns-rrsig equivalent)"""

    def __init__(self, timeout: int = 5, logger: Optional[Logger] = None):
        """Initialize RRSIG analyzer"""
        self.timeout = timeout
        self.logger = logger or Logger()

    def analyze_rrsig(self, domain: str, nameserver: Optional[str] = None) -> Dict:
        """Analyze RRSIG records for expiration and validity"""
        result = {
            'domain': domain,
            'signatures': [],
            'warnings': [],
            'errors': []
        }

        try:
            self.logger.info(f"Analyzing RRSIG records for {domain}")

            query = DNSQuery(nameserver=nameserver, dnssec=True, timeout=self.timeout)

            # Query different record types to get RRSIGs
            for qtype in ['A', 'AAAA', 'MX', 'NS', 'DNSKEY']:
                try:
                    response, _ = query.query(domain, qtype)

                    for rrset in response.answer + response.authority:
                        if rrset.rdtype == dns.rdatatype.RRSIG:
                            for rdata in rrset:
                                sig_info = self._parse_rrsig(rdata)
                                result['signatures'].append(sig_info)

                                # Check for expiration warnings
                                warnings = self._check_expiration(sig_info)
                                result['warnings'].extend(warnings)

                except Exception as e:
                    self.logger.debug(f"Error querying {qtype}: {e}")
                    continue

            # Remove duplicates
            result['signatures'] = self._deduplicate_signatures(result['signatures'])
            result['warnings'] = list(set(result['warnings']))

            self.logger.info(f"Found {len(result['signatures'])} RRSIG records")
            return result

        except Exception as e:
            result['errors'].append(str(e))
            self.logger.error(f"RRSIG analysis failed: {e}")
            return result

    def _parse_rrsig(self, rdata) -> Dict:
        """Parse RRSIG record"""
        inception = datetime.fromtimestamp(rdata.inception)
        expiration = datetime.fromtimestamp(rdata.expiration)
        now = datetime.now()

        return {
            'type_covered': dns.rdatatype.to_text(rdata.type_covered),
            'algorithm': rdata.algorithm,
            'labels': rdata.labels,
            'original_ttl': rdata.original_ttl,
            'expiration': expiration.isoformat(),
            'inception': inception.isoformat(),
            'key_tag': rdata.key_tag,
            'signer': str(rdata.signer),
            'days_until_expiration': (expiration - now).days,
            'is_valid': inception <= now <= expiration
        }

    def _check_expiration(self, sig_info: Dict) -> List[str]:
        """Check for expiration warnings"""
        warnings = []
        days = sig_info['days_until_expiration']

        if days < 0:
            warnings.append(f"CRITICAL: RRSIG for {sig_info['type_covered']} has EXPIRED")
        elif days < 1:
            warnings.append(f"URGENT: RRSIG for {sig_info['type_covered']} expires in less than 24 hours")
        elif days < 7:
            warnings.append(f"WARNING: RRSIG for {sig_info['type_covered']} expires in {days} days")

        return warnings

    def _deduplicate_signatures(self, signatures: List[Dict]) -> List[Dict]:
        """Remove duplicate signatures"""
        seen = set()
        unique = []

        for sig in signatures:
            key = (sig['type_covered'], sig['key_tag'], sig['expiration'])
            if key not in seen:
                seen.add(key)
                unique.append(sig)

        return unique


class DNSSecurityAnalyzer:
    """DNS security analysis - hijacking, cache poisoning, anomaly detection"""

    def __init__(self, timeout: int = 5, logger: Optional[Logger] = None):
        """Initialize security analyzer"""
        self.timeout = timeout
        self.logger = logger or Logger()

    def analyze_domain(self, domain: str, resolvers: List[str]) -> Dict:
        """Comprehensive security analysis"""
        result = {
            'domain': domain,
            'hijacking_detected': False,
            'cache_poisoning_risk': 'LOW',
            'inconsistencies': [],
            'security_score': 100,
            'recommendations': []
        }

        try:
            self.logger.info(f"Starting security analysis for {domain}")

            # Check for DNS hijacking
            hijacking = self._detect_hijacking(domain, resolvers)
            result['hijacking_detected'] = hijacking['detected']
            if hijacking['detected']:
                result['security_score'] -= 50
                result['recommendations'].append('CRITICAL: DNS hijacking detected')

            # Check for cache poisoning vulnerabilities
            poisoning_risk = self._assess_cache_poisoning_risk(domain)
            result['cache_poisoning_risk'] = poisoning_risk['level']
            result['security_score'] -= poisoning_risk['score_impact']

            # Detect anomalies in responses
            anomalies = self._detect_anomalies(domain, resolvers)
            result['inconsistencies'] = anomalies
            result['security_score'] -= len(anomalies) * 5

            # DNSSEC validation
            dnssec_status = self._check_dnssec(domain)
            if not dnssec_status['enabled']:
                result['security_score'] -= 20
                result['recommendations'].append('Enable DNSSEC for enhanced security')

            self.logger.info(f"Security analysis complete. Score: {result['security_score']}/100")
            return result

        except Exception as e:
            result['errors'] = [str(e)]
            self.logger.error(f"Security analysis failed: {e}")
            return result

    def _detect_hijacking(self, domain: str, resolvers: List[str]) -> Dict:
        """Detect DNS hijacking"""
        result = {'detected': False, 'details': []}

        try:
            # Query multiple resolvers and look for suspicious patterns
            responses = {}
            for resolver in resolvers[:10]:  # Test first 10
                try:
                    query = DNSQuery(nameserver=resolver, timeout=self.timeout)
                    response, _ = query.query(domain, 'A')

                    answers = [str(rdata) for rrset in response.answer
                              for rdata in rrset if rrset.rdtype == dns.rdatatype.A]

                    responses[resolver] = set(answers)
                except:
                    continue

            # Detect if one resolver gives very different answers
            if len(responses) > 1:
                answer_sets = list(responses.values())
                common_answers = set.intersection(*answer_sets)

                for resolver, answers in responses.items():
                    if not answers.intersection(common_answers):
                        result['detected'] = True
                        result['details'].append(f"Suspicious answers from {resolver}: {answers}")

        except Exception as e:
            self.logger.debug(f"Hijacking detection error: {e}")

        return result

    def _assess_cache_poisoning_risk(self, domain: str) -> Dict:
        """Assess cache poisoning vulnerability"""
        result = {'level': 'LOW', 'score_impact': 0, 'factors': []}

        try:
            # Check for DNSSEC
            query = DNSQuery(dnssec=True, timeout=self.timeout)
            response, _ = query.query(domain, 'A')

            has_dnssec = any(rrset.rdtype == dns.rdatatype.RRSIG
                           for rrset in response.answer + response.authority)

            if not has_dnssec:
                result['level'] = 'MEDIUM'
                result['score_impact'] = 15
                result['factors'].append('No DNSSEC protection')

            # Check source port randomization (would need packet capture)
            # Placeholder for actual implementation

        except Exception as e:
            self.logger.debug(f"Cache poisoning assessment error: {e}")

        return result

    def _detect_anomalies(self, domain: str, resolvers: List[str]) -> List[str]:
        """Detect anomalies in DNS responses"""
        anomalies = []

        try:
            # Collect TTL values
            ttls = []
            for resolver in resolvers[:5]:
                try:
                    query = DNSQuery(nameserver=resolver, timeout=self.timeout)
                    response, _ = query.query(domain, 'A')

                    for rrset in response.answer:
                        if rrset.rdtype == dns.rdatatype.A:
                            ttls.append(rrset.ttl)
                except:
                    continue

            # Check for TTL anomalies
            if ttls:
                avg_ttl = sum(ttls) / len(ttls)
                for ttl in ttls:
                    if abs(ttl - avg_ttl) > avg_ttl * 0.5:  # 50% deviation
                        anomalies.append(f"TTL anomaly detected: {ttl} vs average {avg_ttl:.0f}")

        except Exception as e:
            self.logger.debug(f"Anomaly detection error: {e}")

        return anomalies

    def _check_dnssec(self, domain: str) -> Dict:
        """Check DNSSEC status"""
        result = {'enabled': False, 'valid': False}

        try:
            query = DNSQuery(dnssec=True, timeout=self.timeout)
            response, _ = query.query(domain, 'DNSKEY')

            result['enabled'] = bool(response.answer)
            result['valid'] = bool(response.flags & dns.flags.AD)

        except:
            pass

        return result


class DNSUpdateManager:
    """Dynamic DNS updates (RFC 2136) - ldns-update equivalent"""

    def __init__(self, server: str, port: int = 53, timeout: int = 5,
                 logger: Optional[Logger] = None):
        """Initialize DNS update manager"""
        self.server = server
        self.port = port
        self.timeout = timeout
        self.logger = logger or Logger()

    def send_update(self, zone: str, updates: List[Dict],
                   tsig_key: Optional[Dict] = None) -> Dict:
        """Send DNS UPDATE message"""
        result = {
            'success': False,
            'response_code': None,
            'error': None
        }

        try:
            self.logger.info(f"Sending DNS UPDATE to {self.server} for zone {zone}")

            # Create UPDATE message
            update_msg = dns.update.Update(zone)

            for upd in updates:
                action = upd.get('action')
                name = upd.get('name')
                ttl = upd.get('ttl', 3600)
                rtype = upd.get('type')
                rdata = upd.get('data')

                if action == 'add':
                    update_msg.add(name, ttl, rtype, rdata)
                elif action == 'delete':
                    if rdata:
                        update_msg.delete(name, rtype, rdata)
                    else:
                        update_msg.delete(name, rtype)
                elif action == 'replace':
                    update_msg.replace(name, ttl, rtype, rdata)

            # Add TSIG if provided
            if tsig_key:
                keyring = dns.tsigkeyring.from_text({
                    tsig_key['name']: tsig_key['secret']
                })
                update_msg.use_tsig(keyring, keyname=tsig_key['name'])

            # Send update
            response = dns.query.tcp(update_msg, self.server, timeout=self.timeout, port=self.port)

            result['success'] = response.rcode() == dns.rcode.NOERROR
            result['response_code'] = dns.rcode.to_text(response.rcode())

            self.logger.info(f"UPDATE response: {result['response_code']}")
            return result

        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"DNS UPDATE failed: {e}")
            return result


class DoHResolver:
    """DNS over HTTPS (DoH) resolver"""

    def __init__(self, server_url: str, timeout: int = 5, logger: Optional[Logger] = None):
        """Initialize DoH resolver"""
        self.server_url = server_url
        self.timeout = timeout
        self.logger = logger or Logger()

    def query(self, domain: str, record_type: str = 'A') -> Dict:
        """Query via DoH"""
        result = {
            'success': False,
            'answers': [],
            'response_time': None,
            'error': None,
            'protocol': 'DoH'
        }

        try:
            start_time = time.time()

            query = dns.message.make_query(domain, record_type)
            wire_query = query.to_wire()

            headers = {
                'Content-Type': 'application/dns-message',
                'Accept': 'application/dns-message'
            }

            response = requests.post(
                self.server_url,
                data=wire_query,
                headers=headers,
                timeout=self.timeout
            )

            response_time = (time.time() - start_time) * 1000

            if response.status_code == 200:
                dns_response = dns.message.from_wire(response.content)
                result['success'] = True
                result['response_time'] = round(response_time, 2)

                for rrset in dns_response.answer:
                    for rdata in rrset:
                        result['answers'].append(str(rdata))
            else:
                result['error'] = f"HTTP {response.status_code}"

        except Exception as e:
            result['error'] = str(e)

        return result


class DoTResolver:
    """DNS over TLS (DoT) resolver"""

    def __init__(self, server_ip: str, server_name: str, port: int = 853,
                 timeout: int = 5, logger: Optional[Logger] = None):
        """Initialize DoT resolver"""
        self.server_ip = server_ip
        self.server_name = server_name
        self.port = port
        self.timeout = timeout
        self.logger = logger or Logger()

    def query(self, domain: str, record_type: str = 'A') -> Dict:
        """Query via DoT"""
        result = {
            'success': False,
            'answers': [],
            'response_time': None,
            'error': None,
            'protocol': 'DoT'
        }

        try:
            start_time = time.time()

            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            query = dns.message.make_query(domain, record_type)

            response = dns.query.tls(
                query,
                self.server_ip,
                timeout=self.timeout,
                port=self.port,
                server_hostname=self.server_name,
                ssl_context=context
            )

            response_time = (time.time() - start_time) * 1000

            result['success'] = True
            result['response_time'] = round(response_time, 2)

            for rrset in response.answer:
                for rdata in rrset:
                    result['answers'].append(str(rdata))

        except Exception as e:
            result['error'] = str(e)

        return result


class GlobalResolverTester:
    """Test domain across global DNS resolvers"""

    def __init__(self, resolvers_file: str = 'dns_resolvers.json',
                 timeout: int = 5, max_workers: int = 50,
                 logger: Optional[Logger] = None):
        """Initialize global resolver tester"""
        self.resolvers_file = resolvers_file
        self.timeout = timeout
        self.max_workers = max_workers
        self.logger = logger or Logger()
        self.resolvers = []

        self._load_resolvers()

    def _load_resolvers(self):
        """Load resolvers from config"""
        try:
            if os.path.exists(self.resolvers_file):
                with open(self.resolvers_file, 'r') as f:
                    data = json.load(f)
                    self.resolvers = data.get('resolvers', [])
                self.logger.info(f"Loaded {len(self.resolvers)} resolvers")
        except Exception as e:
            self.logger.error(f"Failed to load resolvers: {e}")

    def test_domain(self, domain: str, record_type: str = 'A') -> Dict:
        """Test domain across all resolvers"""
        results = []

        self.logger.info(f"Testing {domain} across {len(self.resolvers)} resolvers")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._query_resolver, domain, resolver, record_type): resolver
                for resolver in self.resolvers
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.debug(f"Query failed: {e}")

        # Analyze results
        analysis = self._analyze_results(results)

        return {
            'domain': domain,
            'record_type': record_type,
            'total_resolvers': len(self.resolvers),
            'successful': analysis['successful'],
            'failed': analysis['failed'],
            'unique_answers': analysis['unique_answers'],
            'consistency_score': analysis['consistency_score'],
            'results': results
        }

    def _query_resolver(self, domain: str, resolver: Dict, record_type: str) -> Dict:
        """Query single resolver"""
        result = {
            'resolver_ip': resolver['ip'],
            'provider': resolver.get('provider', 'Unknown'),
            'country': resolver.get('country', 'Unknown'),
            'success': False,
            'answers': [],
            'error': None,
            'response_time': None
        }

        try:
            query = DNSQuery(nameserver=resolver['ip'], timeout=self.timeout)
            response, stats = query.query(domain, record_type)

            result['success'] = True
            result['response_time'] = stats['query_time']
            result['answers'] = [str(rdata) for rrset in response.answer
                                for rdata in rrset if rrset.rdtype == dns.rdatatype.from_text(record_type)]

        except Exception as e:
            result['error'] = str(e)

        return result

    def _analyze_results(self, results: List[Dict]) -> Dict:
        """Analyze query results"""
        successful = sum(1 for r in results if r['success'])
        failed = len(results) - successful

        # Count unique answers
        answer_counts = Counter()
        for r in results:
            if r['success']:
                for answer in r['answers']:
                    answer_counts[answer] += 1

        # Calculate consistency score
        if successful > 0:
            most_common_count = answer_counts.most_common(1)[0][1] if answer_counts else 0
            consistency_score = (most_common_count / successful) * 100
        else:
            consistency_score = 0

        return {
            'successful': successful,
            'failed': failed,
            'unique_answers': dict(answer_counts),
            'consistency_score': round(consistency_score, 2)
        }


class DNSTracer:
    """DNS delegation path tracer"""

    def __init__(self, timeout: int = 5, logger: Optional[Logger] = None):
        """Initialize DNS tracer"""
        self.timeout = timeout
        self.logger = logger or Logger()
        self.trace_path = []

    def trace(self, domain: str, qtype: str = 'A') -> List[Dict]:
        """Trace DNS delegation path"""
        self.logger.info(f"Starting DNS trace for {domain}")
        self.trace_path = []

        root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12']
        current_ns = root_servers[0]
        domain_labels = domain.rstrip('.').split('.')

        for i in range(len(domain_labels)):
            partial_domain = '.'.join(domain_labels[i:])

            query = DNSQuery(nameserver=current_ns, timeout=self.timeout)

            try:
                response, stats = query.query(partial_domain, qtype)

                step = {
                    'query': partial_domain,
                    'nameserver': current_ns,
                    'qtype': qtype,
                    'response': response,
                    'stats': stats
                }

                self.trace_path.append(step)

                if response.answer:
                    break

                # Get next nameserver
                if response.authority:
                    ns_names = []
                    for rrset in response.authority:
                        if rrset.rdtype == dns.rdatatype.NS:
                            for rdata in rrset:
                                ns_names.append(str(rdata.target))

                    if ns_names:
                        try:
                            ns_query = DNSQuery(nameserver=current_ns)
                            ns_response, _ = ns_query.query(ns_names[0], 'A')
                            if ns_response.answer:
                                current_ns = str(ns_response.answer[0][0])
                            else:
                                break
                        except:
                            break
                    else:
                        break
                else:
                    break

            except Exception as e:
                step = {
                    'query': partial_domain,
                    'nameserver': current_ns,
                    'error': str(e)
                }
                self.trace_path.append(step)
                break

        self.logger.info(f"Trace complete: {len(self.trace_path)} steps")
        return self.trace_path


class ZoneTransfer:
    """Zone transfer utility (AXFR/IXFR)"""

    def __init__(self, nameserver: str, timeout: int = 30, logger: Optional[Logger] = None):
        """Initialize zone transfer"""
        self.nameserver = nameserver
        self.timeout = timeout
        self.logger = logger or Logger()

    def axfr(self, domain: str) -> Optional[dns.zone.Zone]:
        """Perform AXFR"""
        try:
            self.logger.info(f"Starting AXFR for {domain} from {self.nameserver}")
            zone = dns.zone.from_xfr(
                dns.query.xfr(self.nameserver, domain, timeout=self.timeout)
            )
            self.logger.info(f"AXFR complete: {len(zone.nodes)} records")
            return zone
        except Exception as e:
            self.logger.error(f"AXFR failed: {e}")
            raise Exception(f"AXFR failed: {str(e)}")


class OutputFormatter:
    """Format DNS output in various styles"""

    def __init__(self, color: bool = True, style: str = 'dig'):
        """Initialize formatter"""
        self.color = color
        self.style = style

        if not color:
            Colors.disable()

    def format_response(self, response: dns.message.Message, stats: Dict,
                       query_name: str, query_type: str) -> str:
        """Format DNS response"""

        if self.style == 'json':
            return self._format_json(response, stats, query_name, query_type)
        elif self.style == 'yaml':
            return self._format_yaml(response, stats, query_name, query_type)
        elif self.style == 'short':
            return self._format_short(response)
        else:
            return self._format_dig(response, stats, query_name, query_type)

    def _format_dig(self, response: dns.message.Message, stats: Dict,
                   query_name: str, query_type: str) -> str:
        """Format in dig style"""
        output = []

        output.append(f"{Colors.BOLD}; <<>> DNSScience Utility v{__version__} <<>> {query_name} {query_type}{Colors.END}")
        output.append(f";; global options: +cmd")

        opcode = dns.opcode.to_text(response.opcode())
        status = dns.rcode.to_text(response.rcode())
        flags = ' '.join(stats['flags'])

        output.append(f";; Got answer:")
        output.append(f";; ->>HEADER<<- opcode: {opcode}, status: {status}, id: {response.id}")
        output.append(f";; flags: {flags}; QUERY: {len(response.question)}, "
                     f"ANSWER: {len(response.answer)}, "
                     f"AUTHORITY: {len(response.authority)}, "
                     f"ADDITIONAL: {len(response.additional)}")

        if response.edns >= 0:
            output.append(f";; EDNS: version {response.edns}; flags:; udp: {response.payload}")

        if response.question:
            output.append(f"\n{Colors.CYAN};; QUESTION SECTION:{Colors.END}")
            for q in response.question:
                output.append(f";{str(q.name):<30} {dns.rdataclass.to_text(q.rdclass):<5} "
                            f"{dns.rdatatype.to_text(q.rdtype)}")

        if response.answer:
            output.append(f"\n{Colors.GREEN};; ANSWER SECTION:{Colors.END}")
            for rrset in response.answer:
                for rdata in rrset:
                    output.append(f"{str(rrset.name):<30} {rrset.ttl:<8} "
                                f"{dns.rdataclass.to_text(rrset.rdclass):<5} "
                                f"{dns.rdatatype.to_text(rrset.rdtype):<10} {rdata}")

        if response.authority:
            output.append(f"\n{Colors.YELLOW};; AUTHORITY SECTION:{Colors.END}")
            for rrset in response.authority:
                for rdata in rrset:
                    output.append(f"{str(rrset.name):<30} {rrset.ttl:<8} "
                                f"{dns.rdataclass.to_text(rrset.rdclass):<5} "
                                f"{dns.rdatatype.to_text(rrset.rdtype):<10} {rdata}")

        if response.additional:
            output.append(f"\n{Colors.BLUE};; ADDITIONAL SECTION:{Colors.END}")
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.OPT:
                    continue
                for rdata in rrset:
                    output.append(f"{str(rrset.name):<30} {rrset.ttl:<8} "
                                f"{dns.rdataclass.to_text(rrset.rdclass):<5} "
                                f"{dns.rdatatype.to_text(rrset.rdtype):<10} {rdata}")

        output.append(f"\n{Colors.BOLD};; Query time: {stats['query_time']:.0f} msec{Colors.END}")
        output.append(f";; SERVER: {stats['server']}({stats['protocol']})")
        output.append(f";; WHEN: {datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}")
        output.append(f";; MSG SIZE  rcvd: {stats['message_size']}")

        return '\n'.join(output)

    def _format_short(self, response: dns.message.Message) -> str:
        """Format in short style"""
        output = []
        if response.answer:
            for rrset in response.answer:
                for rdata in rrset:
                    output.append(str(rdata))
        return '\n'.join(output) if output else '; No answers found'

    def _format_json(self, response: dns.message.Message, stats: Dict,
                    query_name: str, query_type: str) -> str:
        """Format as JSON"""
        data = {
            'query': {'name': query_name, 'type': query_type},
            'status': dns.rcode.to_text(response.rcode()),
            'flags': stats['flags'],
            'question': [],
            'answer': [],
            'authority': [],
            'additional': [],
            'statistics': stats
        }

        for q in response.question:
            data['question'].append({
                'name': str(q.name),
                'class': dns.rdataclass.to_text(q.rdclass),
                'type': dns.rdatatype.to_text(q.rdtype)
            })

        for rrset in response.answer:
            for rdata in rrset:
                data['answer'].append({
                    'name': str(rrset.name),
                    'ttl': rrset.ttl,
                    'class': dns.rdataclass.to_text(rrset.rdclass),
                    'type': dns.rdatatype.to_text(rrset.rdtype),
                    'data': str(rdata)
                })

        for rrset in response.authority:
            for rdata in rrset:
                data['authority'].append({
                    'name': str(rrset.name),
                    'ttl': rrset.ttl,
                    'class': dns.rdataclass.to_text(rrset.rdclass),
                    'type': dns.rdatatype.to_text(rrset.rdtype),
                    'data': str(rdata)
                })

        for rrset in response.additional:
            if rrset.rdtype == dns.rdatatype.OPT:
                continue
            for rdata in rrset:
                data['additional'].append({
                    'name': str(rrset.name),
                    'ttl': rrset.ttl,
                    'class': dns.rdataclass.to_text(rrset.rdclass),
                    'type': dns.rdatatype.to_text(rrset.rdtype),
                    'data': str(rdata)
                })

        return json.dumps(data, indent=2)

    def _format_yaml(self, response: dns.message.Message, stats: Dict,
                    query_name: str, query_type: str) -> str:
        """Format as YAML"""
        data = json.loads(self._format_json(response, stats, query_name, query_type))
        return yaml.dump(data, default_flow_style=False)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        prog='dnsscience-util',
        description=f'DNSScience Utility v{__version__} - The World\'s Most Advanced DNS Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Basic Queries:
    %(prog)s example.com
    %(prog)s example.com MX
    %(prog)s example.com @8.8.8.8

  DNSSEC Analysis:
    %(prog)s example.com +dnssec
    %(prog)s --validate example.com
    %(prog)s --rrsig-analyze example.com

  Zone Operations:
    %(prog)s --trace example.com
    %(prog)s --axfr example.com @ns1.example.com
    %(prog)s --nsec-walk example.com @ns1.example.com

  Security Testing:
    %(prog)s --security-analyze example.com
    %(prog)s --dane-validate mail.example.com 25
    %(prog)s --edns-test 8.8.8.8

  Global Testing:
    %(prog)s --global-test example.com
    %(prog)s --global-test example.com --region europe

  Encrypted DNS:
    %(prog)s --doh example.com https://cloudflare-dns.com/dns-query
    %(prog)s --dot example.com 1.1.1.1 cloudflare-dns.com

  DNSScience.io API:
    %(prog)s --api-add-key dns_live_YOUR_API_KEY
    %(prog)s --api-test
    %(prog)s --api-scan example.com
    %(prog)s --api-info example.com
    %(prog)s --api-list

  Data Enrichment:
    %(prog)s --enrich example.com
    %(prog)s --enrichment example.com --json

  RDAP & Web3 Lookups:
    %(prog)s --rdap example.com
    %(prog)s --whois example.com
    %(prog)s --web3 vitalik.eth

  Output Formats:
    %(prog)s example.com +json
    %(prog)s example.com +yaml
    %(prog)s example.com +short

  Configuration:
    %(prog)s --config myconfig.yaml example.com
    %(prog)s --log-file dns.log --log-level DEBUG example.com

For more information, see: docs/EXAMPLES.md and docs/DNSSCIENCE-API.md
        """
    )

    # Positional arguments
    parser.add_argument('name', nargs='?', help='Domain name to query')
    parser.add_argument('type', nargs='?', default='A', help='Query type (default: A)')
    parser.add_argument('qclass', nargs='?', default='IN', metavar='class', help='Query class (default: IN)')

    # Query options
    query_group = parser.add_argument_group('Basic Query Options')
    query_group.add_argument('--server', '-s', dest='nameserver', metavar='NS',
                            help='Nameserver to query (or use @SERVER)')
    query_group.add_argument('-p', '--port', type=int, default=53, help='Port (default: 53)')
    query_group.add_argument('-x', '--reverse', metavar='IP', help='Reverse lookup (PTR)')
    query_group.add_argument('--timeout', type=int, default=5, help='Timeout in seconds (default: 5)')
    query_group.add_argument('--tcp', action='store_true', help='Use TCP (+tcp)')
    query_group.add_argument('--dnssec', action='store_true', help='Request DNSSEC (+dnssec)')
    query_group.add_argument('--cd', action='store_true', help='Set CD flag (+cd)')
    query_group.add_argument('--ad', action='store_true', help='Set AD flag (+ad)')

    # ldns-equivalent features
    ldns_group = parser.add_argument_group('LDNS-Equivalent Features')
    ldns_group.add_argument('--nsec-walk', action='store_true',
                           help='Walk NSEC chain (ldns-walk)')
    ldns_group.add_argument('--nsec3-analyze', action='store_true',
                           help='Analyze NSEC3 chain')
    ldns_group.add_argument('--dane-validate', nargs=2, metavar=('HOST', 'PORT'),
                           help='Validate DANE/TLSA (ldns-dane)')
    ldns_group.add_argument('--edns-test', metavar='RESOLVER',
                           help='Test EDNS capabilities (ldns-test-edns)')
    ldns_group.add_argument('--rrsig-analyze', action='store_true',
                           help='Analyze RRSIG expiration (ldns-rrsig)')
    ldns_group.add_argument('--dns-update', nargs='+', metavar='UPDATE',
                           help='Send DNS UPDATE (ldns-update)')

    # Security features
    security_group = parser.add_argument_group('Security Analysis')
    security_group.add_argument('--security-analyze', action='store_true',
                               help='Comprehensive security analysis')
    security_group.add_argument('--validate', action='store_true',
                               help='Validate DNSSEC chain')

    # Global testing
    global_group = parser.add_argument_group('Global Resolver Testing')
    global_group.add_argument('--global-test', action='store_true',
                             help='Test across global resolvers')
    global_group.add_argument('--region', help='Filter by region')
    global_group.add_argument('--country', help='Filter by country')

    # Encrypted DNS
    encrypted_group = parser.add_argument_group('Encrypted DNS')
    encrypted_group.add_argument('--doh', metavar='URL', help='Query via DNS over HTTPS')
    encrypted_group.add_argument('--dot', nargs=2, metavar=('IP', 'HOSTNAME'),
                                help='Query via DNS over TLS')

    # Zone operations
    zone_group = parser.add_argument_group('Zone Operations')
    zone_group.add_argument('--trace', action='store_true', help='Trace delegation path (+trace)')
    zone_group.add_argument('--axfr', action='store_true', help='Zone transfer (AXFR)')

    # DNSScience.io API
    api_group = parser.add_argument_group('DNSScience.io Platform API')
    api_group.add_argument('--api-scan', metavar='DOMAIN', help='Scan domain via DNSScience.io API')
    api_group.add_argument('--api-info', metavar='DOMAIN', help='Get domain info from DNSScience.io')
    api_group.add_argument('--api-history', metavar='DOMAIN', help='Get domain scan history')
    api_group.add_argument('--api-list', action='store_true', help='List tracked domains')
    api_group.add_argument('--api-search', metavar='PATTERN', help='Search domains')
    api_group.add_argument('--enrich', '--enrichment', metavar='DOMAIN',
                          help='Get complete enriched domain profile (comprehensive data)')
    api_group.add_argument('--rdap', '--whois', metavar='DOMAIN', help='RDAP lookup (modern WHOIS replacement)')
    api_group.add_argument('--web3', metavar='DOMAIN', help='Web3 domain lookup (.eth, .crypto, etc.)')
    api_group.add_argument('--api-add-key', metavar='KEY', help='Add/set API key')
    api_group.add_argument('--api-show-key', action='store_true', help='Show current API key (masked)')
    api_group.add_argument('--api-remove-key', action='store_true', help='Remove API key')
    api_group.add_argument('--api-test', action='store_true', help='Test API connection')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--short', action='store_true', help='Short output (+short)')
    output_group.add_argument('--json', action='store_true', help='JSON output (+json)')
    output_group.add_argument('--yaml', action='store_true', help='YAML output (+yaml)')
    output_group.add_argument('--nocolor', action='store_true', help='Disable colors (+nocolor)')
    output_group.add_argument('--output-file', '-o', help='Write output to file')

    # Configuration
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument('--config', help='Config file (JSON/YAML)')
    config_group.add_argument('--log-file', help='Log file path')
    config_group.add_argument('--log-level', default='INFO',
                             choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                             help='Log level (default: INFO)')

    # Version
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    # Parse arguments
    modified_argv = []
    nameserver_from_at = None
    plus_options = {}

    for arg in sys.argv[1:]:
        if arg.startswith('@'):
            nameserver_from_at = arg[1:]
        elif arg.startswith('+'):
            option = arg[1:]
            if '=' in option:
                key, value = option.split('=', 1)
                plus_options[key] = value
            else:
                plus_options[option] = True
        else:
            modified_argv.append(arg)

    args = parser.parse_args(modified_argv)

    # Apply +options
    for key, value in plus_options.items():
        if key == 'timeout' and isinstance(value, str):
            args.timeout = int(value)
        elif key == 'short':
            args.short = True
        elif key == 'json':
            args.json = True
        elif key == 'yaml':
            args.yaml = True
        elif key == 'trace':
            args.trace = True
        elif key == 'dnssec':
            args.dnssec = True
        elif key == 'tcp':
            args.tcp = True
        elif key == 'nocolor':
            args.nocolor = True

    if nameserver_from_at:
        args.nameserver = nameserver_from_at

    # Initialize configuration
    config = Config(args.config)

    # Initialize logger
    logger = Logger('dnsscience', args.log_level, args.log_file)

    # DNSScience.io API handlers
    try:
        # API key management
        if args.api_add_key:
            api = DNSScienceAPI(logger=logger)
            api.set_api_key(args.api_add_key)
            print(f"{Colors.GREEN}✓ API key added successfully{Colors.END}")
            print(f"Stored in: {api.CONFIG_FILE}")
            print("\nTest your connection with: dnsscience-util --api-test")
            sys.exit(0)

        if args.api_show_key:
            api = DNSScienceAPI(logger=logger)
            key = api.get_api_key()
            if key:
                print(f"{Colors.GREEN}API Key (masked):{Colors.END} {key}")
                print(f"Stored in: {api.CONFIG_FILE}")
            else:
                print(f"{Colors.YELLOW}No API key configured{Colors.END}")
                print("Add a key with: dnsscience-util --api-add-key <key>")
            sys.exit(0)

        if args.api_remove_key:
            api = DNSScienceAPI(logger=logger)
            api.remove_api_key()
            print(f"{Colors.GREEN}✓ API key removed{Colors.END}")
            sys.exit(0)

        if args.api_test:
            api = DNSScienceAPI(logger=logger)
            if not api.api_key:
                print(f"{Colors.RED}✗ No API key configured{Colors.END}")
                print("Add a key with: dnsscience-util --api-add-key <key>")
                sys.exit(1)

            print(f"Testing connection to {api.API_BASE_URL}...")
            if api.test_connection():
                print(f"{Colors.GREEN}✓ Connection successful{Colors.END}")
                print(f"API key: {api.get_api_key()}")
            else:
                print(f"{Colors.RED}✗ Connection failed{Colors.END}")
                print("Please check your API key and internet connection")
                sys.exit(1)
            sys.exit(0)

        if args.api_scan:
            api = DNSScienceAPI(logger=logger)
            result = api.scan_domain(args.api_scan)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        if args.api_info:
            api = DNSScienceAPI(logger=logger)
            result = api.get_domain_info(args.api_info)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        if args.api_history:
            api = DNSScienceAPI(logger=logger)
            result = api.get_domain_history(args.api_history)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        if args.api_list:
            api = DNSScienceAPI(logger=logger)
            result = api.list_domains()
            print(json.dumps(result, indent=2))
            sys.exit(0)

        if args.api_search:
            api = DNSScienceAPI(logger=logger)
            result = api.search_domains(args.api_search)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        # Domain enrichment
        if args.enrich:
            api = DNSScienceAPI(logger=logger)
            result = api.get_domain_enrichment(args.enrich)

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                # Pretty print enriched domain data
                print(f"\n{Colors.BOLD}=== Complete Domain Enrichment Profile ==={Colors.END}")
                print(f"{Colors.CYAN}Domain:{Colors.END} {args.enrich}\n")

                # Display summary sections based on available data
                if isinstance(result, dict):
                    # DNS Information
                    if 'dns' in result or 'dns_records' in result:
                        print(f"{Colors.GREEN}DNS Records:{Colors.END}")
                        dns_data = result.get('dns') or result.get('dns_records', {})
                        for record_type, records in dns_data.items() if isinstance(dns_data, dict) else []:
                            if records:
                                print(f"  {record_type}:")
                                if isinstance(records, list):
                                    for record in records[:5]:  # Limit to first 5
                                        print(f"    - {record}")
                                else:
                                    print(f"    {records}")

                    # Security Information
                    if 'security' in result:
                        print(f"\n{Colors.YELLOW}Security Posture:{Colors.END}")
                        sec = result['security']
                        if isinstance(sec, dict):
                            for key, value in sec.items():
                                print(f"  {key.replace('_', ' ').title()}: {value}")

                    # Email Security
                    if 'email_security' in result:
                        print(f"\n{Colors.BLUE}Email Security:{Colors.END}")
                        email = result['email_security']
                        if isinstance(email, dict):
                            for key, value in email.items():
                                print(f"  {key.upper()}: {value}")

                    # WHOIS/RDAP Data
                    if 'whois' in result or 'rdap' in result:
                        print(f"\n{Colors.CYAN}Registration Data:{Colors.END}")
                        reg_data = result.get('whois') or result.get('rdap', {})
                        if isinstance(reg_data, dict):
                            for key, value in reg_data.items():
                                if key in ['registrar', 'created', 'expires', 'updated']:
                                    print(f"  {key.title()}: {value}")

                    # SSL/TLS Certificate
                    if 'ssl' in result or 'certificate' in result:
                        print(f"\n{Colors.GREEN}SSL/TLS Certificate:{Colors.END}")
                        cert = result.get('ssl') or result.get('certificate', {})
                        if isinstance(cert, dict):
                            for key, value in cert.items():
                                if key in ['issuer', 'valid_from', 'valid_to', 'subject']:
                                    print(f"  {key.replace('_', ' ').title()}: {value}")

                    # Reputation/Risk Score
                    if 'reputation' in result or 'risk_score' in result:
                        print(f"\n{Colors.YELLOW}Reputation & Risk:{Colors.END}")
                        if 'reputation' in result:
                            print(f"  Reputation: {result['reputation']}")
                        if 'risk_score' in result:
                            print(f"  Risk Score: {result['risk_score']}")

                    # Geolocation/Hosting
                    if 'geolocation' in result or 'hosting' in result:
                        print(f"\n{Colors.BLUE}Hosting & Location:{Colors.END}")
                        geo = result.get('geolocation') or result.get('hosting', {})
                        if isinstance(geo, dict):
                            for key, value in geo.items():
                                print(f"  {key.replace('_', ' ').title()}: {value}")

                    # Additional metadata
                    if 'metadata' in result:
                        print(f"\n{Colors.CYAN}Additional Information:{Colors.END}")
                        meta = result['metadata']
                        if isinstance(meta, dict):
                            for key, value in meta.items():
                                print(f"  {key.replace('_', ' ').title()}: {value}")

                print(f"\n{Colors.BOLD}Use --json flag for complete data{Colors.END}\n")
            sys.exit(0)

        # RDAP lookup
        if args.rdap:
            api = DNSScienceAPI(logger=logger)
            result = api.rdap_lookup(args.rdap)

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                # Pretty print RDAP data
                print(f"\n{Colors.BOLD}=== RDAP Lookup Results ==={Colors.END}")
                print(f"{Colors.CYAN}Domain:{Colors.END} {args.rdap}\n")

                if 'rdap_data' in result and result['rdap_data']:
                    for domain_data in result['rdap_data']:
                        print(f"{Colors.GREEN}Registration Information:{Colors.END}")
                        if 'ldhName' in domain_data:
                            print(f"  Domain Name: {domain_data['ldhName']}")
                        if 'registrationDate' in domain_data:
                            print(f"  Registered: {domain_data['registrationDate']}")
                        if 'expirationDate' in domain_data:
                            print(f"  Expires: {domain_data['expirationDate']}")
                        if 'lastChangedDate' in domain_data:
                            print(f"  Last Updated: {domain_data['lastChangedDate']}")

                        if 'status' in domain_data and domain_data['status']:
                            print(f"\n{Colors.YELLOW}Status:{Colors.END}")
                            for status in domain_data['status']:
                                print(f"  - {status}")

                        if 'nameservers' in domain_data and domain_data['nameservers']:
                            print(f"\n{Colors.BLUE}Nameservers:{Colors.END}")
                            for ns in domain_data['nameservers']:
                                if isinstance(ns, dict) and 'ldhName' in ns:
                                    print(f"  - {ns['ldhName']}")
                                elif isinstance(ns, str):
                                    print(f"  - {ns}")

                        if 'entities' in domain_data and domain_data['entities']:
                            print(f"\n{Colors.CYAN}Entities:{Colors.END}")
                            for entity in domain_data['entities']:
                                if isinstance(entity, dict):
                                    roles = entity.get('roles', [])
                                    if roles:
                                        print(f"  Role: {', '.join(roles)}")
                                    if 'vcardArray' in entity:
                                        print(f"  Contact Info: [vCard data available]")
                print()
            sys.exit(0)

        # Web3 domain lookup
        if args.web3:
            api = DNSScienceAPI(logger=logger)
            result = api.web3_domain_lookup(args.web3)

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                # Pretty print Web3 domain data
                print(f"\n{Colors.BOLD}=== Web3 Domain Lookup Results ==={Colors.END}")
                print(f"{Colors.CYAN}Domain:{Colors.END} {args.web3}\n")

                if 'web3_domains' in result and result['web3_domains']:
                    for domain_data in result['web3_domains']:
                        print(f"{Colors.GREEN}Domain Information:{Colors.END}")
                        if 'name' in domain_data:
                            print(f"  Name: {domain_data['name']}")
                        if 'blockchain' in domain_data:
                            print(f"  Blockchain: {domain_data['blockchain']}")
                        if 'owner' in domain_data:
                            print(f"  Owner: {domain_data['owner']}")
                        if 'resolver' in domain_data:
                            print(f"  Resolver: {domain_data['resolver']}")
                        if 'addresses' in domain_data and domain_data['addresses']:
                            print(f"\n{Colors.YELLOW}Addresses:{Colors.END}")
                            for addr_type, addr_value in domain_data['addresses'].items():
                                print(f"  {addr_type}: {addr_value}")
                        if 'records' in domain_data and domain_data['records']:
                            print(f"\n{Colors.BLUE}Records:{Colors.END}")
                            for record_key, record_value in domain_data['records'].items():
                                print(f"  {record_key}: {record_value}")
                elif 'count' in result and result['count'] == 0:
                    print(f"{Colors.YELLOW}No Web3 domain information found{Colors.END}")
                print()
            sys.exit(0)

    except Exception as e:
        logger.error(str(e))
        print(f"{Colors.RED}; API Error: {e}{Colors.END}", file=sys.stderr)
        sys.exit(1)

    # Validate arguments
    if not args.name and not (args.edns_test or args.security_analyze):
        parser.print_help()
        sys.exit(1)

    try:
        # EDNS testing
        if args.edns_test:
            logger.info(f"Testing EDNS capabilities of {args.edns_test}")
            tester = EDNSTester(timeout=args.timeout, logger=logger)
            result = tester.test_resolver(args.edns_test)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        # DANE validation
        if args.dane_validate:
            host, port = args.dane_validate
            logger.info(f"Validating DANE/TLSA for {host}:{port}")
            validator = DANEValidator(timeout=args.timeout, logger=logger)
            result = validator.validate_tlsa(host, int(port), nameserver=args.nameserver)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        # NSEC walking
        if args.nsec_walk:
            if not args.nameserver:
                print("Error: --nsec-walk requires --server or @server")
                sys.exit(1)
            logger.info(f"Walking NSEC chain for {args.name}")
            walker = NSECWalker(args.nameserver, timeout=args.timeout, logger=logger)
            records = walker.walk_nsec(args.name)
            print(f"Found {len(records)} unique records:")
            for record in sorted(records):
                print(f"  {record}")
            sys.exit(0)

        # NSEC3 analysis
        if args.nsec3_analyze:
            if not args.nameserver:
                print("Error: --nsec3-analyze requires --server or @server")
                sys.exit(1)
            logger.info(f"Analyzing NSEC3 for {args.name}")
            walker = NSECWalker(args.nameserver, timeout=args.timeout, logger=logger)
            result = walker.walk_nsec3(args.name)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        # RRSIG analysis
        if args.rrsig_analyze:
            logger.info(f"Analyzing RRSIG records for {args.name}")
            analyzer = RRSIGAnalyzer(timeout=args.timeout, logger=logger)
            result = analyzer.analyze_rrsig(args.name, args.nameserver)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        # Security analysis
        if args.security_analyze:
            logger.info(f"Performing security analysis for {args.name}")
            analyzer = DNSSecurityAnalyzer(timeout=args.timeout, logger=logger)

            # Load some resolvers for testing
            test_resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
            result = analyzer.analyze_domain(args.name, test_resolvers)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        # Global testing
        if args.global_test:
            logger.info(f"Testing {args.name} across global resolvers")
            tester = GlobalResolverTester(timeout=args.timeout, logger=logger)
            result = tester.test_domain(args.name, args.type)

            print(f"\n{Colors.BOLD}=== Global DNS Test Results ==={Colors.END}")
            print(f"Domain: {result['domain']}")
            print(f"Record Type: {result['record_type']}")
            print(f"Total Resolvers: {result['total_resolvers']}")
            print(f"Successful: {result['successful']}")
            print(f"Failed: {result['failed']}")
            print(f"Consistency Score: {result['consistency_score']}%")
            print(f"\nUnique Answers:")
            for answer, count in result['unique_answers'].items():
                print(f"  {answer}: {count} resolvers")
            sys.exit(0)

        # DoH query
        if args.doh:
            logger.info(f"Querying via DoH: {args.doh}")
            resolver = DoHResolver(args.doh, timeout=args.timeout, logger=logger)
            result = resolver.query(args.name, args.type)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        # DoT query
        if args.dot:
            ip, hostname = args.dot
            logger.info(f"Querying via DoT: {ip} ({hostname})")
            resolver = DoTResolver(ip, hostname, timeout=args.timeout, logger=logger)
            result = resolver.query(args.name, args.type)
            print(json.dumps(result, indent=2))
            sys.exit(0)

        # Trace
        if args.trace:
            logger.info(f"Tracing delegation path for {args.name}")
            tracer = DNSTracer(timeout=args.timeout, logger=logger)
            trace_path = tracer.trace(args.name, args.type)

            print(f"{Colors.BOLD}; <<>> DNSScience Utility - Trace Mode <<>> {args.name}{Colors.END}\n")
            for step in trace_path:
                if 'error' in step:
                    print(f"{Colors.RED}; Error at {step['query']}: {step['error']}{Colors.END}")
                else:
                    print(f"{Colors.CYAN}; Query: {step['query']} from {step['nameserver']}{Colors.END}")
                    formatter = OutputFormatter(color=not args.nocolor, style='dig')
                    output = formatter.format_response(
                        step['response'], step['stats'],
                        step['query'], step['qtype']
                    )
                    print(output)
                    print()
            sys.exit(0)

        # AXFR
        if args.axfr:
            if not args.nameserver:
                print("Error: AXFR requires --server or @server")
                sys.exit(1)

            logger.info(f"Performing AXFR for {args.name}")
            zt = ZoneTransfer(args.nameserver, timeout=30, logger=logger)
            zone = zt.axfr(args.name)

            print(f"; Zone transfer complete for {args.name}")
            print(f"; {len(zone.nodes)} records transferred\n")

            for name, node in zone.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        print(f"{name} {rdataset.ttl} IN {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
            sys.exit(0)

        # Standard query
        qname = args.name
        qtype = args.type
        qclass = args.qclass

        query_opts = {
            'nameserver': args.nameserver,
            'port': args.port,
            'timeout': args.timeout,
            'use_tcp': args.tcp,
            'dnssec': args.dnssec,
            'cd_flag': args.cd,
            'ad_flag': args.ad,
            'logger': logger
        }

        query = DNSQuery(**query_opts)
        response, stats = query.query(qname, qtype, qclass)

        # Determine output style
        if args.json:
            style = 'json'
        elif args.yaml:
            style = 'yaml'
        elif args.short:
            style = 'short'
        else:
            style = 'dig'

        formatter = OutputFormatter(color=not args.nocolor, style=style)
        output = formatter.format_response(response, stats, qname, qtype)

        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(output)
            logger.info(f"Output written to {args.output_file}")
        else:
            print(output)

    except Exception as e:
        logger.error(str(e))
        print(f"{Colors.RED}; Error: {e}{Colors.END}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
