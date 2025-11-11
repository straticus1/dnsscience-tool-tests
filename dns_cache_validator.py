#!/usr/bin/env python3
"""
Global DNS Cache Validator
Production-grade tool for querying domains through public DNS resolvers worldwide
to validate DNS propagation and detect resolution differences across geographic locations.
"""

import json
import dns.resolver
import dns.exception
import dns.dnssec
import dns.message
import dns.query
import dns.rdatatype
import argparse
import sys
import os
import csv
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import hashlib


# Define regions and their country mappings
REGIONS = {
    'north_america': ['United States', 'Canada', 'Mexico'],
    'south_america': ['Brazil', 'Argentina', 'Chile', 'Colombia', 'Peru', 'Venezuela', 'Ecuador', 'Bolivia', 'Paraguay', 'Uruguay', 'Guyana', 'Suriname', 'French Guiana'],
    'europe': ['United Kingdom', 'Germany', 'France', 'Italy', 'Spain', 'Netherlands', 'Belgium', 'Switzerland', 'Austria', 'Sweden', 'Norway', 'Denmark', 'Finland', 'Iceland', 'Poland', 'Czech Republic', 'Hungary', 'Romania', 'Bulgaria', 'Greece', 'Portugal', 'Ireland', 'Luxembourg', 'Croatia', 'Slovenia', 'Slovakia', 'Estonia', 'Latvia', 'Lithuania', 'Malta', 'Cyprus'],
    'asia': ['China', 'Japan', 'South Korea', 'India', 'Singapore', 'Hong Kong', 'Taiwan', 'Thailand', 'Vietnam', 'Malaysia', 'Indonesia', 'Philippines', 'Pakistan', 'Bangladesh', 'Sri Lanka', 'Nepal', 'Myanmar', 'Cambodia', 'Laos', 'Brunei', 'Mongolia', 'Kazakhstan', 'Uzbekistan', 'Kyrgyzstan', 'Tajikistan', 'Turkmenistan', 'Afghanistan', 'Maldives', 'Bhutan', 'Macau'],
    'middle_east': ['Saudi Arabia', 'United Arab Emirates', 'Israel', 'Turkey', 'Iran', 'Iraq', 'Qatar', 'Kuwait', 'Bahrain', 'Oman', 'Lebanon', 'Jordan', 'Yemen', 'Syria', 'Palestine'],
    'africa': ['South Africa', 'Nigeria', 'Kenya', 'Egypt', 'Morocco', 'Ghana', 'Tunisia', 'Algeria', 'Ethiopia', 'Tanzania', 'Uganda', 'Senegal', 'Cameroon', 'Ivory Coast', 'Angola', 'Zimbabwe', 'Mozambique', 'Namibia', 'Botswana', 'Mali', 'Malawi', 'Zambia', 'Chad', 'Somalia', 'Rwanda', 'Burundi', 'Benin', 'Togo', 'Liberia', 'Sierra Leone', 'Libya', 'Mauritania', 'Niger', 'Burkina Faso', 'Madagascar', 'Gabon', 'Guinea', 'Central African Republic', 'Democratic Republic of the Congo', 'Republic of the Congo', 'Eritrea', 'Djibouti', 'Equatorial Guinea', 'Western Sahara', 'Mauritius', 'Swaziland', 'Comoros', 'Cape Verde', 'Sao Tome and Principe', 'Seychelles'],
    'oceania': ['Australia', 'New Zealand', 'Fiji', 'Papua New Guinea', 'Solomon Islands', 'Vanuatu', 'Samoa', 'Tonga', 'Kiribati', 'Micronesia', 'Palau', 'Marshall Islands', 'Nauru', 'Tuvalu'],
    'russia_cis': ['Russia', 'Ukraine', 'Belarus', 'Armenia', 'Azerbaijan', 'Georgia', 'Moldova']
}

# ISO country code to full name mapping (common ones)
COUNTRY_CODE_MAP = {
    'US': 'United States', 'CA': 'Canada', 'UK': 'United Kingdom', 'GB': 'United Kingdom',
    'DE': 'Germany', 'FR': 'France', 'IT': 'Italy', 'ES': 'Spain', 'NL': 'Netherlands',
    'BE': 'Belgium', 'CH': 'Switzerland', 'AT': 'Austria', 'SE': 'Sweden', 'NO': 'Norway',
    'DK': 'Denmark', 'FI': 'Finland', 'IS': 'Iceland', 'PL': 'Poland', 'CZ': 'Czech Republic',
    'HU': 'Hungary', 'RO': 'Romania', 'BG': 'Bulgaria', 'GR': 'Greece', 'PT': 'Portugal',
    'IE': 'Ireland', 'CN': 'China', 'JP': 'Japan', 'KR': 'South Korea', 'IN': 'India',
    'SG': 'Singapore', 'HK': 'Hong Kong', 'TW': 'Taiwan', 'TH': 'Thailand', 'VN': 'Vietnam',
    'MY': 'Malaysia', 'ID': 'Indonesia', 'PH': 'Philippines', 'PK': 'Pakistan', 'BD': 'Bangladesh',
    'LK': 'Sri Lanka', 'NP': 'Nepal', 'MM': 'Myanmar', 'KH': 'Cambodia', 'LA': 'Laos',
    'BN': 'Brunei', 'MN': 'Mongolia', 'AU': 'Australia', 'NZ': 'New Zealand', 'FJ': 'Fiji',
    'PG': 'Papua New Guinea', 'SA': 'Saudi Arabia', 'AE': 'United Arab Emirates', 'IL': 'Israel',
    'TR': 'Turkey', 'IR': 'Iran', 'IQ': 'Iraq', 'QA': 'Qatar', 'KW': 'Kuwait', 'BH': 'Bahrain',
    'OM': 'Oman', 'LB': 'Lebanon', 'JO': 'Jordan', 'YE': 'Yemen', 'SY': 'Syria', 'PS': 'Palestine',
    'ZA': 'South Africa', 'NG': 'Nigeria', 'KE': 'Kenya', 'EG': 'Egypt', 'MA': 'Morocco',
    'GH': 'Ghana', 'TN': 'Tunisia', 'DZ': 'Algeria', 'ET': 'Ethiopia', 'TZ': 'Tanzania',
    'UG': 'Uganda', 'RU': 'Russia', 'UA': 'Ukraine', 'BY': 'Belarus', 'BR': 'Brazil',
    'AR': 'Argentina', 'CL': 'Chile', 'CO': 'Colombia', 'MX': 'Mexico', 'PE': 'Peru'
}

# Supported DNS record types (expanded to 50+ types)
VALID_RECORD_TYPES = {
    # Common record types
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'PTR',
    # DNSSEC record types
    'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'RRSIG', 'NSEC3PARAM', 'CDNSKEY', 'CDS',
    # Security & authentication
    'CAA', 'TLSA', 'SSHFP', 'CERT', 'OPENPGPKEY', 'SMIMEA', 'IPSECKEY',
    # Service discovery
    'NAPTR', 'AFSDB', 'URI', 'HTTPS', 'SVCB',
    # Legacy/informational
    'SPF', 'RP', 'HINFO', 'MINFO', 'WKS', 'LOC',
    # Delegation & naming
    'DNAME', 'APL', 'DHCID', 'DLV', 'HIP', 'KX',
    # DNSSEC-related
    'TA', 'TKEY', 'TSIG', 'KEY',
    # Experimental/rare
    'NULL', 'ZONEMD', 'NID', 'L32', 'L64', 'LP', 'EUI48', 'EUI64',
    # Special types
    'ANY', 'AXFR', 'IXFR', 'OPT'
}


class DNSCacheValidator:
    """Production-grade DNS cache validator with comprehensive features."""

    def __init__(
        self,
        config_file: str = 'dns_resolvers.json',
        timeout: int = 5,
        max_workers: int = 50,
        retry_count: int = 2,
        rate_limit: Optional[float] = None,
        log_file: Optional[str] = None,
        log_level: str = 'INFO'
    ):
        """
        Initialize the DNS Cache Validator.

        Args:
            config_file: Path to JSON config with DNS resolvers
            timeout: DNS query timeout in seconds
            max_workers: Maximum concurrent queries
            retry_count: Number of retries for failed queries
            rate_limit: Rate limit in queries per second (None for unlimited)
            log_file: Path to log file (None for console only)
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        """
        self.config_file = config_file
        self.timeout = timeout
        self.max_workers = max_workers
        self.retry_count = retry_count
        self.rate_limit = rate_limit
        self.resolvers = []
        self.query_timestamps = []  # For rate limiting

        # Setup logging
        self._setup_logging(log_file, log_level)

        # Load resolvers
        self.load_resolvers()

    def _setup_logging(self, log_file: Optional[str], log_level: str):
        """Configure logging for the application."""
        level = getattr(logging, log_level.upper(), logging.INFO)

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Setup logger
        self.logger = logging.getLogger('DNSCacheValidator')
        self.logger.setLevel(level)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            self.logger.info(f"Logging to file: {log_file}")

    def load_resolvers(self):
        """Load DNS resolvers from JSON config file."""
        try:
            with open(self.config_file, 'r') as f:
                data = json.load(f)
                self.resolvers = data.get('resolvers', [])
            self.logger.info(f"Loaded {len(self.resolvers)} DNS resolvers from config")
        except FileNotFoundError:
            self.logger.error(f"Config file '{self.config_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in '{self.config_file}': {e}")
            sys.exit(1)

    def _apply_rate_limit(self):
        """Apply rate limiting if configured."""
        if not self.rate_limit:
            return

        current_time = time.time()
        # Remove timestamps older than 1 second
        self.query_timestamps = [ts for ts in self.query_timestamps if current_time - ts < 1.0]

        # If we've hit the rate limit, sleep
        if len(self.query_timestamps) >= self.rate_limit:
            sleep_time = 1.0 - (current_time - self.query_timestamps[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
                self.query_timestamps = []

        self.query_timestamps.append(time.time())

    def validate_domain(self, domain: str) -> bool:
        """
        Validate domain name format.

        Args:
            domain: Domain name to validate

        Returns:
            True if valid, False otherwise
        """
        # Basic domain validation regex
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )

        if not domain_pattern.match(domain):
            self.logger.error(f"Invalid domain name format: {domain}")
            return False

        if len(domain) > 253:
            self.logger.error(f"Domain name too long: {domain}")
            return False

        return True

    def validate_record_type(self, record_type: str, type_id: Optional[int] = None) -> bool:
        """
        Validate DNS record type.

        Args:
            record_type: DNS record type to validate
            type_id: Optional numeric record type ID (1-65535)

        Returns:
            True if valid, False otherwise
        """
        # If type_id is provided, validate it's in valid range
        if type_id is not None:
            if not (1 <= type_id <= 65535):
                self.logger.error(f"Invalid record type ID: {type_id} (must be 1-65535)")
                return False
            self.logger.info(f"Using custom record type ID: {type_id}")
            return True

        # Otherwise validate string record type
        if record_type.upper() not in VALID_RECORD_TYPES:
            self.logger.error(f"Invalid record type: {record_type}")
            self.logger.error(f"Supported types: {', '.join(sorted(VALID_RECORD_TYPES))}")
            return False
        return True

    def filter_resolvers(
        self,
        countries: Optional[List[str]] = None,
        regions: Optional[List[str]] = None,
        tiers: Optional[List[str]] = None,
        tags: Optional[List[str]] = None
    ) -> List[Dict]:
        """
        Filter resolvers based on criteria.

        Args:
            countries: List of country names or codes
            regions: List of region names
            tiers: List of tier levels
            tags: List of tags

        Returns:
            Filtered list of resolvers
        """
        filtered = self.resolvers.copy()

        # Filter by country
        if countries:
            # Normalize country codes to full names
            normalized_countries = []
            for c in countries:
                c_upper = c.upper()
                if c_upper in COUNTRY_CODE_MAP:
                    normalized_countries.append(COUNTRY_CODE_MAP[c_upper])
                else:
                    normalized_countries.append(c)

            filtered = [
                r for r in filtered
                if r.get('country') in normalized_countries or
                   r.get('country_code') in countries
            ]
            self.logger.info(f"Filtered to {len(filtered)} resolvers in countries: {', '.join(countries)}")

        # Filter by region
        if regions:
            region_countries = set()
            for region in regions:
                region_lower = region.lower()
                if region_lower in REGIONS:
                    region_countries.update(REGIONS[region_lower])
                else:
                    self.logger.warning(f"Unknown region: {region}")

            if region_countries:
                filtered = [r for r in filtered if r.get('country') in region_countries]
                self.logger.info(f"Filtered to {len(filtered)} resolvers in regions: {', '.join(regions)}")

        # Filter by tier
        if tiers:
            filtered = [r for r in filtered if r.get('tier') in tiers]
            self.logger.info(f"Filtered to {len(filtered)} resolvers in tiers: {', '.join(tiers)}")

        # Filter by tags
        if tags:
            filtered = [
                r for r in filtered
                if any(tag in r.get('tags', []) for tag in tags)
            ]
            self.logger.info(f"Filtered to {len(filtered)} resolvers with tags: {', '.join(tags)}")

        return filtered

    def query_resolver(
        self,
        domain: str,
        resolver_info: Dict,
        record_type: str = 'A',
        attempt: int = 1,
        type_id: Optional[int] = None
    ) -> Dict:
        """
        Query a single DNS resolver for a domain with retry logic.

        Args:
            domain: Domain to query
            resolver_info: Dict with resolver details
            record_type: DNS record type
            attempt: Current attempt number

        Returns:
            Dict with query results
        """
        # Apply rate limiting
        self._apply_rate_limit()

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolver_info['ip']]
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        result = {
            'resolver_ip': resolver_info['ip'],
            'country': resolver_info.get('country', 'Unknown'),
            'country_code': resolver_info.get('country_code', ''),
            'region': resolver_info.get('region', ''),
            'continent': resolver_info.get('continent', ''),
            'provider': resolver_info.get('provider', 'Unknown'),
            'city': resolver_info.get('city', ''),
            'tier': resolver_info.get('tier', ''),
            'tags': resolver_info.get('tags', []),
            'success': False,
            'answers': [],
            'error': None,
            'response_time': None,
            'ttl': None,
            'timestamp': datetime.utcnow().isoformat(),
            'attempt': attempt
        }

        try:
            start_time = time.time()
            # Use numeric type ID if provided, otherwise use string record type
            query_type = type_id if type_id is not None else record_type
            answers = resolver.resolve(domain, query_type)
            response_time = (time.time() - start_time) * 1000  # Convert to ms

            result['success'] = True
            result['answers'] = [str(rdata) for rdata in answers]
            result['response_time'] = round(response_time, 2)
            result['ttl'] = answers.rrset.ttl

            self.logger.debug(
                f"Success: {resolver_info['provider']} ({resolver_info['ip']}) "
                f"- {response_time:.2f}ms"
            )

        except dns.exception.Timeout:
            result['error'] = 'Timeout'
            self.logger.debug(f"Timeout: {resolver_info['ip']}")

        except dns.resolver.NXDOMAIN:
            result['error'] = 'NXDOMAIN'
            self.logger.debug(f"NXDOMAIN: {resolver_info['ip']}")

        except dns.resolver.NoAnswer:
            result['error'] = 'No Answer'
            self.logger.debug(f"No Answer: {resolver_info['ip']}")

        except dns.resolver.NoNameservers:
            result['error'] = 'No Nameservers'
            self.logger.debug(f"No Nameservers: {resolver_info['ip']}")

        except Exception as e:
            result['error'] = str(e)
            self.logger.debug(f"Error querying {resolver_info['ip']}: {e}")

        # Retry logic with exponential backoff
        if not result['success'] and attempt < self.retry_count:
            backoff_time = (2 ** attempt) * 0.5  # 0.5s, 1s, 2s, etc.
            self.logger.debug(f"Retrying {resolver_info['ip']} in {backoff_time}s (attempt {attempt + 1})")
            time.sleep(backoff_time)
            return self.query_resolver(domain, resolver_info, record_type, attempt + 1, type_id)

        return result

    def check_dnssec(self, domain: str, resolver_ip: str) -> Dict:
        """
        Check DNSSEC validation status for a domain on a specific resolver.

        Args:
            domain: Domain to check
            resolver_ip: IP address of the resolver

        Returns:
            Dict with DNSSEC validation results
        """
        dnssec_result = {
            'resolver_ip': resolver_ip,
            'dnssec_enabled': False,
            'do_bit_support': False,
            'has_dnskey': False,
            'has_ds': False,
            'has_rrsig': False,
            'validation_chain_ok': False,
            'error': None
        }

        try:
            # Check if resolver supports DO (DNSSEC OK) bit
            query = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
            query.flags |= dns.flags.AD  # Request authenticated data

            response = dns.query.udp(query, resolver_ip, timeout=self.timeout)

            # Check if DO bit is set in response
            dnssec_result['do_bit_support'] = response.edns >= 0

            # Check for DNSKEY records
            try:
                dnskey_resolver = dns.resolver.Resolver()
                dnskey_resolver.nameservers = [resolver_ip]
                dnskey_resolver.timeout = self.timeout
                dnskey_answer = dnskey_resolver.resolve(domain, 'DNSKEY')
                dnssec_result['has_dnskey'] = len(dnskey_answer) > 0
            except:
                pass

            # Check for RRSIG records on A record
            try:
                query_rrsig = dns.message.make_query(domain, dns.rdatatype.A)
                query_rrsig.flags |= dns.flags.AD
                response_rrsig = dns.query.udp(query_rrsig, resolver_ip, timeout=self.timeout)

                for rrset in response_rrsig.answer:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        dnssec_result['has_rrsig'] = True
                        break
            except:
                pass

            # Check for DS records (at parent zone)
            try:
                ds_domain = '.'.join(domain.split('.')[1:]) if '.' in domain else domain
                ds_resolver = dns.resolver.Resolver()
                ds_resolver.nameservers = [resolver_ip]
                ds_resolver.timeout = self.timeout
                ds_answer = ds_resolver.resolve(ds_domain, 'DS')
                dnssec_result['has_ds'] = len(ds_answer) > 0
            except:
                pass

            # Overall DNSSEC status
            dnssec_result['dnssec_enabled'] = (
                dnssec_result['do_bit_support'] and
                (dnssec_result['has_rrsig'] or dnssec_result['has_dnskey'])
            )

            # Check AD (Authenticated Data) flag
            dnssec_result['validation_chain_ok'] = bool(response.flags & dns.flags.AD)

        except dns.exception.Timeout:
            dnssec_result['error'] = 'Timeout'
        except Exception as e:
            dnssec_result['error'] = str(e)

        return dnssec_result

    def validate_domain_scan(
        self,
        domain: str,
        record_type: str = 'A',
        resolvers: Optional[List[Dict]] = None,
        progress_callback: Optional[callable] = None,
        type_id: Optional[int] = None
    ) -> List[Dict]:
        """
        Validate a domain across multiple DNS resolvers.

        Args:
            domain: Domain to validate
            record_type: DNS record type
            resolvers: List of resolvers to query (None for all)
            progress_callback: Optional callback for progress updates

        Returns:
            List of query results
        """
        resolvers_to_query = resolvers if resolvers else self.resolvers
        results = []

        self.logger.info(
            f"Querying {len(resolvers_to_query)} DNS resolvers for {domain} "
            f"({record_type} records)"
        )
        self.logger.info(f"Timeout: {self.timeout}s | Max concurrent: {self.max_workers}")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_resolver = {
                executor.submit(self.query_resolver, domain, resolver, record_type, 1, type_id): resolver
                for resolver in resolvers_to_query
            }

            completed = 0
            for future in as_completed(future_to_resolver):
                result = future.result()
                results.append(result)
                completed += 1

                if progress_callback:
                    progress_callback(completed, len(resolvers_to_query))

        return results

    def analyze_results(self, results: List[Dict]) -> Dict:
        """
        Analyze query results and generate comprehensive statistics.

        Returns:
            Dict with detailed analysis data
        """
        analysis = {
            'total_queries': len(results),
            'successful': 0,
            'failed': 0,
            'by_country': defaultdict(lambda: {
                'success': 0, 'failed': 0, 'answers': set(), 'avg_response_time': 0,
                'response_times': []
            }),
            'by_region': defaultdict(lambda: {
                'success': 0, 'failed': 0, 'answers': set()
            }),
            'by_continent': defaultdict(lambda: {
                'success': 0, 'failed': 0, 'answers': set()
            }),
            'unique_answers': defaultdict(lambda: {
                'count': 0,
                'first_seen': None,
                'last_seen': None,
                'resolvers': [],
                'countries': set()
            }),
            'errors': defaultdict(int),
            'avg_response_time': 0,
            'median_response_time': 0,
            'fastest_resolver': None,
            'slowest_resolver': None,
            'consistency_score': 0.0,
            'propagation_lag': None
        }

        response_times = []
        answer_timestamps = {}

        for result in results:
            country = result['country']
            region = result.get('region', 'Unknown')
            continent = result.get('continent', 'Unknown')

            if result['success']:
                analysis['successful'] += 1
                analysis['by_country'][country]['success'] += 1
                analysis['by_region'][region]['success'] += 1
                analysis['by_continent'][continent]['success'] += 1

                # Track unique answers with timestamps
                for answer in result['answers']:
                    answer_data = analysis['unique_answers'][answer]
                    answer_data['count'] += 1
                    answer_data['resolvers'].append(result['resolver_ip'])
                    answer_data['countries'].add(country)

                    timestamp = datetime.fromisoformat(result['timestamp'])
                    if answer_data['first_seen'] is None:
                        answer_data['first_seen'] = timestamp
                    else:
                        answer_data['first_seen'] = min(answer_data['first_seen'], timestamp)

                    if answer_data['last_seen'] is None:
                        answer_data['last_seen'] = timestamp
                    else:
                        answer_data['last_seen'] = max(answer_data['last_seen'], timestamp)

                    analysis['by_country'][country]['answers'].add(answer)
                    analysis['by_region'][region]['answers'].add(answer)
                    analysis['by_continent'][continent]['answers'].add(answer)

                # Track response times
                if result['response_time']:
                    response_times.append(result['response_time'])
                    analysis['by_country'][country]['response_times'].append(result['response_time'])

                    if not analysis['fastest_resolver'] or \
                       result['response_time'] < analysis['fastest_resolver']['response_time']:
                        analysis['fastest_resolver'] = result

                    if not analysis['slowest_resolver'] or \
                       result['response_time'] > analysis['slowest_resolver']['response_time']:
                        analysis['slowest_resolver'] = result
            else:
                analysis['failed'] += 1
                analysis['by_country'][country]['failed'] += 1
                analysis['by_region'][region]['failed'] += 1
                analysis['by_continent'][continent]['failed'] += 1
                if result['error']:
                    analysis['errors'][result['error']] += 1

        # Calculate average and median response times
        if response_times:
            analysis['avg_response_time'] = round(sum(response_times) / len(response_times), 2)
            sorted_times = sorted(response_times)
            mid = len(sorted_times) // 2
            if len(sorted_times) % 2 == 0:
                analysis['median_response_time'] = round(
                    (sorted_times[mid - 1] + sorted_times[mid]) / 2, 2
                )
            else:
                analysis['median_response_time'] = round(sorted_times[mid], 2)

        # Calculate per-country average response times
        for country_data in analysis['by_country'].values():
            if country_data['response_times']:
                country_data['avg_response_time'] = round(
                    sum(country_data['response_times']) / len(country_data['response_times']), 2
                )

        # Calculate consistency score (0-1, where 1 is perfectly consistent)
        if analysis['successful'] > 0:
            most_common_answer_count = max(
                (data['count'] for data in analysis['unique_answers'].values()),
                default=0
            )
            analysis['consistency_score'] = round(
                most_common_answer_count / analysis['successful'], 3
            )

        # Calculate propagation lag
        if len(analysis['unique_answers']) > 1:
            timestamps = [
                (answer, data['first_seen'], data['last_seen'])
                for answer, data in analysis['unique_answers'].items()
                if data['first_seen'] and data['last_seen']
            ]
            if timestamps:
                earliest = min(ts[1] for ts in timestamps)
                latest = max(ts[2] for ts in timestamps)
                lag = (latest - earliest).total_seconds()
                analysis['propagation_lag'] = {
                    'seconds': lag,
                    'earliest': earliest.isoformat(),
                    'latest': latest.isoformat(),
                    'answers': {ts[0]: {'first': ts[1].isoformat(), 'last': ts[2].isoformat()}
                               for ts in timestamps}
                }

        # Convert sets to lists for JSON serialization
        for country_data in analysis['by_country'].values():
            country_data['answers'] = list(country_data['answers'])
            del country_data['response_times']  # Remove raw data

        for region_data in analysis['by_region'].values():
            region_data['answers'] = list(region_data['answers'])

        for continent_data in analysis['by_continent'].values():
            continent_data['answers'] = list(continent_data['answers'])

        for answer_data in analysis['unique_answers'].values():
            answer_data['countries'] = list(answer_data['countries'])
            if answer_data['first_seen']:
                answer_data['first_seen'] = answer_data['first_seen'].isoformat()
            if answer_data['last_seen']:
                answer_data['last_seen'] = answer_data['last_seen'].isoformat()

        return analysis

    def detect_stale_resolvers(self, results: List[Dict], analysis: Dict) -> List[Dict]:
        """
        Identify resolvers with potentially stale/outdated answers.

        Args:
            results: Query results
            analysis: Analysis data from analyze_results()

        Returns:
            List of resolvers with stale data
        """
        if len(analysis['unique_answers']) <= 1:
            return []  # No inconsistency detected

        # Determine the most common answer (assumed to be current)
        most_common_answer = max(
            analysis['unique_answers'].items(),
            key=lambda x: x[1]['count']
        )[0]

        stale_resolvers = []
        for result in results:
            if result['success'] and most_common_answer not in result['answers']:
                stale_resolvers.append({
                    'resolver_ip': result['resolver_ip'],
                    'provider': result['provider'],
                    'country': result['country'],
                    'answers': result['answers'],
                    'timestamp': result['timestamp']
                })

        return stale_resolvers

    def print_summary(self, analysis: Dict, mode: str = 'default'):
        """
        Print summary of the analysis.

        Args:
            analysis: Analysis data
            mode: Output mode ('default', 'summary', 'detailed')
        """
        if mode == 'summary':
            self._print_brief_summary(analysis)
        else:
            self._print_detailed_summary(analysis)

    def _print_brief_summary(self, analysis: Dict):
        """Print brief summary mode."""
        print("\n" + "=" * 60)
        print("DNS VALIDATION SUMMARY")
        print("=" * 60)

        success_rate = (analysis['successful'] / analysis['total_queries'] * 100) \
                       if analysis['total_queries'] > 0 else 0

        print(f"Status: {'PASS' if analysis['consistency_score'] > 0.95 else 'WARN'}")
        print(f"Success Rate: {success_rate:.1f}% ({analysis['successful']}/{analysis['total_queries']})")
        print(f"Consistency Score: {analysis['consistency_score']:.1%}")
        print(f"Unique Answers: {len(analysis['unique_answers'])}")

        if analysis['unique_answers']:
            print("\nMost Common Answer:")
            most_common = max(analysis['unique_answers'].items(), key=lambda x: x[1]['count'])
            print(f"  {most_common[0]} ({most_common[1]['count']} resolvers)")

        if analysis['propagation_lag']:
            lag = analysis['propagation_lag']['seconds']
            print(f"\nPropagation Lag: {lag:.1f}s")

    def _print_detailed_summary(self, analysis: Dict):
        """Print detailed summary mode."""
        print("\n" + "=" * 80)
        print("DNS VALIDATION SUMMARY")
        print("=" * 80)

        # Overall statistics
        print(f"\nTotal Queries: {analysis['total_queries']}")
        print(f"Successful: {analysis['successful']} "
              f"({analysis['successful']/analysis['total_queries']*100:.1f}%)")
        print(f"Failed: {analysis['failed']} "
              f"({analysis['failed']/analysis['total_queries']*100:.1f}%)")
        print(f"Consistency Score: {analysis['consistency_score']:.1%}")

        # Response time statistics
        if analysis['avg_response_time']:
            print(f"\nResponse Time Statistics:")
            print(f"  Average: {analysis['avg_response_time']}ms")
            print(f"  Median: {analysis['median_response_time']}ms")

        # Geographic coverage
        print(f"\nGeographic Coverage:")
        print(f"  Countries: {len(analysis['by_country'])}")
        print(f"  Regions: {len(analysis['by_region'])}")
        print(f"  Continents: {len(analysis['by_continent'])}")

        # Resolution results
        print(f"\nUnique Answers: {len(analysis['unique_answers'])}")
        if analysis['unique_answers']:
            print("\nResolution Results:")
            for answer, data in sorted(
                analysis['unique_answers'].items(),
                key=lambda x: x[1]['count'],
                reverse=True
            ):
                percentage = (data['count'] / analysis['successful']) * 100 \
                            if analysis['successful'] > 0 else 0
                print(f"  {answer}")
                print(f"    Count: {data['count']} resolvers ({percentage:.1f}%)")
                print(f"    Countries: {', '.join(sorted(data['countries']))}")
                if data['first_seen']:
                    print(f"    First Seen: {data['first_seen']}")
                    print(f"    Last Seen: {data['last_seen']}")

        # Propagation lag analysis
        if analysis['propagation_lag']:
            lag = analysis['propagation_lag']['seconds']
            print(f"\nPropagation Lag Detected:")
            print(f"  Time Span: {lag:.2f} seconds ({lag/60:.1f} minutes)")
            print(f"  Earliest Response: {analysis['propagation_lag']['earliest']}")
            print(f"  Latest Response: {analysis['propagation_lag']['latest']}")

        # Errors
        if analysis['errors']:
            print("\nErrors Encountered:")
            for error, count in sorted(analysis['errors'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / analysis['total_queries']) * 100
                print(f"  {error}: {count} ({percentage:.1f}%)")

        # Performance extremes
        if analysis['fastest_resolver']:
            fr = analysis['fastest_resolver']
            print(f"\nFastest Resolver:")
            print(f"  {fr['provider']} ({fr['country']}) - {fr['response_time']}ms")

        if analysis['slowest_resolver']:
            sr = analysis['slowest_resolver']
            print(f"Slowest Resolver:")
            print(f"  {sr['provider']} ({sr['country']}) - {sr['response_time']}ms")

    def print_detailed_results(self, results: List[Dict], analysis: Dict, show_errors: bool = False):
        """Print detailed results by country."""
        print("\n" + "=" * 80)
        print("DETAILED RESULTS BY COUNTRY")
        print("=" * 80)

        by_country = defaultdict(list)
        for result in results:
            by_country[result['country']].append(result)

        for country in sorted(by_country.keys()):
            country_results = by_country[country]
            successful = [r for r in country_results if r['success']]
            failed = [r for r in country_results if not r['success']]

            # Get country stats from analysis
            country_stats = analysis['by_country'][country]
            avg_time = country_stats.get('avg_response_time', 0)

            print(f"\n{country} ({len(successful)}/{len(country_results)} successful, "
                  f"avg: {avg_time}ms)")
            print("-" * 80)

            if successful:
                for result in successful[:5]:  # Show first 5 successful
                    answers_str = ', '.join(result['answers'])
                    ttl_str = f"TTL: {result['ttl']}s" if result['ttl'] else ""
                    print(f"  ✓ {result['provider']} ({result['resolver_ip']}) "
                          f"- {result['response_time']}ms {ttl_str}")
                    print(f"    → {answers_str}")

                if len(successful) > 5:
                    print(f"  ... and {len(successful) - 5} more successful queries")

            if show_errors and failed:
                print(f"  Failed queries: {len(failed)}")
                for result in failed[:3]:  # Show first 3 failures
                    print(f"  ✗ {result['provider']} ({result['resolver_ip']}) "
                          f"- {result['error']}")

    def print_stale_resolvers(self, stale_resolvers: List[Dict]):
        """Print information about resolvers with stale data."""
        if not stale_resolvers:
            print("\nNo stale resolvers detected - all resolvers returned consistent results")
            return

        print("\n" + "=" * 80)
        print(f"STALE RESOLVERS DETECTED: {len(stale_resolvers)}")
        print("=" * 80)
        print("\nThe following resolvers returned answers different from the majority:")

        for resolver in stale_resolvers:
            answers_str = ', '.join(resolver['answers'])
            print(f"\n  {resolver['provider']} ({resolver['country']})")
            print(f"    IP: {resolver['resolver_ip']}")
            print(f"    Answer: {answers_str}")
            print(f"    Timestamp: {resolver['timestamp']}")

    def export_json(self, domain: str, record_type: str, results: List[Dict],
                    analysis: Dict, output_file: str):
        """Export results to JSON file."""
        export_data = {
            'metadata': {
                'timestamp': datetime.utcnow().isoformat(),
                'domain': domain,
                'record_type': record_type,
                'total_resolvers': len(results),
                'tool_version': '2.0.0'
            },
            'analysis': analysis,
            'results': results
        }

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

        self.logger.info(f"Results exported to JSON: {output_file}")
        print(f"\nResults exported to: {output_file}")

    def export_csv(self, results: List[Dict], output_file: str):
        """Export results to CSV file."""
        if not results:
            self.logger.warning("No results to export")
            return

        fieldnames = [
            'timestamp', 'resolver_ip', 'provider', 'country', 'region', 'continent',
            'city', 'tier', 'success', 'answers', 'error', 'response_time', 'ttl'
        ]

        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                row = {
                    'timestamp': result['timestamp'],
                    'resolver_ip': result['resolver_ip'],
                    'provider': result['provider'],
                    'country': result['country'],
                    'region': result.get('region', ''),
                    'continent': result.get('continent', ''),
                    'city': result['city'],
                    'tier': result.get('tier', ''),
                    'success': result['success'],
                    'answers': '; '.join(result['answers']) if result['answers'] else '',
                    'error': result['error'] or '',
                    'response_time': result['response_time'] or '',
                    'ttl': result['ttl'] or ''
                }
                writer.writerow(row)

        self.logger.info(f"Results exported to CSV: {output_file}")
        print(f"Results exported to: {output_file}")

    def save_cache(self, domain: str, record_type: str, results: List[Dict],
                   analysis: Dict, cache_file: str):
        """Save results to cache file for later comparison."""
        cache_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'domain': domain,
            'record_type': record_type,
            'results': results,
            'analysis': analysis,
            'checksum': self._calculate_checksum(results)
        }

        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2, default=str)

        self.logger.info(f"Results cached to: {cache_file}")
        print(f"\nResults cached to: {cache_file}")

    def load_cache(self, cache_file: str) -> Optional[Dict]:
        """Load cached results from file."""
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            self.logger.info(f"Loaded cached results from: {cache_file}")
            return cache_data
        except FileNotFoundError:
            self.logger.warning(f"Cache file not found: {cache_file}")
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in cache file: {e}")
            return None

    def _calculate_checksum(self, results: List[Dict]) -> str:
        """Calculate checksum of results for change detection."""
        # Create a stable representation of answers
        answers_set = set()
        for result in results:
            if result['success']:
                for answer in result['answers']:
                    answers_set.add(answer)

        answers_str = '|'.join(sorted(answers_set))
        return hashlib.sha256(answers_str.encode()).hexdigest()

    def compare_with_cache(self, current_results: List[Dict], cached_data: Dict) -> Dict:
        """
        Compare current results with cached results.

        Returns:
            Dict with comparison analysis
        """
        current_checksum = self._calculate_checksum(current_results)
        cached_checksum = cached_data.get('checksum', '')

        comparison = {
            'changed': current_checksum != cached_checksum,
            'cached_timestamp': cached_data.get('timestamp'),
            'current_timestamp': datetime.utcnow().isoformat(),
            'cached_answers': set(),
            'current_answers': set(),
            'added_answers': set(),
            'removed_answers': set(),
            'common_answers': set()
        }

        # Extract answers
        for result in cached_data.get('results', []):
            if result['success']:
                comparison['cached_answers'].update(result['answers'])

        for result in current_results:
            if result['success']:
                comparison['current_answers'].update(result['answers'])

        # Calculate differences
        comparison['added_answers'] = comparison['current_answers'] - comparison['cached_answers']
        comparison['removed_answers'] = comparison['cached_answers'] - comparison['current_answers']
        comparison['common_answers'] = comparison['current_answers'] & comparison['cached_answers']

        # Convert sets to lists for JSON serialization
        for key in ['cached_answers', 'current_answers', 'added_answers',
                    'removed_answers', 'common_answers']:
            comparison[key] = list(comparison[key])

        return comparison

    def print_comparison(self, comparison: Dict):
        """Print cache comparison results."""
        print("\n" + "=" * 80)
        print("CACHE COMPARISON")
        print("=" * 80)

        print(f"\nCached Results: {comparison['cached_timestamp']}")
        print(f"Current Results: {comparison['current_timestamp']}")
        print(f"\nChanges Detected: {'YES' if comparison['changed'] else 'NO'}")

        if comparison['changed']:
            if comparison['added_answers']:
                print("\nAdded Answers:")
                for answer in comparison['added_answers']:
                    print(f"  + {answer}")

            if comparison['removed_answers']:
                print("\nRemoved Answers:")
                for answer in comparison['removed_answers']:
                    print(f"  - {answer}")

        if comparison['common_answers']:
            print(f"\nUnchanged Answers ({len(comparison['common_answers'])}):")
            for answer in comparison['common_answers']:
                print(f"  = {answer}")


def print_progress(completed: int, total: int):
    """Print progress indicator."""
    percentage = (completed / total) * 100
    bar_length = 50
    filled_length = int(bar_length * completed / total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f'\rProgress: |{bar}| {percentage:.1f}% ({completed}/{total})', end='', flush=True)
    if completed == total:
        print()


def validate_config_file(config_file: str) -> Tuple[bool, List[str], Dict]:
    """
    Validate DNS resolver configuration file.

    Returns:
        Tuple of (is_valid, errors, data)
    """
    errors = []
    data = {}

    # Check file exists
    if not Path(config_file).exists():
        return False, [f"Config file not found: {config_file}"], {}

    # Try to load JSON
    try:
        with open(config_file, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"], {}
    except Exception as e:
        return False, [f"Error reading file: {e}"], {}

    # Validate structure
    if 'resolvers' not in data:
        errors.append("Missing 'resolvers' key in config file")
        return False, errors, data

    resolvers = data.get('resolvers', [])
    if not isinstance(resolvers, list):
        errors.append("'resolvers' must be a list")
        return False, errors, data

    if len(resolvers) == 0:
        errors.append("No resolvers defined in config file")

    # Validate each resolver
    required_fields = ['ip', 'provider', 'country']
    optional_fields = ['country_code', 'region', 'continent', 'city', 'tier', 'tags']

    for idx, resolver in enumerate(resolvers):
        if not isinstance(resolver, dict):
            errors.append(f"Resolver {idx}: Must be a dictionary")
            continue

        # Check required fields
        for field in required_fields:
            if field not in resolver:
                errors.append(f"Resolver {idx}: Missing required field '{field}'")

        # Validate IP address format (basic)
        if 'ip' in resolver:
            ip = resolver['ip']
            if not isinstance(ip, str) or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                errors.append(f"Resolver {idx}: Invalid IP address format: {ip}")

        # Validate tags if present
        if 'tags' in resolver and not isinstance(resolver['tags'], list):
            errors.append(f"Resolver {idx}: 'tags' must be a list")

    is_valid = len(errors) == 0
    return is_valid, errors, data


def print_config_validation_report(config_file: str, is_valid: bool, errors: List[str], data: Dict):
    """Print configuration validation report."""
    print("=" * 80)
    print("DNS RESOLVER CONFIGURATION VALIDATION")
    print("=" * 80)
    print(f"\nFile: {config_file}")
    print(f"Status: {'✓ VALID' if is_valid else '✗ INVALID'}")

    if data and 'resolvers' in data:
        resolvers = data['resolvers']
        print(f"Total Resolvers: {len(resolvers)}")

        # Count by country
        countries = defaultdict(int)
        for r in resolvers:
            if isinstance(r, dict):
                countries[r.get('country', 'Unknown')] += 1

        print(f"Countries: {len(countries)}")

        # Count by region
        regions = defaultdict(int)
        for r in resolvers:
            if isinstance(r, dict):
                region = r.get('region', 'Unknown')
                regions[region] += 1

        print(f"Regions: {len(regions)}")

        # Count by tier
        tiers = defaultdict(int)
        for r in resolvers:
            if isinstance(r, dict):
                tier = r.get('tier', 'Unknown')
                tiers[tier] += 1

        if tiers:
            print(f"\nTier Distribution:")
            for tier, count in sorted(tiers.items()):
                print(f"  {tier}: {count} resolvers")

    if errors:
        print(f"\n{'Errors' if not is_valid else 'Warnings'}: {len(errors)}")
        for error in errors:
            print(f"  - {error}")
    else:
        print("\n✓ No errors found")

    print("=" * 80)


def validate_cli_args(args):
    """Validate CLI arguments and exit on error."""
    errors = []

    # Domain is required unless --validate-config is used
    if not args.validate_config and not args.domain:
        errors.append("Domain argument is required (unless using --validate-config)")

    # Validate timeout
    if args.timeout <= 0:
        errors.append("Timeout must be positive")
    if args.timeout > 60:
        errors.append("Timeout should not exceed 60 seconds")

    # Validate retry count
    if args.retry_count < 0:
        errors.append("Retry count cannot be negative")
    if args.retry_count > 10:
        errors.append("Retry count should not exceed 10")

    # Validate workers
    if args.workers <= 0:
        errors.append("Workers must be positive")
    if args.workers > 500:
        errors.append("Workers should not exceed 500")

    # Validate rate limit
    if args.rate_limit is not None and args.rate_limit <= 0:
        errors.append("Rate limit must be positive")

    # Validate limit
    if args.limit is not None and args.limit <= 0:
        errors.append("Limit must be positive")

    # Check config file exists (only if not using validate-config, which has its own check)
    if not args.validate_config and not Path(args.config).exists():
        errors.append(f"Config file not found: {args.config}")

    # Validate compare cache file exists
    if args.compare and not Path(args.compare).exists():
        errors.append(f"Cache file for comparison not found: {args.compare}")

    if errors:
        print("Error: Invalid arguments:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog='dns-cache-validator',
        description='Global DNS Cache Validator - Production-grade DNS propagation validation tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic A record query
  %(prog)s example.com

  # Query specific record type
  %(prog)s example.com -t AAAA
  %(prog)s example.com -t MX
  %(prog)s _dmarc.example.com -t TXT

  # Filter by country (codes or names)
  %(prog)s example.com --country US,CA,UK
  %(prog)s example.com --country "United States,Canada"

  # Filter by region
  %(prog)s example.com --region europe
  %(prog)s example.com --region asia,oceania

  # Export results
  %(prog)s example.com --json results.json
  %(prog)s example.com --csv results.csv
  %(prog)s example.com --output-all results

  # Cache and compare mode
  %(prog)s example.com --cache dns-cache.json
  %(prog)s example.com --compare dns-cache.json

  # Production monitoring
  %(prog)s example.com --summary --cache current.json --log-file dns.log
  %(prog)s example.com --region europe --workers 100 --timeout 3 --detailed

  # Advanced filtering
  %(prog)s example.com --tier tier1 --region north_america --detailed
  %(prog)s example.com --tags public,secure --show-errors

  # Validate configuration
  %(prog)s --validate-config
  %(prog)s --validate-config -c custom_resolvers.json

Record Types Supported:
  A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR, CAA, DNSKEY, DS, NSEC, NSEC3,
  RRSIG, TLSA, SPF, NAPTR, SSHFP

Regions:
  north_america, south_america, europe, asia, middle_east, africa, oceania, russia_cis

Exit Codes:
  0 - Success (consistency score >= 95%%)
  1 - Error (more failures than successes or invalid arguments)
  2 - Warning (consistency score < 95%%)
        """
    )

    # Version flag
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.0.0')

    # Validation mode (makes domain optional)
    parser.add_argument('--validate-config', action='store_true',
                        help='Validate DNS resolver configuration file and exit')

    # Required arguments (optional if --validate-config is used)
    parser.add_argument('domain', nargs='?', help='Domain to validate')

    # DNS query options
    dns_group = parser.add_argument_group('DNS Query Options')
    dns_group.add_argument('-t', '--type', default='A', dest='record_type',
                           choices=sorted(list(VALID_RECORD_TYPES)),
                           metavar='TYPE',
                           help='DNS record type (default: A). Choices: A, AAAA, CNAME, MX, NS, TXT, etc.')
    dns_group.add_argument('--type-id', type=int, metavar='ID', dest='type_id',
                           help='DNS record type ID (1-65535) for unsupported types. Overrides --type.')
    dns_group.add_argument('--timeout', type=int, default=5, metavar='SECONDS',
                           help='Query timeout in seconds (default: 5, max: 60)')
    dns_group.add_argument('--retry', type=int, default=2, dest='retry_count', metavar='COUNT',
                           help='Number of retries for failed queries (default: 2, max: 10)')
    dns_group.add_argument('--check-dnssec', action='store_true',
                           help='Check DNSSEC validation status for resolvers')
    dns_group.add_argument('--watch', type=int, metavar='INTERVAL',
                           help='Continuous monitoring mode - repeat scan every N seconds')
    dns_group.add_argument('--domains-file', type=str, metavar='FILE',
                           help='File containing list of domains to scan (one per line)')

    # Filtering options
    filter_group = parser.add_argument_group('Resolver Filtering')
    filter_group.add_argument('--country', type=str, metavar='CODES',
                              help='Filter by country codes or names (comma-separated, e.g., US,CA,UK)')
    filter_group.add_argument('--region', type=str, metavar='REGIONS',
                              help='Filter by region (comma-separated, e.g., europe,asia)')
    filter_group.add_argument('--tier', type=str, metavar='TIERS',
                              help='Filter by tier level (comma-separated, e.g., tier1,tier2)')
    filter_group.add_argument('--tags', type=str, metavar='TAGS',
                              help='Filter by tags (comma-separated, e.g., public,secure)')
    filter_group.add_argument('-l', '--limit', type=int, metavar='N',
                              help='Limit number of resolvers to query (useful for testing)')

    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('-w', '--workers', type=int, default=50, metavar='N',
                            help='Maximum concurrent queries (default: 50, max: 500)')
    perf_group.add_argument('--rate-limit', type=float, metavar='QPS',
                            help='Rate limit in queries per second (no limit by default)')

    # Output options
    output_group = parser.add_argument_group('Output Options')

    # Mutually exclusive output modes
    output_mode = output_group.add_mutually_exclusive_group()
    output_mode.add_argument('--summary', action='store_true',
                             help='Brief summary mode (mutually exclusive with --detailed)')
    output_mode.add_argument('-d', '--detailed', action='store_true',
                             help='Show detailed results by country (mutually exclusive with --summary)')

    output_group.add_argument('--show-errors', action='store_true',
                              help='Show error details in detailed view')
    output_group.add_argument('--show-stale', action='store_true',
                              help='Show resolvers with potentially stale data')
    output_group.add_argument('--json', type=str, dest='json_output', metavar='FILE',
                              help='Export results to JSON file')
    output_group.add_argument('--csv', type=str, dest='csv_output', metavar='FILE',
                              help='Export results to CSV file')
    output_group.add_argument('--output-all', type=str, metavar='BASENAME',
                              help='Export to both JSON and CSV with given basename')

    # Cache options
    cache_group = parser.add_argument_group('Cache & Comparison')
    cache_group.add_argument('--cache', type=str, metavar='FILE',
                             help='Cache results to file for later comparison')
    cache_group.add_argument('--compare', type=str, metavar='FILE',
                             help='Compare current results with cached file')

    # Configuration options
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument('-c', '--config', default='dns_resolvers.json', metavar='FILE',
                              help='Path to DNS resolvers config file (default: dns_resolvers.json, env: DNS_CONFIG)')
    config_group.add_argument('--log-file', type=str, metavar='FILE',
                              help='Write logs to file (console only by default)')
    config_group.add_argument('--log-level', default='INFO', metavar='LEVEL',
                              choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                              help='Logging level (default: INFO)')

    args = parser.parse_args()

    # Support environment variables
    if args.config == 'dns_resolvers.json' and 'DNS_CONFIG' in os.environ:
        args.config = os.environ['DNS_CONFIG']

    # Validate CLI arguments
    validate_cli_args(args)

    # Handle config validation mode
    if args.validate_config:
        is_valid, errors, data = validate_config_file(args.config)
        print_config_validation_report(args.config, is_valid, errors, data)
        sys.exit(0 if is_valid else 1)

    # Load domains from file if specified
    domains_to_scan = []
    if args.domains_file:
        try:
            with open(args.domains_file, 'r') as f:
                domains_to_scan = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"Loaded {len(domains_to_scan)} domains from {args.domains_file}")
        except FileNotFoundError:
            print(f"Error: Domains file not found: {args.domains_file}", file=sys.stderr)
            sys.exit(1)
    elif args.domain:
        domains_to_scan = [args.domain]
    else:
        print("Error: Either domain or --domains-file must be specified", file=sys.stderr)
        sys.exit(1)

    # Watch mode setup
    watch_mode = args.watch is not None
    watch_interval = args.watch if watch_mode else 0
    iteration = 0

    # Create validator instance
    validator = DNSCacheValidator(
        config_file=args.config,
        timeout=args.timeout,
        max_workers=args.workers,
        retry_count=args.retry_count,
        rate_limit=args.rate_limit,
        log_file=args.log_file,
        log_level=args.log_level
    )

    # Get type_id if provided
    type_id = getattr(args, 'type_id', None)

    # Validate record type
    if not validator.validate_record_type(args.record_type, type_id):
        sys.exit(1)

    # Main scanning loop (supports watch mode and bulk domains)
    try:
        while True:
            iteration += 1

            if watch_mode and iteration > 1:
                print(f"\n{'='*80}")
                print(f"Watch Mode - Iteration #{iteration} - {datetime.utcnow().isoformat()}")
                print(f"{'='*80}\n")

            # Process each domain
            for domain_idx, domain in enumerate(domains_to_scan, 1):
                # Validate domain
                if not validator.validate_domain(domain):
                    print(f"Skipping invalid domain: {domain}")
                    continue

                if len(domains_to_scan) > 1:
                    print(f"\n[Domain {domain_idx}/{len(domains_to_scan)}]: {domain}")

                # Filter resolvers
                countries = args.country.split(',') if args.country else None
                regions = args.region.split(',') if args.region else None
                tiers = args.tier.split(',') if args.tier else None
                tags = args.tags.split(',') if args.tags else None

                filtered_resolvers = validator.filter_resolvers(
                    countries=countries,
                    regions=regions,
                    tiers=tiers,
                    tags=tags
                )

                if not filtered_resolvers:
                    print("Error: No resolvers match the specified filters")
                    continue

                # Apply limit if specified
                if args.limit:
                    filtered_resolvers = filtered_resolvers[:args.limit]

                # Perform DNS validation
                display_type = f"Type ID {type_id}" if type_id else f"{args.record_type} records"
                print(f"\nQuerying {len(filtered_resolvers)} DNS resolvers for {domain} "
                      f"({display_type})...")
                print(f"Timeout: {args.timeout}s | Max concurrent: {args.workers}")
                print("-" * 80)

                results = validator.validate_domain_scan(
                    domain,
                    args.record_type,
                    filtered_resolvers,
                    progress_callback=print_progress,
                    type_id=type_id
                )

                print("-" * 80)

                # Analyze results
                analysis = validator.analyze_results(results)

                # Print summary
                output_mode = 'summary' if args.summary else 'default'
                validator.print_summary(analysis, mode=output_mode)

                # Print detailed results if requested
                if args.detailed:
                    validator.print_detailed_results(results, analysis, args.show_errors)

                # Show stale resolvers if requested
                if args.show_stale:
                    stale_resolvers = validator.detect_stale_resolvers(results, analysis)
                    validator.print_stale_resolvers(stale_resolvers)

                # Export results (append iteration number in watch mode)
                output_suffix = f"_iter{iteration}" if watch_mode else ""
                domain_suffix = f"_{domain.replace('.', '_')}" if len(domains_to_scan) > 1 else ""

                if args.json_output:
                    json_file = args.json_output.replace('.json', f'{domain_suffix}{output_suffix}.json')
                    validator.export_json(domain, args.record_type, results, analysis, json_file)

                if args.csv_output:
                    csv_file = args.csv_output.replace('.csv', f'{domain_suffix}{output_suffix}.csv')
                    validator.export_csv(results, csv_file)

                if args.output_all:
                    json_file = f"{args.output_all}{domain_suffix}{output_suffix}.json"
                    csv_file = f"{args.output_all}{domain_suffix}{output_suffix}.csv"
                    validator.export_json(domain, args.record_type, results, analysis, json_file)
                    validator.export_csv(results, csv_file)

                # Cache results if requested
                if args.cache:
                    cache_file = args.cache.replace('.json', f'{domain_suffix}{output_suffix}.json')
                    validator.save_cache(domain, args.record_type, results, analysis, cache_file)

                # Compare with cached results if requested
                if args.compare:
                    cached_data = validator.load_cache(args.compare)
                    if cached_data:
                        comparison = validator.compare_with_cache(results, cached_data)
                        validator.print_comparison(comparison)

            # Exit if not in watch mode
            if not watch_mode:
                # Exit with appropriate code based on consistency of last domain
                if analysis['consistency_score'] < 0.95:
                    sys.exit(2)  # Warning: low consistency
                elif analysis['failed'] > analysis['successful']:
                    sys.exit(1)  # Error: more failures than successes
                else:
                    sys.exit(0)  # Success

            # Wait for next iteration in watch mode
            print(f"\n[Watch Mode] Sleeping for {watch_interval} seconds... (Press Ctrl+C to exit)")
            time.sleep(watch_interval)

    except KeyboardInterrupt:
        print("\n\n[Watch Mode] Interrupted by user. Exiting...")
        sys.exit(0)


if __name__ == '__main__':
    main()
