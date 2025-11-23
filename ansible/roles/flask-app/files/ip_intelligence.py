"""
IP Intelligence Engine for DNS Science
Comprehensive IP address research, BGP routing, and threat intelligence

Features:
- IP geolocation (IPinfo.io)
- Threat intelligence (AbuseIPDB)
- BGP routing data (RIPEstat, BGPView)
- RBL/DNSBL checking (Spamhaus, SORBS, etc.)
- WHOIS lookups (ipwhois library)
- ASN analysis
- Route validation (RPKI)
"""

import requests
import dns.resolver
import dns.reversename
import ipaddress
import json
import time
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import concurrent.futures
import os

class IPIntelligenceEngine:
    """IP address intelligence and analysis engine"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize IP intelligence engine

        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}

        # API Keys (from environment or config)
        self.ipinfo_token = self.config.get('ipinfo_token') or os.getenv('IPINFO_TOKEN')
        self.abuseipdb_key = self.config.get('abuseipdb_key') or os.getenv('ABUSEIPDB_KEY')
        self.cloudflare_token = self.config.get('cloudflare_token') or os.getenv('CLOUDFLARE_TOKEN')

        # API Endpoints
        self.ipinfo_url = "https://ipinfo.io/{ip}/json"
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        self.ripestat_url = "https://stat.ripe.net/data/{endpoint}/data.json"
        self.bgpview_url = "https://api.bgpview.io"

        # RBL Lists (DNS-based)
        self.rbl_lists = {
            'spamhaus_zen': 'zen.spamhaus.org',
            'spamhaus_sbl': 'sbl.spamhaus.org',
            'spamhaus_xbl': 'xbl.spamhaus.org',
            'spamhaus_pbl': 'pbl.spamhaus.org',
            'sorbs': 'dnsbl.sorbs.net',
            'barracuda': 'b.barracudacentral.org',
            'spamcop': 'bl.spamcop.net',
            'cbl': 'cbl.abuseat.org',
            'psbl': 'psbl.surriel.com',
            'uceprotect_1': 'dnsbl-1.uceprotect.net'
        }

        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5

    def scan_ip(self, ip: str, full_scan: bool = True) -> Dict[str, Any]:
        """
        Comprehensive IP address scan

        Args:
            ip: IP address to scan
            full_scan: If True, include all data sources (slower)

        Returns:
            Dictionary with complete IP intelligence
        """
        start_time = time.time()
        ip_obj = ipaddress.ip_address(ip)

        result = {
            'ip': ip,
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'ip_version': ip_obj.version,
            'is_private': ip_obj.is_private,
            'is_loopback': ip_obj.is_loopback,
            'is_multicast': ip_obj.is_multicast,
            'geolocation': {},
            'network': {},
            'bgp': {},
            'reputation': {},
            'whois': {},
            'reverse_dns': {},
            'data_sources': [],
            'errors': []
        }

        # Skip scanning private/special IPs
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
            result['scan_duration_ms'] = int((time.time() - start_time) * 1000)
            result['note'] = 'Private/special IP - limited scanning'
            return result

        # Parallel data collection
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = {}

            # Geolocation (IPinfo)
            if self.ipinfo_token:
                futures['ipinfo'] = executor.submit(self._get_ipinfo_data, ip)

            # Threat Intelligence (AbuseIPDB)
            if self.abuseipdb_key:
                futures['abuseipdb'] = executor.submit(self._get_abuseipdb_data, ip)

            # BGP Data (RIPEstat)
            futures['ripestat_bgp'] = executor.submit(self._get_ripestat_bgp, ip)

            # BGP Data (BGPView) - as backup/additional data
            if full_scan:
                futures['bgpview'] = executor.submit(self._get_bgpview_data, ip)

            # WHOIS Data (RIPEstat)
            futures['whois'] = executor.submit(self._get_ripestat_whois, ip)

            # RBL Checks
            futures['rbl'] = executor.submit(self._check_rbls, ip)

            # Reverse DNS
            futures['ptr'] = executor.submit(self._get_ptr_record, ip)

            # Collect results
            for key, future in futures.items():
                try:
                    data = future.result(timeout=10)
                    if data:
                        if key == 'ipinfo':
                            self._process_ipinfo(result, data)
                        elif key == 'abuseipdb':
                            self._process_abuseipdb(result, data)
                        elif key == 'ripestat_bgp':
                            self._process_ripestat_bgp(result, data)
                        elif key == 'bgpview':
                            self._process_bgpview(result, data)
                        elif key == 'whois':
                            self._process_whois(result, data)
                        elif key == 'rbl':
                            self._process_rbl(result, data)
                        elif key == 'ptr':
                            result['reverse_dns'] = data
                        result['data_sources'].append(key)
                except Exception as e:
                    result['errors'].append({
                        'source': key,
                        'error': str(e)
                    })

        result['scan_duration_ms'] = int((time.time() - start_time) * 1000)
        return result

    def _get_ipinfo_data(self, ip: str) -> Optional[Dict]:
        """Get geolocation and network data from IPinfo.io"""
        try:
            url = self.ipinfo_url.format(ip=ip)
            if self.ipinfo_token:
                url += f"?token={self.ipinfo_token}"

            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return None
        return None

    def _get_abuseipdb_data(self, ip: str) -> Optional[Dict]:
        """Get threat intelligence from AbuseIPDB"""
        try:
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            response = requests.get(self.abuseipdb_url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return None
        return None

    def _get_ripestat_bgp(self, ip: str) -> Optional[Dict]:
        """Get BGP routing data from RIPEstat"""
        try:
            url = self.ripestat_url.format(endpoint='bgp-state')
            params = {'resource': ip}
            response = requests.get(url, params=params, timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return None
        return None

    def _get_ripestat_whois(self, ip: str) -> Optional[Dict]:
        """Get WHOIS data from RIPEstat"""
        try:
            url = self.ripestat_url.format(endpoint='whois')
            params = {'resource': ip}
            response = requests.get(url, params=params, timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return None
        return None

    def _get_bgpview_data(self, ip: str) -> Optional[Dict]:
        """Get BGP data from BGPView"""
        try:
            url = f"{self.bgpview_url}/ip/{ip}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return None
        return None

    def _check_rbls(self, ip: str) -> Dict[str, Any]:
        """Check IP against multiple RBL/DNSBL lists"""
        results = {
            'listed_in': [],
            'not_listed_in': [],
            'hit_count': 0,
            'details': {}
        }

        # Reverse IP for DNS lookups
        try:
            ip_obj = ipaddress.ip_address(ip)
            reversed_ip = '.'.join(reversed(ip.split('.')))
        except Exception:
            return results

        for rbl_name, rbl_domain in self.rbl_lists.items():
            try:
                query = f"{reversed_ip}.{rbl_domain}"
                answers = self.resolver.resolve(query, 'A')

                # Listed in RBL
                response_codes = [str(rdata) for rdata in answers]
                results['listed_in'].append(rbl_name)
                results['hit_count'] += 1
                results['details'][rbl_name] = {
                    'listed': True,
                    'response_codes': response_codes
                }
            except dns.resolver.NXDOMAIN:
                # Not listed (this is good)
                results['not_listed_in'].append(rbl_name)
                results['details'][rbl_name] = {'listed': False}
            except Exception as e:
                # Query failed
                results['details'][rbl_name] = {
                    'listed': None,
                    'error': str(e)
                }

        return results

    def _get_ptr_record(self, ip: str) -> Dict[str, Any]:
        """Get PTR (reverse DNS) record for IP"""
        try:
            reversed_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(reversed_name, 'PTR')
            ptr_records = [str(rdata) for rdata in answers]

            return {
                'has_ptr': True,
                'ptr_records': ptr_records,
                'ptr_record': ptr_records[0] if ptr_records else None
            }
        except Exception as e:
            return {
                'has_ptr': False,
                'ptr_records': [],
                'ptr_record': None,
                'error': str(e)
            }

    def _process_ipinfo(self, result: Dict, data: Dict):
        """Process IPinfo.io response"""
        result['geolocation'] = {
            'country': data.get('country'),
            'region': data.get('region'),
            'city': data.get('city'),
            'postal_code': data.get('postal'),
            'timezone': data.get('timezone'),
            'coordinates': None
        }

        if 'loc' in data:
            lat, lon = data['loc'].split(',')
            result['geolocation']['coordinates'] = {
                'latitude': float(lat),
                'longitude': float(lon)
            }

        # Network info from IPinfo
        org = data.get('org', '')
        if org:
            parts = org.split(' ', 1)
            if parts[0].startswith('AS'):
                result['network']['asn'] = int(parts[0][2:])
                result['network']['asn_name'] = parts[1] if len(parts) > 1 else None

        result['network']['organization'] = data.get('org')
        result['network']['hostname'] = data.get('hostname')

        # Privacy detection (if using paid tier)
        if 'privacy' in data:
            privacy = data['privacy']
            result['network']['is_vpn'] = privacy.get('vpn', False)
            result['network']['is_proxy'] = privacy.get('proxy', False)
            result['network']['is_tor'] = privacy.get('tor', False)
            result['network']['is_hosting'] = privacy.get('hosting', False)

    def _process_abuseipdb(self, result: Dict, data: Dict):
        """Process AbuseIPDB response"""
        if 'data' in data:
            abuse_data = data['data']
            result['reputation'] = {
                'abuse_confidence': abuse_data.get('abuseConfidenceScore', 0),
                'total_reports': abuse_data.get('totalReports', 0),
                'num_distinct_users': abuse_data.get('numDistinctUsers', 0),
                'last_reported_at': abuse_data.get('lastReportedAt'),
                'is_whitelisted': abuse_data.get('isWhitelisted', False),
                'country_code': abuse_data.get('countryCode'),
                'usage_type': abuse_data.get('usageType'),
                'isp': abuse_data.get('isp'),
                'domain': abuse_data.get('domain')
            }

            # Threat categories
            if 'reports' in abuse_data:
                categories = set()
                for report in abuse_data['reports']:
                    if 'categories' in report:
                        categories.update([str(c) for c in report['categories']])
                result['reputation']['threat_categories'] = list(categories)

    def _process_ripestat_bgp(self, result: Dict, data: Dict):
        """Process RIPEstat BGP data"""
        if 'data' in data and 'bgp_state' in data['data']:
            bgp_state = data['data']['bgp_state']

            if bgp_state:
                state = bgp_state[0] if isinstance(bgp_state, list) else bgp_state

                result['bgp'] = {
                    'prefix': state.get('target_prefix'),
                    'origin_asn': state.get('source_id'),
                    'is_announced': True,
                    'path': state.get('path', [])
                }

    def _process_bgpview(self, result: Dict, data: Dict):
        """Process BGPView response"""
        if 'data' in data:
            bgp_data = data['data']

            if 'prefixes' in bgp_data and bgp_data['prefixes']:
                prefix_data = bgp_data['prefixes'][0]

                if 'bgp' not in result or not result['bgp']:
                    result['bgp'] = {}

                result['bgp'].update({
                    'prefix': prefix_data.get('prefix'),
                    'origin_asn': prefix_data.get('asn', {}).get('asn'),
                    'asn_name': prefix_data.get('asn', {}).get('name'),
                    'asn_description': prefix_data.get('asn', {}).get('description'),
                    'asn_country': prefix_data.get('asn', {}).get('country_code')
                })

    def _process_whois(self, result: Dict, data: Dict):
        """Process WHOIS data from RIPEstat"""
        if 'data' in data and 'records' in data['data']:
            records = data['data']['records']

            whois_info = {}
            for record_group in records:
                if isinstance(record_group, list):
                    for record in record_group:
                        if isinstance(record, dict):
                            key = record.get('key', '').lower()
                            value = record.get('value')

                            if key == 'netname':
                                whois_info['net_name'] = value
                            elif key == 'descr' or key == 'description':
                                whois_info['description'] = value
                            elif key == 'country':
                                whois_info['country'] = value
                            elif key == 'abuse-mailbox':
                                whois_info['abuse_contact'] = value
                            elif key == 'inetnum' or key == 'netrange':
                                whois_info['net_range'] = value

            result['whois'] = whois_info

    def _process_rbl(self, result: Dict, rbl_data: Dict):
        """Process RBL check results"""
        result['reputation']['blacklists'] = {
            'hit_count': rbl_data.get('hit_count', 0),
            'listed_in': rbl_data.get('listed_in', []),
            'details': rbl_data.get('details', {})
        }

        # Update RBL flags
        for rbl_name in rbl_data.get('listed_in', []):
            if 'spamhaus' in rbl_name:
                result['reputation']['in_spamhaus'] = True
            elif 'sorbs' in rbl_name:
                result['reputation']['in_sorbs'] = True
            elif 'barracuda' in rbl_name:
                result['reputation']['in_barracuda'] = True
            elif 'spamcop' in rbl_name:
                result['reputation']['in_spamcop'] = True

    def get_asn_info(self, asn: int) -> Dict[str, Any]:
        """
        Get detailed information about an Autonomous System

        Args:
            asn: AS number

        Returns:
            Dictionary with AS information
        """
        result = {
            'asn': asn,
            'as_name': None,
            'organization': None,
            'country': None,
            'prefixes': [],
            'peers': [],
            'upstreams': [],
            'downstreams': []
        }

        try:
            # Get AS info from BGPView
            url = f"{self.bgpview_url}/asn/{asn}"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    as_data = data['data']
                    result['as_name'] = as_data.get('name')
                    result['description'] = as_data.get('description_short')
                    result['country'] = as_data.get('country_code')
                    result['website'] = as_data.get('website')
                    result['email_contacts'] = as_data.get('email_contacts', [])
                    result['abuse_contacts'] = as_data.get('abuse_contacts', [])

            # Get prefixes
            prefix_url = f"{self.bgpview_url}/asn/{asn}/prefixes"
            prefix_response = requests.get(prefix_url, timeout=5)

            if prefix_response.status_code == 200:
                prefix_data = prefix_response.json()
                if 'data' in prefix_data:
                    ipv4 = prefix_data['data'].get('ipv4_prefixes', [])
                    ipv6 = prefix_data['data'].get('ipv6_prefixes', [])
                    result['prefixes'] = ipv4 + ipv6

        except Exception as e:
            result['error'] = str(e)

        return result

    def scan_ip_range(self, cidr: str, max_ips: int = 256) -> Dict[str, Any]:
        """
        Scan an IP range (CIDR)

        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            max_ips: Maximum IPs to scan (safety limit)

        Returns:
            Dictionary with range scan results
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            return {'error': f'Invalid CIDR: {str(e)}'}

        total_ips = network.num_addresses
        if total_ips > max_ips:
            return {
                'error': f'Range too large ({total_ips} IPs). Maximum allowed: {max_ips}'
            }

        result = {
            'cidr': str(network),
            'total_ips': total_ips,
            'scanned_ips': 0,
            'results': [],
            'summary': {
                'alive_ips': 0,
                'threat_ips': 0,
                'blacklisted_ips': 0,
                'countries': {},
                'asns': {}
            }
        }

        # Scan each IP
        for ip in network.hosts():
            ip_str = str(ip)
            scan_result = self.scan_ip(ip_str, full_scan=False)

            result['results'].append(scan_result)
            result['scanned_ips'] += 1

            # Update summary
            if not scan_result.get('is_private'):
                result['summary']['alive_ips'] += 1

                # Track threats
                abuse_confidence = scan_result.get('reputation', {}).get('abuse_confidence', 0)
                if abuse_confidence >= 75:
                    result['summary']['threat_ips'] += 1

                rbl_hits = scan_result.get('reputation', {}).get('blacklists', {}).get('hit_count', 0)
                if rbl_hits > 0:
                    result['summary']['blacklisted_ips'] += 1

                # Track countries
                country = scan_result.get('geolocation', {}).get('country')
                if country:
                    result['summary']['countries'][country] = result['summary']['countries'].get(country, 0) + 1

                # Track ASNs
                asn = scan_result.get('network', {}).get('asn')
                if asn:
                    result['summary']['asns'][asn] = result['summary']['asns'].get(asn, 0) + 1

        return result


# Convenience functions
def scan_ip(ip: str, config: Optional[Dict] = None) -> Dict[str, Any]:
    """Scan a single IP address"""
    engine = IPIntelligenceEngine(config)
    return engine.scan_ip(ip)


def scan_ip_range(cidr: str, config: Optional[Dict] = None, max_ips: int = 256) -> Dict[str, Any]:
    """Scan an IP range"""
    engine = IPIntelligenceEngine(config)
    return engine.scan_ip_range(cidr, max_ips)


def get_asn_info(asn: int, config: Optional[Dict] = None) -> Dict[str, Any]:
    """Get AS information"""
    engine = IPIntelligenceEngine(config)
    return engine.get_asn_info(asn)
