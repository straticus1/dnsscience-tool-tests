#!/usr/bin/env python3
"""
Advanced DNS Features Module
Includes resolver fingerprinting, GeoIP validation, heatmap generation,
negative response testing, and automated resolver discovery
"""

import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import requests
import socket
import time
import json
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


class ResolverFingerprinter:
    """Detect DNS resolver software and version"""

    def __init__(self, timeout: int = 5):
        """
        Initialize fingerprinter.

        Args:
            timeout: Query timeout in seconds
        """
        self.timeout = timeout

    def fingerprint(self, resolver_ip: str) -> Dict:
        """
        Fingerprint a DNS resolver.

        Args:
            resolver_ip: IP address of resolver

        Returns:
            Dict with fingerprint results
        """
        result = {
            'resolver_ip': resolver_ip,
            'software': 'Unknown',
            'version': None,
            'features': [],
            'edns_support': False,
            'dnssec_support': False,
            'tcp_support': False
        }

        try:
            # Check EDNS support
            query = dns.message.make_query('version.bind', 'TXT', want_dnssec=True)
            try:
                response = dns.query.udp(query, resolver_ip, timeout=self.timeout)
                result['edns_support'] = response.edns >= 0
            except:
                pass

            # Try to get version via version.bind (CHAOS class)
            try:
                query_chaos = dns.message.make_query('version.bind', 'TXT', 'CH')
                response_chaos = dns.query.udp(query_chaos, resolver_ip, timeout=self.timeout)

                for rrset in response_chaos.answer:
                    for rdata in rrset:
                        version_str = str(rdata).strip('"')
                        result['software'], result['version'] = self._parse_version(version_str)
                        break
            except:
                pass

            # Check TCP support
            try:
                query_tcp = dns.message.make_query('example.com', 'A')
                response_tcp = dns.query.tcp(query_tcp, resolver_ip, timeout=self.timeout)
                result['tcp_support'] = True
            except:
                pass

            # Check DNSSEC support
            try:
                query_dnssec = dns.message.make_query('dnssec-failed.org', 'A', want_dnssec=True)
                response_dnssec = dns.query.udp(query_dnssec, resolver_ip, timeout=self.timeout)
                result['dnssec_support'] = bool(response_dnssec.flags & dns.flags.AD)
            except:
                pass

        except Exception as e:
            result['error'] = str(e)

        return result

    def _parse_version(self, version_str: str) -> Tuple[str, Optional[str]]:
        """
        Parse version string to extract software and version.

        Args:
            version_str: Version string from resolver

        Returns:
            Tuple of (software, version)
        """
        # Common patterns
        if 'bind' in version_str.lower():
            parts = version_str.split()
            version = parts[1] if len(parts) > 1 else None
            return 'BIND', version
        elif 'unbound' in version_str.lower():
            parts = version_str.split()
            version = parts[1] if len(parts) > 1 else None
            return 'Unbound', version
        elif 'powerdns' in version_str.lower():
            return 'PowerDNS', None
        elif 'dnsmasq' in version_str.lower():
            return 'dnsmasq', None
        elif 'microsoft' in version_str.lower():
            return 'Microsoft DNS', None

        return 'Unknown', version_str if version_str else None


class GeoIPValidator:
    """Validate resolver geographic locations"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize GeoIP validator.

        Args:
            api_key: Optional API key for GeoIP service
        """
        self.api_key = api_key

    def validate_location(self, resolver_ip: str, claimed_country: str) -> Dict:
        """
        Validate resolver's claimed location.

        Args:
            resolver_ip: IP address of resolver
            claimed_country: Country claimed in resolver config

        Returns:
            Dict with validation results
        """
        result = {
            'resolver_ip': resolver_ip,
            'claimed_country': claimed_country,
            'actual_country': None,
            'actual_city': None,
            'latitude': None,
            'longitude': None,
            'location_match': False,
            'error': None
        }

        try:
            # Use ip-api.com (free, no key needed)
            response = requests.get(f'http://ip-api.com/json/{resolver_ip}', timeout=5)

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    result['actual_country'] = data.get('country')
                    result['actual_city'] = data.get('city')
                    result['latitude'] = data.get('lat')
                    result['longitude'] = data.get('lon')
                    result['location_match'] = (
                        claimed_country.lower() == data.get('country', '').lower()
                    )
                else:
                    result['error'] = data.get('message', 'Unknown error')
            else:
                result['error'] = f"HTTP {response.status_code}"

        except Exception as e:
            result['error'] = str(e)

        return result


class NegativeResponseTester:
    """Test NXDOMAIN and negative response behavior"""

    def __init__(self, timeout: int = 5):
        """
        Initialize negative response tester.

        Args:
            timeout: Query timeout in seconds
        """
        self.timeout = timeout

    def test_nxdomain(self, resolver_ip: str) -> Dict:
        """
        Test NXDOMAIN response behavior.

        Args:
            resolver_ip: IP address of resolver

        Returns:
            Dict with test results
        """
        result = {
            'resolver_ip': resolver_ip,
            'nxdomain_works': False,
            'wildcard_detected': False,
            'hijacking_detected': False,
            'error': None
        }

        try:
            # Test with guaranteed non-existent domain
            test_domain = f'nonexistent{time.time()}.invalid'

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.timeout = self.timeout

            try:
                answers = resolver.resolve(test_domain, 'A')
                # If we got an answer for a non-existent domain, it's hijacking
                result['hijacking_detected'] = True
                result['wildcard_detected'] = True
            except dns.resolver.NXDOMAIN:
                # Correct behavior
                result['nxdomain_works'] = True
            except dns.resolver.NoAnswer:
                # NODATA response - also acceptable
                result['nxdomain_works'] = True
            except Exception as e:
                result['error'] = str(e)

        except Exception as e:
            result['error'] = str(e)

        return result


class HeatmapGenerator:
    """Generate response time heatmaps"""

    def generate_geographic_heatmap(
        self,
        results: List[Dict],
        output_file: str = 'response_time_heatmap.png'
    ):
        """
        Generate geographic response time heatmap.

        Args:
            results: Query results with geographic data
            output_file: Output file path
        """
        try:
            # Prepare data
            countries = []
            response_times = []

            by_country = defaultdict(list)
            for result in results:
                if result['success'] and result.get('response_time'):
                    by_country[result['country']].append(result['response_time'])

            # Calculate averages
            for country, times in by_country.items():
                countries.append(country)
                response_times.append(np.mean(times))

            # Sort by response time
            sorted_pairs = sorted(zip(countries, response_times), key=lambda x: x[1])
            countries, response_times = zip(*sorted_pairs) if sorted_pairs else ([], [])

            # Create horizontal bar chart
            fig, ax = plt.subplots(figsize=(12, max(8, len(countries) * 0.3)))

            # Color based on response time (green=fast, red=slow)
            colors = plt.cm.RdYlGn_r(np.array(response_times) / max(response_times) if response_times else [])

            bars = ax.barh(countries, response_times, color=colors)

            ax.set_xlabel('Average Response Time (ms)')
            ax.set_ylabel('Country')
            ax.set_title('DNS Response Time by Country')
            ax.grid(axis='x', alpha=0.3)

            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()

            print(f"Heatmap saved to: {output_file}")

        except Exception as e:
            print(f"Error generating heatmap: {e}")

    def generate_time_series_heatmap(
        self,
        historical_data: List[Tuple],
        output_file: str = 'time_series_heatmap.png'
    ):
        """
        Generate time series heatmap of DNS metrics.

        Args:
            historical_data: List of (timestamp, value) tuples
            output_file: Output file path
        """
        try:
            if not historical_data:
                print("No data to plot")
                return

            timestamps, values = zip(*historical_data)

            fig, ax = plt.subplots(figsize=(14, 6))
            ax.plot(timestamps, values, marker='o', linestyle='-', linewidth=2)

            ax.set_xlabel('Time')
            ax.set_ylabel('Value')
            ax.set_title('DNS Metrics Over Time')
            ax.grid(True, alpha=0.3)

            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()

            print(f"Time series heatmap saved to: {output_file}")

        except Exception as e:
            print(f"Error generating time series heatmap: {e}")


class ResolverDiscovery:
    """Automated DNS resolver discovery"""

    def __init__(self):
        """Initialize resolver discovery"""
        self.known_providers = []

    def discover_public_resolvers(self) -> List[Dict]:
        """
        Discover additional public DNS resolvers.

        Returns:
            List of discovered resolvers
        """
        discovered = []

        # List of well-known public DNS providers (expanding the built-in list)
        additional_resolvers = [
            {'ip': '185.228.168.168', 'provider': 'CleanBrowsing', 'tier': 'tier2'},
            {'ip': '76.76.2.2', 'provider': 'ControlD', 'tier': 'tier1'},
            {'ip': '45.90.28.167', 'provider': 'NextDNS', 'tier': 'tier1'},
            {'ip': '94.140.14.14', 'provider': 'AdGuard DNS', 'tier': 'tier2'},
            {'ip': '94.140.15.15', 'provider': 'AdGuard DNS', 'tier': 'tier2'},
        ]

        for resolver in additional_resolvers:
            # Test if resolver is reachable
            if self._test_resolver(resolver['ip']):
                discovered.append(resolver)

        return discovered

    def _test_resolver(self, ip: str, timeout: int = 5) -> bool:
        """
        Test if a resolver is functional.

        Args:
            ip: IP address to test
            timeout: Query timeout

        Returns:
            True if resolver works
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            resolver.timeout = timeout
            resolver.resolve('example.com', 'A')
            return True
        except:
            return False


# Example usage
if __name__ == '__main__':
    print("DNS Advanced Features Module")
    print("=" * 60)

    # Test fingerprinting
    print("\n1. Testing Resolver Fingerprinting...")
    fingerprinter = ResolverFingerprinter()
    result = fingerprinter.fingerprint('8.8.8.8')
    print(f"Google DNS (8.8.8.8):")
    print(f"  Software: {result['software']}")
    print(f"  EDNS Support: {result['edns_support']}")
    print(f"  TCP Support: {result['tcp_support']}")

    # Test negative responses
    print("\n2. Testing Negative Response Handling...")
    tester = NegativeResponseTester()
    result = tester.test_nxdomain('8.8.8.8')
    print(f"NXDOMAIN Test:")
    print(f"  Works Correctly: {result['nxdomain_works']}")
    print(f"  Hijacking Detected: {result['hijacking_detected']}")

    print("\nAdvanced features module loaded successfully!")
