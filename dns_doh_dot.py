#!/usr/bin/env python3
"""
DNS over HTTPS (DoH) and DNS over TLS (DoT) support module
Provides encrypted DNS query capabilities
"""

import dns.message
import dns.query
import dns.rdatatype
import requests
import ssl
import base64
import time
from typing import Dict, Optional, List


class DoHResolver:
    """DNS over HTTPS resolver"""

    def __init__(self, server_url: str, timeout: int = 5):
        """
        Initialize DoH resolver.

        Args:
            server_url: DoH server URL (e.g., 'https://cloudflare-dns.com/dns-query')
            timeout: Query timeout in seconds
        """
        self.server_url = server_url
        self.timeout = timeout

    def query(self, domain: str, record_type: str = 'A') -> Dict:
        """
        Query domain via DoH.

        Args:
            domain: Domain to query
            record_type: DNS record type

        Returns:
            Dict with query results
        """
        result = {
            'success': False,
            'answers': [],
            'response_time': None,
            'error': None,
            'protocol': 'DoH',
            'server': self.server_url
        }

        try:
            start_time = time.time()

            # Create DNS query message
            query = dns.message.make_query(domain, record_type)
            wire_query = query.to_wire()

            # Make HTTPS POST request
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
                # Parse DNS response
                dns_response = dns.message.from_wire(response.content)
                result['success'] = True
                result['response_time'] = round(response_time, 2)

                for rrset in dns_response.answer:
                    for rdata in rrset:
                        result['answers'].append(str(rdata))
            else:
                result['error'] = f"HTTP {response.status_code}"

        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = str(e)

        return result

    def query_get(self, domain: str, record_type: str = 'A') -> Dict:
        """
        Query domain via DoH using GET method (RFC 8484).

        Args:
            domain: Domain to query
            record_type: DNS record type

        Returns:
            Dict with query results
        """
        result = {
            'success': False,
            'answers': [],
            'response_time': None,
            'error': None,
            'protocol': 'DoH-GET',
            'server': self.server_url
        }

        try:
            start_time = time.time()

            # Create DNS query message
            query = dns.message.make_query(domain, record_type)
            wire_query = query.to_wire()

            # Base64url encode (RFC 8484)
            dns_param = base64.urlsafe_b64encode(wire_query).decode('utf-8').rstrip('=')

            # Make HTTPS GET request
            params = {'dns': dns_param}
            headers = {'Accept': 'application/dns-message'}

            response = requests.get(
                self.server_url,
                params=params,
                headers=headers,
                timeout=self.timeout
            )

            response_time = (time.time() - start_time) * 1000

            if response.status_code == 200:
                # Parse DNS response
                dns_response = dns.message.from_wire(response.content)
                result['success'] = True
                result['response_time'] = round(response_time, 2)

                for rrset in dns_response.answer:
                    for rdata in rrset:
                        result['answers'].append(str(rdata))
            else:
                result['error'] = f"HTTP {response.status_code}"

        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = str(e)

        return result


class DoTResolver:
    """DNS over TLS resolver"""

    def __init__(self, server_ip: str, server_name: str, port: int = 853, timeout: int = 5):
        """
        Initialize DoT resolver.

        Args:
            server_ip: IP address of DoT server
            server_name: Hostname for SNI (Server Name Indication)
            port: DoT port (default 853)
            timeout: Query timeout in seconds
        """
        self.server_ip = server_ip
        self.server_name = server_name
        self.port = port
        self.timeout = timeout

    def query(self, domain: str, record_type: str = 'A') -> Dict:
        """
        Query domain via DoT.

        Args:
            domain: Domain to query
            record_type: DNS record type

        Returns:
            Dict with query results
        """
        result = {
            'success': False,
            'answers': [],
            'response_time': None,
            'error': None,
            'protocol': 'DoT',
            'server': f"{self.server_ip}:{self.port}"
        }

        try:
            start_time = time.time()

            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            # Create DNS query
            query = dns.message.make_query(domain, record_type)

            # Query via TLS
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

        except dns.exception.Timeout:
            result['error'] = 'Timeout'
        except ssl.SSLError as e:
            result['error'] = f"SSL Error: {e}"
        except Exception as e:
            result['error'] = str(e)

        return result


# Popular DoH/DoT providers
DOH_PROVIDERS = {
    'cloudflare': 'https://cloudflare-dns.com/dns-query',
    'google': 'https://dns.google/dns-query',
    'quad9': 'https://dns.quad9.net/dns-query',
    'cleanbrowsing': 'https://doh.cleanbrowsing.org/doh/family-filter/',
    'adguard': 'https://dns.adguard.com/dns-query',
    'nextdns': 'https://dns.nextdns.io/dns-query',
}

DOT_PROVIDERS = {
    'cloudflare': {'ip': '1.1.1.1', 'hostname': 'cloudflare-dns.com'},
    'google': {'ip': '8.8.8.8', 'hostname': 'dns.google'},
    'quad9': {'ip': '9.9.9.9', 'hostname': 'dns.quad9.net'},
    'adguard': {'ip': '94.140.14.14', 'hostname': 'dns.adguard.com'},
}


def test_doh_providers(domain: str = 'example.com', record_type: str = 'A') -> List[Dict]:
    """
    Test all DoH providers.

    Args:
        domain: Domain to test
        record_type: Record type to query

    Returns:
        List of results from all providers
    """
    results = []

    for provider, url in DOH_PROVIDERS.items():
        resolver = DoHResolver(url)
        result = resolver.query(domain, record_type)
        result['provider'] = provider
        results.append(result)

    return results


def test_dot_providers(domain: str = 'example.com', record_type: str = 'A') -> List[Dict]:
    """
    Test all DoT providers.

    Args:
        domain: Domain to test
        record_type: Record type to query

    Returns:
        List of results from all providers
    """
    results = []

    for provider, config in DOT_PROVIDERS.items():
        resolver = DoTResolver(config['ip'], config['hostname'])
        result = resolver.query(domain, record_type)
        result['provider'] = provider
        results.append(result)

    return results


if __name__ == '__main__':
    # Test DoH/DoT functionality
    import sys

    domain = sys.argv[1] if len(sys.argv) > 1 else 'example.com'

    print(f"Testing DoH providers for {domain}...")
    print("=" * 60)
    doh_results = test_doh_providers(domain)

    for result in doh_results:
        status = "✓" if result['success'] else "✗"
        print(f"{status} {result['provider']:15} - {result['response_time'] or 'N/A':<6}ms - {result['answers'] or result['error']}")

    print(f"\nTesting DoT providers for {domain}...")
    print("=" * 60)
    dot_results = test_dot_providers(domain)

    for result in dot_results:
        status = "✓" if result['success'] else "✗"
        print(f"{status} {result['provider']:15} - {result['response_time'] or 'N/A':<6}ms - {result['answers'] or result['error']}")
