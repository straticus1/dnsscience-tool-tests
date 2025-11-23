#!/usr/bin/env python3
"""
DNS Science - Reverse DNS (PTR) Checker
Supports IPv4 (in-addr.arpa) and IPv6 (ip6.arpa) reverse DNS validation
"""

import socket
import ipaddress
import dns.resolver
import dns.reversename
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import re


class ReverseDNSChecker:
    """Check and validate reverse DNS (PTR) records for IPv4 and IPv6"""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def check_ptr_record(self, ip_address: str) -> Dict:
        """
        Check PTR record for an IP address (IPv4 or IPv6)

        Args:
            ip_address: IP address to check (e.g., "8.8.8.8" or "2001:4860:4860::8888")

        Returns:
            Dict with PTR record information and validation results
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            ip_version = ip_obj.version

            result = {
                'ip_address': ip_address,
                'ip_version': ip_version,
                'timestamp': datetime.utcnow().isoformat(),
                'has_ptr': False,
                'ptr_hostname': None,
                'ptr_names': [],  # Can have multiple PTR records
                'reverse_zone': None,
                'is_valid': False,
                'forward_matches': False,
                'forward_lookup_result': None,
                'validation_errors': [],
                'is_private': ip_obj.is_private,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
            }

            # Get reverse DNS name
            reverse_name = dns.reversename.from_address(ip_address)
            result['reverse_zone'] = str(reverse_name)

            # Perform PTR lookup
            try:
                answers = self.resolver.resolve(reverse_name, 'PTR', raise_on_no_answer=False)

                if answers:
                    result['has_ptr'] = True
                    result['ptr_names'] = [str(rdata.target) for rdata in answers]
                    result['ptr_hostname'] = result['ptr_names'][0]  # Primary PTR

                    # Validate the PTR record
                    validation = self._validate_ptr(ip_address, result['ptr_hostname'])
                    result.update(validation)
                else:
                    result['validation_errors'].append('No PTR record found')

            except dns.resolver.NXDOMAIN:
                result['validation_errors'].append('PTR record does not exist (NXDOMAIN)')
            except dns.resolver.NoAnswer:
                result['validation_errors'].append('No PTR record in response')
            except dns.resolver.Timeout:
                result['validation_errors'].append('DNS query timeout')
            except Exception as e:
                result['validation_errors'].append(f'PTR lookup error: {str(e)}')

            return result

        except ValueError as e:
            return {
                'error': f'Invalid IP address: {str(e)}',
                'ip_address': ip_address,
                'timestamp': datetime.utcnow().isoformat()
            }

    def _validate_ptr(self, ip_address: str, ptr_hostname: str) -> Dict:
        """
        Validate PTR record and check Forward Confirmed reverse DNS (FCrDNS)

        Returns:
            Dict with validation results
        """
        validation = {
            'is_valid': True,
            'forward_matches': False,
            'forward_lookup_result': None,
            'validation_errors': []
        }

        if not ptr_hostname:
            validation['is_valid'] = False
            validation['validation_errors'].append('PTR hostname is empty')
            return validation

        # Check if PTR ends with a dot (FQDN requirement)
        if not ptr_hostname.endswith('.'):
            validation['validation_errors'].append('PTR hostname should end with a dot (FQDN)')

        # Check for generic/ISP-assigned patterns (indicates bad practice)
        generic_patterns = [
            r'static',
            r'dhcp',
            r'dynamic',
            r'pool',
            r'cable',
            r'dsl',
            r'generic',
            r'customer',
            r'host\d+',
            r'ip-\d+-\d+-\d+-\d+',
        ]

        for pattern in generic_patterns:
            if re.search(pattern, ptr_hostname, re.IGNORECASE):
                validation['validation_errors'].append(
                    f'PTR appears to be generic/ISP-assigned (pattern: {pattern})'
                )
                break

        # Forward DNS confirmation (FCrDNS)
        # Check if the PTR hostname resolves back to the original IP
        try:
            ptr_hostname_clean = ptr_hostname.rstrip('.')
            ip_obj = ipaddress.ip_address(ip_address)

            if ip_obj.version == 4:
                record_type = 'A'
            else:
                record_type = 'AAAA'

            forward_answers = self.resolver.resolve(ptr_hostname_clean, record_type, raise_on_no_answer=False)

            if forward_answers:
                forward_ips = [str(rdata.address) for rdata in forward_answers]
                validation['forward_lookup_result'] = forward_ips[0]  # Primary

                if ip_address in forward_ips:
                    validation['forward_matches'] = True
                else:
                    validation['validation_errors'].append(
                        f'Forward DNS mismatch: {ptr_hostname_clean} resolves to {forward_ips[0]}, not {ip_address}'
                    )
            else:
                validation['validation_errors'].append(
                    f'PTR hostname {ptr_hostname_clean} has no {record_type} record'
                )
                validation['forward_lookup_result'] = None

        except dns.resolver.NXDOMAIN:
            validation['validation_errors'].append(
                f'PTR hostname {ptr_hostname_clean} does not exist (NXDOMAIN)'
            )
        except dns.resolver.NoAnswer:
            validation['validation_errors'].append(
                f'PTR hostname {ptr_hostname_clean} has no {record_type} record'
            )
        except Exception as e:
            validation['validation_errors'].append(
                f'Forward DNS lookup error: {str(e)}'
            )

        # PTR is only valid if there are no critical errors and FCrDNS passes
        if validation['validation_errors'] and not validation['forward_matches']:
            validation['is_valid'] = False

        return validation

    def check_email_server_ptr(self, domain: str) -> List[Dict]:
        """
        Check PTR records for all MX servers of a domain
        Critical for email deliverability

        Args:
            domain: Domain name to check MX records for

        Returns:
            List of dicts with MX server PTR validation results
        """
        results = []

        try:
            # Get MX records
            mx_records = self.resolver.resolve(domain, 'MX', raise_on_no_answer=False)

            for mx in sorted(mx_records, key=lambda x: x.preference):
                mx_hostname = str(mx.exchange).rstrip('.')

                mx_result = {
                    'domain': domain,
                    'mx_hostname': mx_hostname,
                    'mx_priority': mx.preference,
                    'mx_ips': [],
                    'ptr_checks': [],
                    'all_valid': True,
                    'rejection_risk': 'low',
                    'recommendations': []
                }

                # Resolve MX hostname to IP(s)
                try:
                    # Try IPv4
                    try:
                        a_records = self.resolver.resolve(mx_hostname, 'A', raise_on_no_answer=False)
                        for a_record in a_records:
                            ip = str(a_record.address)
                            mx_result['mx_ips'].append({'ip': ip, 'type': 'ipv4'})
                    except:
                        pass

                    # Try IPv6
                    try:
                        aaaa_records = self.resolver.resolve(mx_hostname, 'AAAA', raise_on_no_answer=False)
                        for aaaa_record in aaaa_records:
                            ip = str(aaaa_record.address)
                            mx_result['mx_ips'].append({'ip': ip, 'type': 'ipv6'})
                    except:
                        pass

                    # Check PTR for each IP
                    for ip_info in mx_result['mx_ips']:
                        ptr_check = self.check_ptr_record(ip_info['ip'])
                        mx_result['ptr_checks'].append(ptr_check)

                        # Evaluate email deliverability impact
                        if not ptr_check.get('has_ptr'):
                            mx_result['all_valid'] = False
                            mx_result['rejection_risk'] = 'high'
                            mx_result['recommendations'].append(
                                f"Add PTR record for {ip_info['ip']} pointing to {mx_hostname}"
                            )
                        elif not ptr_check.get('forward_matches'):
                            mx_result['all_valid'] = False
                            mx_result['rejection_risk'] = 'medium'
                            mx_result['recommendations'].append(
                                f"Fix FCrDNS: {ip_info['ip']} PTR points to {ptr_check.get('ptr_hostname')}, "
                                f"which resolves to {ptr_check.get('forward_lookup_result')}"
                            )

                        # Check if PTR hostname matches MX hostname
                        ptr_hostname = ptr_check.get('ptr_hostname', '').rstrip('.')
                        if ptr_hostname and ptr_hostname.lower() != mx_hostname.lower():
                            mx_result['recommendations'].append(
                                f"PTR hostname ({ptr_hostname}) does not match MX hostname ({mx_hostname}). "
                                f"This may cause issues with some mail servers."
                            )

                except Exception as e:
                    mx_result['error'] = f'Failed to resolve MX hostname: {str(e)}'

                results.append(mx_result)

        except dns.resolver.NXDOMAIN:
            return [{
                'domain': domain,
                'error': 'Domain does not exist (NXDOMAIN)'
            }]
        except dns.resolver.NoAnswer:
            return [{
                'domain': domain,
                'error': 'No MX records found'
            }]
        except Exception as e:
            return [{
                'domain': domain,
                'error': f'MX lookup error: {str(e)}'
            }]

        return results

    def batch_check_ips(self, ip_addresses: List[str]) -> List[Dict]:
        """
        Check PTR records for multiple IP addresses

        Args:
            ip_addresses: List of IP addresses to check

        Returns:
            List of PTR check results
        """
        results = []
        for ip in ip_addresses:
            result = self.check_ptr_record(ip)
            results.append(result)
        return results

    def get_reverse_zone_for_ip(self, ip_address: str) -> Optional[str]:
        """
        Get the reverse DNS zone for an IP address

        Args:
            ip_address: IP address

        Returns:
            Reverse zone name (e.g., "1.0.0.127.in-addr.arpa" or "...ip6.arpa")
        """
        try:
            reverse_name = dns.reversename.from_address(ip_address)
            return str(reverse_name)
        except Exception:
            return None

    def check_reverse_zone_delegation(self, network: str) -> Dict:
        """
        Check if a network block has proper reverse DNS delegation

        Args:
            network: Network in CIDR notation (e.g., "192.0.2.0/24")

        Returns:
            Dict with delegation information
        """
        try:
            net = ipaddress.ip_network(network, strict=False)

            result = {
                'network': str(net),
                'ip_version': net.version,
                'network_size': net.num_addresses,
                'reverse_zone': None,
                'is_delegated': False,
                'nameservers': [],
                'authority_soa': None,
            }

            # For /24 IPv4 or /48 IPv6, check delegation
            if net.version == 4:
                # Get the reverse zone name
                # For 192.0.2.0/24, the zone is 2.0.192.in-addr.arpa
                octets = str(net.network_address).split('.')
                if net.prefixlen == 24:
                    reverse_zone = f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
                elif net.prefixlen == 16:
                    reverse_zone = f"{octets[1]}.{octets[0]}.in-addr.arpa"
                elif net.prefixlen == 8:
                    reverse_zone = f"{octets[0]}.in-addr.arpa"
                else:
                    reverse_zone = None  # Non-standard delegation

                if reverse_zone:
                    result['reverse_zone'] = reverse_zone

                    # Check for NS records
                    try:
                        ns_records = self.resolver.resolve(reverse_zone, 'NS', raise_on_no_answer=False)
                        if ns_records:
                            result['is_delegated'] = True
                            result['nameservers'] = [str(ns.target) for ns in ns_records]

                        # Check SOA
                        try:
                            soa_records = self.resolver.resolve(reverse_zone, 'SOA', raise_on_no_answer=False)
                            if soa_records:
                                soa = soa_records[0]
                                result['authority_soa'] = {
                                    'mname': str(soa.mname),
                                    'rname': str(soa.rname),
                                    'serial': soa.serial,
                                    'refresh': soa.refresh,
                                    'retry': soa.retry,
                                    'expire': soa.expire,
                                    'minimum': soa.minimum,
                                }
                        except:
                            pass

                    except Exception as e:
                        result['error'] = f'Failed to check delegation: {str(e)}'

            elif net.version == 6:
                # IPv6 reverse zones are more complex
                # For now, just provide the format
                result['reverse_zone'] = f"IPv6 reverse zones use ip6.arpa format"

            return result

        except ValueError as e:
            return {
                'error': f'Invalid network: {str(e)}',
                'network': network
            }


# Example usage and testing
if __name__ == '__main__':
    import json

    checker = ReverseDNSChecker()

    print("=" * 80)
    print("DNS Science - Reverse DNS Checker")
    print("=" * 80)

    # Test 1: Check Google's DNS server
    print("\n1. Checking PTR for 8.8.8.8 (Google DNS):")
    result = checker.check_ptr_record('8.8.8.8')
    print(json.dumps(result, indent=2))

    # Test 2: Check IPv6
    print("\n2. Checking PTR for 2001:4860:4860::8888 (Google DNS IPv6):")
    result = checker.check_ptr_record('2001:4860:4860::8888')
    print(json.dumps(result, indent=2))

    # Test 3: Check email server PTR
    print("\n3. Checking email servers for gmail.com:")
    results = checker.check_email_server_ptr('gmail.com')
    print(json.dumps(results, indent=2))

    # Test 4: Check reverse zone delegation
    print("\n4. Checking reverse zone delegation for 8.8.8.0/24:")
    result = checker.check_reverse_zone_delegation('8.8.8.0/24')
    print(json.dumps(result, indent=2))

    # Test 5: Batch check
    print("\n5. Batch checking multiple IPs:")
    ips = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    results = checker.batch_check_ips(ips)
    for r in results:
        print(f"  {r['ip_address']}: PTR={r.get('ptr_hostname', 'None')}, Valid={r.get('is_valid', False)}")
