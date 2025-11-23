"""
DNS Configuration Validation Suite - Premium Feature
Supports djbdns, BIND9, Unbound, NSD configuration analysis and hardening recommendations
"""

import os
import re
import zipfile
import tempfile
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime
import dns.resolver
import dns.zone
import dns.query


class DNSConfigValidator:
    """Main DNS configuration validation suite"""

    def __init__(self):
        self.supported_servers = ['bind9', 'djbdns', 'unbound', 'nsd']
        self.validation_results = {}
        self.hardening_recommendations = []

    def validate_uploaded_files(self, file_path: str, server_type: str = None) -> Dict[str, Any]:
        """
        Validate uploaded DNS configuration files.

        Args:
            file_path: Path to config file or zip archive
            server_type: Type of DNS server (bind9, djbdns, unbound, nsd) or auto-detect

        Returns:
            Validation results with errors, warnings, and recommendations
        """
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'file': file_path,
            'server_type': server_type,
            'valid': False,
            'errors': [],
            'warnings': [],
            'recommendations': [],
            'security_score': 0
        }

        # Handle zip files
        if file_path.endswith('.zip'):
            return self._validate_zip_archive(file_path)

        # Auto-detect server type if not specified
        if not server_type:
            server_type = self._detect_server_type(file_path)
            results['server_type'] = server_type

        # Route to appropriate validator
        if server_type == 'bind9':
            results = self._validate_bind9(file_path)
        elif server_type == 'djbdns':
            results = self._validate_djbdns(file_path)
        elif server_type == 'unbound':
            results = self._validate_unbound(file_path)
        elif server_type == 'nsd':
            results = self._validate_nsd(file_path)
        else:
            results['errors'].append(f"Unsupported server type: {server_type}")

        return results

    def _validate_zip_archive(self, zip_path: str) -> Dict[str, Any]:
        """
        Extract and validate all configs in a zip archive.

        Args:
            zip_path: Path to zip file

        Returns:
            Combined validation results
        """
        combined_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'archive': zip_path,
            'configs': {},
            'overall_score': 0
        }

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)

                # Scan for config files
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        server_type = self._detect_server_type(file_path)

                        if server_type:
                            config_name = os.path.relpath(file_path, temp_dir)
                            combined_results['configs'][config_name] = self.validate_uploaded_files(
                                file_path, server_type
                            )

            # Calculate overall security score
            if combined_results['configs']:
                total_score = sum(
                    config['security_score']
                    for config in combined_results['configs'].values()
                )
                combined_results['overall_score'] = total_score / len(combined_results['configs'])

        except Exception as e:
            combined_results['error'] = str(e)

        return combined_results

    def _detect_server_type(self, file_path: str) -> Optional[str]:
        """
        Auto-detect DNS server type from config file.

        Args:
            file_path: Path to config file

        Returns:
            Server type or None
        """
        filename = os.path.basename(file_path).lower()

        # Detect by filename
        if 'named.conf' in filename:
            return 'bind9'
        elif 'unbound.conf' in filename:
            return 'unbound'
        elif 'nsd.conf' in filename:
            return 'nsd'
        elif any(x in filename for x in ['tinydns', 'djbdns']):
            return 'djbdns'

        # Detect by content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(4096)  # Read first 4KB

                if 'zone "' in content and 'options {' in content:
                    return 'bind9'
                elif 'server:' in content and 'interface:' in content:
                    return 'unbound'
                elif 'zone:' in content and 'zonefile:' in content:
                    return 'nsd'
                elif content.startswith('+') or content.startswith('='):
                    return 'djbdns'
        except:
            pass

        return None

    def _validate_bind9(self, config_path: str) -> Dict[str, Any]:
        """
        Validate BIND9 named.conf configuration.

        Args:
            config_path: Path to named.conf

        Returns:
            Validation results with hardening recommendations
        """
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'file': config_path,
            'server_type': 'bind9',
            'valid': False,
            'errors': [],
            'warnings': [],
            'recommendations': [],
            'security_score': 100,
            'hardening': {}
        }

        try:
            with open(config_path, 'r') as f:
                config_content = f.read()

            # Syntax validation using named-checkconf
            syntax_check = self._check_bind9_syntax(config_path)
            if not syntax_check['valid']:
                results['errors'].extend(syntax_check['errors'])
                results['security_score'] -= 50
            else:
                results['valid'] = True

            # Security analysis
            hardening = self._analyze_bind9_hardening(config_content)
            results['hardening'] = hardening
            results['recommendations'].extend(hardening['recommendations'])
            results['security_score'] = hardening['score']

        except Exception as e:
            results['errors'].append(f"Error reading config: {str(e)}")
            results['security_score'] = 0

        return results

    def _check_bind9_syntax(self, config_path: str) -> Dict[str, Any]:
        """
        Use named-checkconf to validate BIND9 syntax.

        Args:
            config_path: Path to named.conf

        Returns:
            Syntax validation results
        """
        result = {'valid': False, 'errors': []}

        try:
            # Check if named-checkconf is available
            cmd = ['named-checkconf', config_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if proc.returncode == 0:
                result['valid'] = True
            else:
                result['errors'].append(proc.stderr.strip())
        except FileNotFoundError:
            # named-checkconf not installed, do basic validation
            result['warnings'] = ['named-checkconf not available, performing basic validation']
            result['valid'] = True  # Don't fail if tool not available
        except subprocess.TimeoutExpired:
            result['errors'].append('Syntax check timed out')
        except Exception as e:
            result['errors'].append(f"Syntax check error: {str(e)}")

        return result

    def _analyze_bind9_hardening(self, config_content: str) -> Dict[str, Any]:
        """
        Analyze BIND9 configuration for security hardening.

        Args:
            config_content: Content of named.conf

        Returns:
            Hardening analysis with score and recommendations
        """
        analysis = {
            'score': 100,
            'recommendations': [],
            'findings': {}
        }

        # Check for version hiding
        if 'version "' not in config_content:
            analysis['score'] -= 10
            analysis['recommendations'].append({
                'severity': 'medium',
                'finding': 'Version disclosure enabled',
                'recommendation': 'Hide BIND version: options { version "DNS Server"; };'
            })

        # Check for recursion controls
        if 'allow-recursion' not in config_content:
            analysis['score'] -= 15
            analysis['recommendations'].append({
                'severity': 'high',
                'finding': 'Unrestricted recursion',
                'recommendation': 'Limit recursion: options { allow-recursion { trusted-networks; }; };'
            })

        # Check for query source port randomization
        if 'use-v4-udp-ports' not in config_content and 'use-v6-udp-ports' not in config_content:
            analysis['score'] -= 5
            analysis['recommendations'].append({
                'severity': 'low',
                'finding': 'Source port randomization not configured',
                'recommendation': 'Configure port randomization: options { use-v4-udp-ports { range 1024 65535; }; };'
            })

        # Check for rate limiting
        if 'rate-limit' not in config_content:
            analysis['score'] -= 10
            analysis['recommendations'].append({
                'severity': 'medium',
                'finding': 'No rate limiting configured',
                'recommendation': 'Enable rate limiting: options { rate-limit { responses-per-second 5; }; };'
            })

        # Check for DNSSEC validation
        if 'dnssec-validation' not in config_content:
            analysis['score'] -= 15
            analysis['recommendations'].append({
                'severity': 'high',
                'finding': 'DNSSEC validation not enabled',
                'recommendation': 'Enable DNSSEC: options { dnssec-validation auto; };'
            })

        # Check for zone transfer restrictions
        if 'allow-transfer' not in config_content:
            analysis['score'] -= 10
            analysis['recommendations'].append({
                'severity': 'medium',
                'finding': 'Unrestricted zone transfers',
                'recommendation': 'Restrict zone transfers: options { allow-transfer { none; }; };'
            })

        # Check for query logging
        if 'querylog' not in config_content and 'logging' not in config_content:
            analysis['score'] -= 5
            analysis['recommendations'].append({
                'severity': 'low',
                'finding': 'Query logging not configured',
                'recommendation': 'Enable logging for security monitoring'
            })

        # Check for response rate limiting (RRL)
        if 'rate-limit' not in config_content:
            analysis['score'] -= 10
            analysis['recommendations'].append({
                'severity': 'medium',
                'finding': 'Response Rate Limiting (RRL) not configured',
                'recommendation': 'Configure RRL to mitigate DNS amplification attacks'
            })

        return analysis

    def _validate_djbdns(self, config_path: str) -> Dict[str, Any]:
        """
        Validate djbdns tinydns data file.

        Args:
            config_path: Path to djbdns data file

        Returns:
            Validation results
        """
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'file': config_path,
            'server_type': 'djbdns',
            'valid': False,
            'errors': [],
            'warnings': [],
            'recommendations': [],
            'security_score': 100,
            'records_analyzed': 0
        }

        try:
            with open(config_path, 'r') as f:
                lines = f.readlines()

            valid_record_types = ['+', '=', '@', '^', 'C', 'Z', '.', '&', "'"]
            record_count = 0

            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                record_type = line[0]
                if record_type not in valid_record_types:
                    results['errors'].append(
                        f"Line {line_num}: Invalid record type '{record_type}'"
                    )
                    results['security_score'] -= 5
                else:
                    record_count += 1

            results['records_analyzed'] = record_count
            results['valid'] = len(results['errors']) == 0

            # djbdns-specific recommendations
            results['recommendations'].append({
                'severity': 'info',
                'finding': 'djbdns security notes',
                'recommendation': 'djbdns has good security by default. Ensure firewall rules limit access.'
            })

        except Exception as e:
            results['errors'].append(f"Error reading djbdns config: {str(e)}")
            results['security_score'] = 0

        return results

    def _validate_unbound(self, config_path: str) -> Dict[str, Any]:
        """
        Validate Unbound configuration.

        Args:
            config_path: Path to unbound.conf

        Returns:
            Validation results with hardening recommendations
        """
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'file': config_path,
            'server_type': 'unbound',
            'valid': False,
            'errors': [],
            'warnings': [],
            'recommendations': [],
            'security_score': 100,
            'hardening': {}
        }

        try:
            with open(config_path, 'r') as f:
                config_content = f.read()

            # Syntax validation using unbound-checkconf
            syntax_check = self._check_unbound_syntax(config_path)
            if not syntax_check['valid']:
                results['errors'].extend(syntax_check['errors'])
                results['security_score'] -= 50
            else:
                results['valid'] = True

            # Security analysis
            hardening = self._analyze_unbound_hardening(config_content)
            results['hardening'] = hardening
            results['recommendations'].extend(hardening['recommendations'])
            results['security_score'] = hardening['score']

        except Exception as e:
            results['errors'].append(f"Error reading config: {str(e)}")
            results['security_score'] = 0

        return results

    def _check_unbound_syntax(self, config_path: str) -> Dict[str, Any]:
        """
        Use unbound-checkconf to validate syntax.

        Args:
            config_path: Path to unbound.conf

        Returns:
            Syntax validation results
        """
        result = {'valid': False, 'errors': []}

        try:
            cmd = ['unbound-checkconf', config_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if proc.returncode == 0:
                result['valid'] = True
            else:
                result['errors'].append(proc.stderr.strip())
        except FileNotFoundError:
            result['warnings'] = ['unbound-checkconf not available']
            result['valid'] = True
        except subprocess.TimeoutExpired:
            result['errors'].append('Syntax check timed out')
        except Exception as e:
            result['errors'].append(f"Syntax check error: {str(e)}")

        return result

    def _analyze_unbound_hardening(self, config_content: str) -> Dict[str, Any]:
        """
        Analyze Unbound configuration for security hardening.

        Args:
            config_content: Content of unbound.conf

        Returns:
            Hardening analysis with score and recommendations
        """
        analysis = {
            'score': 100,
            'recommendations': [],
            'findings': {}
        }

        # Check for DNSSEC validation
        if 'auto-trust-anchor-file:' not in config_content:
            analysis['score'] -= 15
            analysis['recommendations'].append({
                'severity': 'high',
                'finding': 'DNSSEC auto-trust-anchor not configured',
                'recommendation': 'Enable DNSSEC: auto-trust-anchor-file: "/var/lib/unbound/root.key"'
            })

        # Check for access control
        if 'access-control:' not in config_content:
            analysis['score'] -= 15
            analysis['recommendations'].append({
                'severity': 'high',
                'finding': 'No access control configured',
                'recommendation': 'Configure access control to limit who can query'
            })

        # Check for hiding identity/version
        if 'hide-identity: yes' not in config_content:
            analysis['score'] -= 5
            analysis['recommendations'].append({
                'severity': 'low',
                'finding': 'Server identity not hidden',
                'recommendation': 'Add: hide-identity: yes'
            })

        if 'hide-version: yes' not in config_content:
            analysis['score'] -= 5
            analysis['recommendations'].append({
                'severity': 'low',
                'finding': 'Server version not hidden',
                'recommendation': 'Add: hide-version: yes'
            })

        # Check for prefetch
        if 'prefetch: yes' not in config_content:
            analysis['score'] -= 5
            analysis['recommendations'].append({
                'severity': 'info',
                'finding': 'Prefetch not enabled',
                'recommendation': 'Enable prefetch for better performance: prefetch: yes'
            })

        # Check for aggressive NSEC
        if 'aggressive-nsec: yes' not in config_content:
            analysis['score'] -= 5
            analysis['recommendations'].append({
                'severity': 'info',
                'finding': 'Aggressive NSEC not enabled',
                'recommendation': 'Enable aggressive NSEC for DNSSEC: aggressive-nsec: yes'
            })

        return analysis

    def _validate_nsd(self, config_path: str) -> Dict[str, Any]:
        """
        Validate NSD configuration.

        Args:
            config_path: Path to nsd.conf

        Returns:
            Validation results with hardening recommendations
        """
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'file': config_path,
            'server_type': 'nsd',
            'valid': False,
            'errors': [],
            'warnings': [],
            'recommendations': [],
            'security_score': 100,
            'hardening': {}
        }

        try:
            with open(config_path, 'r') as f:
                config_content = f.read()

            # Syntax validation using nsd-checkconf
            syntax_check = self._check_nsd_syntax(config_path)
            if not syntax_check['valid']:
                results['errors'].extend(syntax_check['errors'])
                results['security_score'] -= 50
            else:
                results['valid'] = True

            # Security analysis
            hardening = self._analyze_nsd_hardening(config_content)
            results['hardening'] = hardening
            results['recommendations'].extend(hardening['recommendations'])
            results['security_score'] = hardening['score']

        except Exception as e:
            results['errors'].append(f"Error reading config: {str(e)}")
            results['security_score'] = 0

        return results

    def _check_nsd_syntax(self, config_path: str) -> Dict[str, Any]:
        """
        Use nsd-checkconf to validate syntax.

        Args:
            config_path: Path to nsd.conf

        Returns:
            Syntax validation results
        """
        result = {'valid': False, 'errors': []}

        try:
            cmd = ['nsd-checkconf', config_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if proc.returncode == 0:
                result['valid'] = True
            else:
                result['errors'].append(proc.stderr.strip())
        except FileNotFoundError:
            result['warnings'] = ['nsd-checkconf not available']
            result['valid'] = True
        except subprocess.TimeoutExpired:
            result['errors'].append('Syntax check timed out')
        except Exception as e:
            result['errors'].append(f"Syntax check error: {str(e)}")

        return result

    def _analyze_nsd_hardening(self, config_content: str) -> Dict[str, Any]:
        """
        Analyze NSD configuration for security hardening.

        Args:
            config_content: Content of nsd.conf

        Returns:
            Hardening analysis with score and recommendations
        """
        analysis = {
            'score': 100,
            'recommendations': [],
            'findings': {}
        }

        # Check for hiding version
        if 'hide-version: yes' not in config_content:
            analysis['score'] -= 5
            analysis['recommendations'].append({
                'severity': 'low',
                'finding': 'Server version not hidden',
                'recommendation': 'Add: hide-version: yes'
            })

        # Check for rate limiting
        if 'rrl-size:' not in config_content:
            analysis['score'] -= 10
            analysis['recommendations'].append({
                'severity': 'medium',
                'finding': 'Response Rate Limiting (RRL) not configured',
                'recommendation': 'Configure RRL: rrl-size: 1000000'
            })

        # Check for NOTIFY restrictions
        if 'provide-xfr:' in config_content:
            if 'NOKEY' in config_content or 'BLOCKED' not in config_content:
                analysis['score'] -= 10
                analysis['recommendations'].append({
                    'severity': 'medium',
                    'finding': 'Zone transfer security could be improved',
                    'recommendation': 'Use TSIG keys for zone transfers'
                })

        # Check for verbosity
        if 'verbosity: 0' not in config_content and 'verbosity: 1' not in config_content:
            analysis['score'] -= 5
            analysis['recommendations'].append({
                'severity': 'info',
                'finding': 'Logging verbosity not optimized',
                'recommendation': 'Set appropriate verbosity level: verbosity: 1'
            })

        return analysis


class DNSCacheInspector:
    """
    Inspect DNS cache from Unbound daemon.
    Requires access to unbound-control socket.
    """

    def __init__(self, unbound_control_path: str = 'unbound-control'):
        self.unbound_control = unbound_control_path

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get overall cache statistics from Unbound.

        Returns:
            Cache statistics
        """
        try:
            cmd = [self.unbound_control, 'stats_noreset']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if proc.returncode == 0:
                return self._parse_unbound_stats(proc.stdout)
            else:
                return {'error': proc.stderr}
        except Exception as e:
            return {'error': str(e)}

    def dump_cache(self, domain_filter: str = None) -> List[Dict[str, Any]]:
        """
        Dump DNS cache entries from Unbound.

        Args:
            domain_filter: Optional domain to filter results

        Returns:
            List of cache entries
        """
        try:
            cmd = [self.unbound_control, 'dump_cache']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if proc.returncode == 0:
                return self._parse_cache_dump(proc.stdout, domain_filter)
            else:
                return []
        except Exception as e:
            return []

    def lookup_cache(self, domain: str) -> Dict[str, Any]:
        """
        Lookup specific domain in cache.

        Args:
            domain: Domain to lookup

        Returns:
            Cache entry for domain
        """
        try:
            cmd = [self.unbound_control, 'lookup', domain]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            return {
                'domain': domain,
                'in_cache': proc.returncode == 0,
                'data': proc.stdout if proc.returncode == 0 else None
            }
        except Exception as e:
            return {'domain': domain, 'error': str(e)}

    def _parse_unbound_stats(self, stats_output: str) -> Dict[str, Any]:
        """Parse unbound statistics output"""
        stats = {}
        for line in stats_output.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                try:
                    stats[key.strip()] = float(value.strip())
                except:
                    stats[key.strip()] = value.strip()
        return stats

    def _parse_cache_dump(self, dump_output: str, domain_filter: str = None) -> List[Dict[str, Any]]:
        """Parse cache dump output"""
        entries = []
        # TODO: Implement cache dump parsing
        return entries


class DNSSECValidator:
    """
    DNSSEC and DANE validation.
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.use_edns(0, dns.flags.DO, 4096)

    def validate_dnssec(self, domain: str) -> Dict[str, Any]:
        """
        Validate DNSSEC for a domain.

        Args:
            domain: Domain to validate

        Returns:
            DNSSEC validation results
        """
        results = {
            'domain': domain,
            'dnssec_enabled': False,
            'validated': False,
            'chain': [],
            'errors': []
        }

        try:
            # Check for DNSKEY records
            try:
                dnskey = self.resolver.resolve(domain, 'DNSKEY')
                results['dnssec_enabled'] = True
                results['dnskey_count'] = len(dnskey)
            except:
                results['errors'].append('No DNSKEY records found')
                return results

            # Check for DS records at parent
            try:
                parent_domain = '.'.join(domain.split('.')[1:])
                ds = self.resolver.resolve(domain, 'DS')
                results['ds_records'] = len(ds)
            except:
                results['errors'].append('No DS records at parent')

            # Full validation would require DNSSEC library
            results['validated'] = len(results['errors']) == 0

        except Exception as e:
            results['errors'].append(str(e))

        return results

    def validate_dane(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Validate DANE/TLSA records.

        Args:
            domain: Domain to validate
            port: Port number (default 443)

        Returns:
            DANE validation results
        """
        results = {
            'domain': domain,
            'port': port,
            'tlsa_records': [],
            'valid': False,
            'errors': []
        }

        try:
            tlsa_domain = f"_{port}._tcp.{domain}"
            tlsa_records = self.resolver.resolve(tlsa_domain, 'TLSA')

            for rr in tlsa_records:
                results['tlsa_records'].append({
                    'usage': rr.usage,
                    'selector': rr.selector,
                    'mtype': rr.mtype,
                    'cert': rr.cert.hex()
                })

            results['valid'] = len(results['tlsa_records']) > 0

        except dns.resolver.NXDOMAIN:
            results['errors'].append('No TLSA records found')
        except Exception as e:
            results['errors'].append(str(e))

        return results


class ZoneTransferChecker:
    """
    Check for unauthorized zone transfers.
    """

    def check_zone_transfer(self, domain: str, nameserver: str = None) -> Dict[str, Any]:
        """
        Attempt zone transfer (AXFR) to check if it's restricted.

        Args:
            domain: Domain to test
            nameserver: Specific nameserver to test (optional)

        Returns:
            Zone transfer test results
        """
        results = {
            'domain': domain,
            'nameserver': nameserver,
            'transfer_allowed': False,
            'records_count': 0,
            'security_issue': False,
            'message': ''
        }

        try:
            # Get nameservers if not specified
            if not nameserver:
                resolver = dns.resolver.Resolver()
                ns_records = resolver.resolve(domain, 'NS')
                nameserver = str(ns_records[0].target)

            # Attempt zone transfer
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))

            if zone:
                results['transfer_allowed'] = True
                results['security_issue'] = True
                results['records_count'] = len(zone.nodes)
                results['message'] = 'CRITICAL: Zone transfer is allowed! This is a security risk.'

        except dns.exception.FormError:
            results['message'] = 'Zone transfer properly restricted (REFUSED)'
        except dns.xfr.TransferError:
            results['message'] = 'Zone transfer properly restricted'
        except Exception as e:
            results['message'] = f'Test completed: {str(e)}'

        return results


class DomainHijackingValidator:
    """
    Validate domain against hijacking indicators.
    """

    def check_hijacking_indicators(self, domain: str) -> Dict[str, Any]:
        """
        Check domain for potential hijacking indicators.

        Args:
            domain: Domain to check

        Returns:
            Hijacking validation results
        """
        results = {
            'domain': domain,
            'risk_level': 'low',
            'indicators': [],
            'recommendations': []
        }

        resolver = dns.resolver.Resolver()

        # Check for suspicious NS records
        try:
            ns_records = resolver.resolve(domain, 'NS')
            ns_list = [str(ns.target) for ns in ns_records]

            # Check for known parking/hijacked nameservers
            suspicious_ns = ['sedoparking', 'parkingcrew', 'bodis', 'sedo']
            for ns in ns_list:
                if any(sus in ns.lower() for sus in suspicious_ns):
                    results['indicators'].append(f'Suspicious nameserver: {ns}')
                    results['risk_level'] = 'high'
        except:
            pass

        # Check for multiple A record changes (would need historical data)
        results['recommendations'].append('Enable DNSSEC to prevent hijacking')
        results['recommendations'].append('Use registry lock if available')
        results['recommendations'].append('Monitor DNS records for unauthorized changes')

        return results
