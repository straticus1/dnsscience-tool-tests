"""Security checkers for DNS, email, and TLS validation"""
import dns.resolver
import dns.dnssec
import dns.message
import dns.query
import dns.rdatatype
import socket
import smtplib
import requests
import json
import re
import os
from config import Config


def get_resolver():
    """
    Get a configured DNS resolver instance.

    Uses environment variables to configure custom DNS resolver (e.g., Unbound):
    - DNS_RESOLVER: hostname or IP of DNS server (default: system resolver)
    - DNS_RESOLVER_PORT: port number (default: 53)

    Returns:
        dns.resolver.Resolver: Configured resolver instance
    """
    resolver = dns.resolver.Resolver()

    # Configure custom DNS resolver if specified
    dns_server = os.getenv('DNS_RESOLVER')
    dns_port = int(os.getenv('DNS_RESOLVER_PORT', '53'))

    if dns_server:
        # Use custom resolver (e.g., Unbound container)
        resolver.nameservers = [dns_server]
        resolver.port = dns_port

    # Apply timeout configuration
    resolver.timeout = Config.DNS_TIMEOUT
    resolver.lifetime = Config.DNS_TIMEOUT

    return resolver

class DNSSECChecker:
    """Check DNSSEC validation for a domain"""

    @staticmethod
    def check(domain):
        """
        Check if domain has DNSSEC enabled and if it's valid.
        Returns: dict with enabled, valid, and details
        """
        result = {
            'enabled': False,
            'valid': False,
            'details': ''
        }

        try:
            resolver = get_resolver()

            # Check for DNSKEY records
            try:
                dnskey_response = resolver.resolve(domain, 'DNSKEY')
                if dnskey_response:
                    result['enabled'] = True
                    result['details'] = f"Found {len(dnskey_response)} DNSKEY record(s)"
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result['details'] = "No DNSKEY records found"
                return result

            # Check for DS records at parent (for validation)
            try:
                # Get parent domain for DS record check
                parts = domain.split('.')
                if len(parts) >= 2:
                    parent_domain = '.'.join(parts[1:])
                    ds_response = resolver.resolve(f"{domain}", 'DS')
                    if ds_response:
                        result['valid'] = True
                        result['details'] += f" | DS records present, DNSSEC chain valid"
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result['details'] += " | No DS records (may be unsigned or issue with chain)"

        except dns.exception.Timeout:
            result['details'] = "DNS query timeout"
        except Exception as e:
            result['details'] = f"Error: {str(e)}"

        return result


class SPFChecker:
    """Check SPF records for a domain"""

    @staticmethod
    def check(domain):
        """
        Check SPF record for domain.
        Returns: dict with record, valid, and details
        """
        result = {
            'record': None,
            'valid': False,
            'details': ''
        }

        try:
            resolver = get_resolver()

            # SPF records are in TXT records
            txt_records = resolver.resolve(domain, 'TXT')

            spf_records = []
            for rdata in txt_records:
                txt_string = b''.join(rdata.strings).decode('utf-8')
                if txt_string.startswith('v=spf1'):
                    spf_records.append(txt_string)

            if not spf_records:
                result['details'] = "No SPF record found"
                return result

            if len(spf_records) > 1:
                result['details'] = f"WARNING: Multiple SPF records found ({len(spf_records)})"
                result['record'] = spf_records[0]
                result['valid'] = False
            else:
                result['record'] = spf_records[0]
                result['valid'] = True
                result['details'] = "SPF record found and valid"

        except dns.resolver.NoAnswer:
            result['details'] = "No TXT records found"
        except dns.resolver.NXDOMAIN:
            result['details'] = "Domain does not exist"
        except dns.exception.Timeout:
            result['details'] = "DNS query timeout"
        except Exception as e:
            result['details'] = f"Error: {str(e)}"

        return result


class DKIMChecker:
    """Check DKIM records for a domain"""

    @staticmethod
    def check(domain):
        """
        Check for DKIM records using common selectors.
        Returns: dict with selectors, valid, and details
        """
        result = {
            'selectors': [],
            'valid': False,
            'details': ''
        }

        found_selectors = []
        resolver = get_resolver()

        for selector in Config.DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                txt_records = resolver.resolve(dkim_domain, 'TXT')
                for rdata in txt_records:
                    txt_string = b''.join(rdata.strings).decode('utf-8')
                    if 'v=DKIM1' in txt_string or 'k=' in txt_string:
                        found_selectors.append(selector)
                        break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue
            except Exception:
                continue

        if found_selectors:
            result['selectors'] = found_selectors
            result['valid'] = True
            result['details'] = f"Found DKIM selector(s): {', '.join(found_selectors)}"
        else:
            result['details'] = f"No DKIM records found (checked {len(Config.DKIM_SELECTORS)} common selectors)"

        return result


class DMARCChecker:
    """Check DMARC policy for a domain"""

    @staticmethod
    def check(domain):
        """
        Check DMARC policy record.
        Returns: dict with policy, enabled, and detailed configuration
        """
        result = {
            'enabled': False,
            'record': None,
            'policy': None,
            'subdomain_policy': None,
            'percentage': 100,
            'aggregate_reports': [],
            'forensic_reports': [],
            'dkim_alignment': 'r',  # relaxed by default
            'spf_alignment': 'r',   # relaxed by default
            'details': ''
        }

        try:
            resolver = get_resolver()

            # DMARC record is at _dmarc.domain
            dmarc_domain = f"_dmarc.{domain}"
            try:
                txt_records = resolver.resolve(dmarc_domain, 'TXT')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result['details'] = "No DMARC record found"
                return result

            # Find DMARC record
            dmarc_record = None
            for rdata in txt_records:
                txt_string = b''.join(rdata.strings).decode('utf-8')
                if txt_string.startswith('v=DMARC1'):
                    dmarc_record = txt_string
                    break

            if not dmarc_record:
                result['details'] = "No valid DMARC record found"
                return result

            # Parse DMARC record
            result['enabled'] = True
            result['record'] = dmarc_record

            # Extract policy (p=)
            policy_match = re.search(r'p=(\w+)', dmarc_record)
            if policy_match:
                result['policy'] = policy_match.group(1)

            # Extract subdomain policy (sp=)
            sp_match = re.search(r'sp=(\w+)', dmarc_record)
            if sp_match:
                result['subdomain_policy'] = sp_match.group(1)
            else:
                result['subdomain_policy'] = result['policy']  # Inherits from p= if not specified

            # Extract percentage (pct=)
            pct_match = re.search(r'pct=(\d+)', dmarc_record)
            if pct_match:
                result['percentage'] = int(pct_match.group(1))

            # Extract aggregate report addresses (rua=)
            rua_match = re.search(r'rua=([^;]+)', dmarc_record)
            if rua_match:
                result['aggregate_reports'] = [addr.strip() for addr in rua_match.group(1).split(',')]

            # Extract forensic report addresses (ruf=)
            ruf_match = re.search(r'ruf=([^;]+)', dmarc_record)
            if ruf_match:
                result['forensic_reports'] = [addr.strip() for addr in ruf_match.group(1).split(',')]

            # Extract DKIM alignment (adkim=)
            adkim_match = re.search(r'adkim=([rs])', dmarc_record)
            if adkim_match:
                result['dkim_alignment'] = adkim_match.group(1)

            # Extract SPF alignment (aspf=)
            aspf_match = re.search(r'aspf=([rs])', dmarc_record)
            if aspf_match:
                result['spf_alignment'] = aspf_match.group(1)

            # Build details
            policy_desc = {
                'none': 'Monitor only (no action)',
                'quarantine': 'Quarantine suspicious emails',
                'reject': 'Reject unauthenticated emails'
            }
            result['details'] = f"DMARC policy: {policy_desc.get(result['policy'], result['policy'])}"

            if result['percentage'] < 100:
                result['details'] += f" (applied to {result['percentage']}% of messages)"

        except dns.exception.Timeout:
            result['details'] = "DNS query timeout"
        except Exception as e:
            result['details'] = f"Error: {str(e)}"

        return result


class CAAChecker:
    """Check CAA (Certificate Authority Authorization) records"""

    @staticmethod
    def check(domain):
        """
        Check CAA records for certificate authority restrictions.
        Returns: dict with CAA configuration
        """
        result = {
            'enabled': False,
            'record_count': 0,
            'records': [],
            'authorized_cas': [],
            'wildcard_cas': [],
            'has_iodef': False,
            'details': ''
        }

        try:
            resolver = get_resolver()

            try:
                caa_records = resolver.resolve(domain, 'CAA')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result['details'] = "No CAA records found"
                return result

            result['enabled'] = True
            result['record_count'] = len(caa_records)

            for rdata in caa_records:
                record_info = {
                    'flags': rdata.flags,
                    'tag': rdata.tag.decode('utf-8') if isinstance(rdata.tag, bytes) else rdata.tag,
                    'value': rdata.value.decode('utf-8') if isinstance(rdata.value, bytes) else rdata.value
                }
                result['records'].append(record_info)

                # Categorize by tag
                if record_info['tag'] == 'issue':
                    result['authorized_cas'].append(record_info['value'])
                elif record_info['tag'] == 'issuewild':
                    result['wildcard_cas'].append(record_info['value'])
                elif record_info['tag'] == 'iodef':
                    result['has_iodef'] = True

            result['details'] = f"Found {result['record_count']} CAA record(s)"
            if result['authorized_cas']:
                result['details'] += f" | Authorized CAs: {', '.join(result['authorized_cas'][:3])}"

        except dns.exception.Timeout:
            result['details'] = "DNS query timeout"
        except Exception as e:
            result['details'] = f"Error: {str(e)}"

        return result


class BIMIChecker:
    """Check BIMI (Brand Indicators for Message Identification) records"""

    @staticmethod
    def check(domain):
        """
        Check BIMI record for brand logo configuration.
        Returns: dict with BIMI configuration
        """
        result = {
            'enabled': False,
            'record': None,
            'logo_url': None,
            'authority_url': None,
            'details': ''
        }

        try:
            resolver = get_resolver()

            # BIMI record is at default._bimi.domain
            bimi_domain = f"default._bimi.{domain}"
            try:
                txt_records = resolver.resolve(bimi_domain, 'TXT')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result['details'] = "No BIMI record found"
                return result

            # Find BIMI record
            for rdata in txt_records:
                txt_string = b''.join(rdata.strings).decode('utf-8')
                if 'v=BIMI1' in txt_string:
                    result['enabled'] = True
                    result['record'] = txt_string

                    # Extract logo URL (l=)
                    logo_match = re.search(r'l=([^;\s]+)', txt_string)
                    if logo_match:
                        result['logo_url'] = logo_match.group(1)

                    # Extract authority URL (a=)
                    auth_match = re.search(r'a=([^;\s]+)', txt_string)
                    if auth_match:
                        result['authority_url'] = auth_match.group(1)

                    result['details'] = "BIMI enabled"
                    if result['logo_url']:
                        result['details'] += f" with logo at {result['logo_url']}"
                    break

            if not result['enabled']:
                result['details'] = "No valid BIMI record found"

        except dns.exception.Timeout:
            result['details'] = "DNS query timeout"
        except Exception as e:
            result['details'] = f"Error: {str(e)}"

        return result


class TLSAChecker:
    """Check DANE/TLSA records for certificate pinning"""

    @staticmethod
    def check(domain, port=25):
        """
        Check TLSA records for DANE certificate pinning.
        Returns: dict with TLSA configuration
        """
        result = {
            'enabled': False,
            'record_count': 0,
            'records': [],
            'details': ''
        }

        try:
            resolver = get_resolver()

            # TLSA record format: _port._protocol.domain
            tlsa_domain = f"_{port}._tcp.{domain}"
            try:
                tlsa_records = resolver.resolve(tlsa_domain, 'TLSA')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result['details'] = f"No TLSA records found for port {port}"
                return result

            result['enabled'] = True
            result['record_count'] = len(tlsa_records)

            usage_types = {0: 'CA constraint', 1: 'Service certificate constraint',
                          2: 'Trust anchor assertion', 3: 'Domain-issued certificate'}
            selector_types = {0: 'Full certificate', 1: 'SubjectPublicKeyInfo'}
            matching_types = {0: 'Exact match', 1: 'SHA-256', 2: 'SHA-512'}

            for rdata in tlsa_records:
                record_info = {
                    'usage': rdata.usage,
                    'usage_desc': usage_types.get(rdata.usage, 'Unknown'),
                    'selector': rdata.selector,
                    'selector_desc': selector_types.get(rdata.selector, 'Unknown'),
                    'matching_type': rdata.mtype,
                    'matching_desc': matching_types.get(rdata.mtype, 'Unknown'),
                    'cert_data': rdata.cert.hex()[:32] + '...'  # Truncate for display
                }
                result['records'].append(record_info)

            result['details'] = f"Found {result['record_count']} TLSA record(s) for port {port}"

        except dns.exception.Timeout:
            result['details'] = "DNS query timeout"
        except Exception as e:
            result['details'] = f"Error: {str(e)}"

        return result


class MTASTSChecker:
    """Check MTA-STS policy for a domain"""

    @staticmethod
    def check(domain):
        """
        Check if MTA-STS is enabled and fetch policy.
        Returns: dict with enabled, policy, and details
        """
        result = {
            'enabled': False,
            'policy': None,
            'details': ''
        }

        try:
            # Check for _mta-sts TXT record
            resolver = get_resolver()

            mta_sts_domain = f"_mta-sts.{domain}"
            try:
                txt_records = resolver.resolve(mta_sts_domain, 'TXT')
                for rdata in txt_records:
                    txt_string = b''.join(rdata.strings).decode('utf-8')
                    if txt_string.startswith('v=STSv1'):
                        result['enabled'] = True
                        break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result['details'] = "No MTA-STS TXT record found"
                return result

            # Fetch the policy file
            if result['enabled']:
                policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
                try:
                    response = requests.get(policy_url, timeout=Config.HTTP_TIMEOUT)
                    if response.status_code == 200:
                        result['policy'] = response.text
                        result['details'] = "MTA-STS enabled with valid policy"
                    else:
                        result['details'] = f"MTA-STS record found but policy fetch failed (HTTP {response.status_code})"
                except requests.RequestException as e:
                    result['details'] = f"MTA-STS record found but policy fetch failed: {str(e)}"

        except dns.exception.Timeout:
            result['details'] = "DNS query timeout"
        except Exception as e:
            result['details'] = f"Error: {str(e)}"

        return result


class SMTPSTARTTLSChecker:
    """Check SMTP STARTTLS capability on ports 25 and 587"""

    @staticmethod
    def check(domain):
        """
        Check if STARTTLS is advertised on SMTP ports.
        Returns: dict with starttls_25, starttls_587, and details
        """
        result = {
            'starttls_25': False,
            'starttls_587': False,
            'details': ''
        }

        details_parts = []

        # Get MX records first
        try:
            resolver = get_resolver()
            mx_records = resolver.resolve(domain, 'MX')
            mx_hosts = [str(rdata.exchange).rstrip('.') for rdata in mx_records]

            if not mx_hosts:
                result['details'] = "No MX records found"
                return result

            # Use the first MX host for testing
            mx_host = mx_hosts[0]
            details_parts.append(f"Testing {mx_host}")

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result['details'] = "No MX records found"
            return result
        except Exception as e:
            result['details'] = f"Error resolving MX: {str(e)}"
            return result

        # Check port 25
        port_25_result = SMTPSTARTTLSChecker._check_port(mx_host, 25, domain)
        result['starttls_25'] = port_25_result['starttls']
        details_parts.append(f"Port 25: {'STARTTLS' if port_25_result['starttls'] else 'No STARTTLS'}")

        # Check port 587
        port_587_result = SMTPSTARTTLSChecker._check_port(mx_host, 587, domain)
        result['starttls_587'] = port_587_result['starttls']
        details_parts.append(f"Port 587: {'STARTTLS' if port_587_result['starttls'] else 'No STARTTLS'}")

        result['details'] = ' | '.join(details_parts)
        return result

    @staticmethod
    def _check_port(host, port, domain):
        """Check a specific SMTP port for STARTTLS using posttls-finger or fallback to smtplib"""
        result = {'starttls': False, 'error': None}

        # Try using posttls-finger first (more reliable for STARTTLS testing)
        try:
            import subprocess
            cmd = ['posttls-finger', '-c', '-l', 'secure', f'[{host}]:{port}']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            # posttls-finger outputs indicate STARTTLS support
            if proc.returncode == 0:
                output = proc.stdout + proc.stderr
                if 'Trusted TLS connection established' in output or 'Verified TLS connection established' in output:
                    result['starttls'] = True
                    return result
                elif 'Untrusted TLS connection established' in output:
                    result['starttls'] = True  # STARTTLS works, even if cert not trusted
                    return result
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            # posttls-finger not available or failed, fall back to smtplib
            pass

        # Fallback to Python smtplib method
        smtp = None
        try:
            # Create SMTP connection with timeout
            smtp = smtplib.SMTP(timeout=Config.SMTP_TIMEOUT)
            smtp.connect(host, port)

            # EHLO with the MX hostname (not the domain)
            smtp.ehlo(host)

            # Check if STARTTLS is in capabilities
            if smtp.has_extn('STARTTLS'):
                result['starttls'] = True

                # Try to actually initiate STARTTLS to verify it works
                try:
                    smtp.starttls(context=None)  # Use default SSL context
                    smtp.ehlo(host)  # Re-EHLO after STARTTLS
                except Exception as starttls_error:
                    # STARTTLS advertised but failed - still mark as True (server supports it)
                    # But log the error for debugging
                    result['error'] = f"STARTTLS failed: {str(starttls_error)}"

        except smtplib.SMTPException as e:
            result['error'] = f"SMTP error: {str(e)}"
        except socket.timeout:
            result['error'] = "Connection timeout"
        except socket.error as e:
            result['error'] = f"Socket error: {str(e)}"
        except Exception as e:
            result['error'] = f"Error: {str(e)}"
        finally:
            # Always try to close the connection
            if smtp:
                try:
                    smtp.quit()
                except:
                    pass

        return result


class DomainScanner:
    """Main scanner that orchestrates all checks"""

    def __init__(self, check_ssl=True):
        self.dnssec_checker = DNSSECChecker()
        self.spf_checker = SPFChecker()
        self.dkim_checker = DKIMChecker()
        self.dmarc_checker = DMARCChecker()
        self.caa_checker = CAAChecker()
        self.bimi_checker = BIMIChecker()
        self.tlsa_checker = TLSAChecker()
        self.mta_sts_checker = MTASTSChecker()
        self.smtp_checker = SMTPSTARTTLSChecker()
        self.check_ssl = check_ssl

        # Import SSL checker only if needed (lazy loading)
        if self.check_ssl:
            from ssl_checker import SSLCertificateChecker
            self.ssl_checker = SSLCertificateChecker()
        else:
            self.ssl_checker = None

    def scan_domain(self, domain, check_ssl=None):
        """
        Perform a complete scan of a domain.

        Args:
            domain: Domain to scan
            check_ssl: Override instance setting for SSL checking

        Returns: dict with all check results
        """
        # Use parameter override if provided, otherwise use instance setting
        should_check_ssl = check_ssl if check_ssl is not None else self.check_ssl

        result = {
            'domain': domain,
            'scan_status': 'completed',
            'error_message': None
        }

        try:
            # DNSSEC
            dnssec_result = self.dnssec_checker.check(domain)
            result['dnssec_enabled'] = dnssec_result['enabled']
            result['dnssec_valid'] = dnssec_result['valid']
            result['dnssec_details'] = dnssec_result['details']

            # SPF
            spf_result = self.spf_checker.check(domain)
            result['spf_record'] = spf_result['record']
            result['spf_valid'] = spf_result['valid']
            result['spf_details'] = spf_result['details']

            # DKIM
            dkim_result = self.dkim_checker.check(domain)
            result['dkim_selectors'] = dkim_result['selectors']
            result['dkim_valid'] = dkim_result['valid']
            result['dkim_details'] = dkim_result['details']

            # DMARC
            dmarc_result = self.dmarc_checker.check(domain)
            result['dmarc_enabled'] = dmarc_result['enabled']
            result['dmarc_policy'] = dmarc_result['policy']
            result['dmarc_subdomain_policy'] = dmarc_result['subdomain_policy']
            result['dmarc_percentage'] = dmarc_result['percentage']
            result['dmarc_record'] = dmarc_result['record']
            result['dmarc_details'] = dmarc_result['details']

            # CAA
            caa_result = self.caa_checker.check(domain)
            result['caa_enabled'] = caa_result['enabled']
            result['caa_records'] = json.dumps(caa_result['records'])
            result['caa_details'] = caa_result['details']

            # BIMI
            bimi_result = self.bimi_checker.check(domain)
            result['bimi_enabled'] = bimi_result['enabled']
            result['bimi_record'] = bimi_result['record']
            result['bimi_logo_url'] = bimi_result['logo_url']
            result['bimi_details'] = bimi_result['details']

            # DANE/TLSA (check port 25 for email)
            tlsa_result = self.tlsa_checker.check(domain, port=25)
            result['tlsa_enabled'] = tlsa_result['enabled']
            result['tlsa_records'] = json.dumps(tlsa_result['records'])
            result['tlsa_details'] = tlsa_result['details']

            # MTA-STS
            mta_sts_result = self.mta_sts_checker.check(domain)
            result['mta_sts_enabled'] = mta_sts_result['enabled']
            result['mta_sts_policy'] = mta_sts_result['policy']
            result['mta_sts_details'] = mta_sts_result['details']

            # SMTP STARTTLS
            smtp_result = self.smtp_checker.check(domain)
            result['smtp_starttls_25'] = smtp_result['starttls_25']
            result['smtp_starttls_587'] = smtp_result['starttls_587']
            result['smtp_details'] = smtp_result['details']

            # SSL Certificates (optional)
            if should_check_ssl:
                if not self.ssl_checker:
                    from ssl_checker import SSLCertificateChecker
                    self.ssl_checker = SSLCertificateChecker()

                ssl_result = self.ssl_checker.check_domain(domain)
                result['ssl_certificates'] = ssl_result.get('certificates', [])
                result['ssl_ports_checked'] = ssl_result.get('ports_checked', [])
                result['ssl_ports_with_ssl'] = ssl_result.get('ports_with_ssl', [])
                result['ssl_has_expired'] = ssl_result.get('has_expired_certs', False)
                result['ssl_expiring_soon'] = ssl_result.get('expiring_soon', [])

            # Calculate Security Score (0-100)
            result['security_score'] = self._calculate_security_score(result)
            result['security_grade'] = self._score_to_grade(result['security_score'])

        except Exception as e:
            result['scan_status'] = 'failed'
            result['error_message'] = str(e)

        return result

    @staticmethod
    def _calculate_security_score(scan_result):
        """
        Calculate comprehensive security score (0-100).

        Scoring breakdown:
        - DNSSEC: 25 points
        - Email Auth (SPF+DKIM+DMARC): 40 points
        - Transport Security (STARTTLS+MTA-STS): 20 points
        - Advanced (CAA+BIMI+TLSA): 15 points
        """
        score = 0

        # DNSSEC (25 points)
        if scan_result.get('dnssec_valid'):
            score += 25
        elif scan_result.get('dnssec_enabled'):
            score += 10

        # SPF (10 points)
        if scan_result.get('spf_valid'):
            score += 10

        # DKIM (10 points)
        if scan_result.get('dkim_valid'):
            score += 10

        # DMARC (20 points - most critical)
        if scan_result.get('dmarc_policy') == 'reject':
            score += 20
        elif scan_result.get('dmarc_policy') == 'quarantine':
            score += 15
        elif scan_result.get('dmarc_enabled'):
            score += 5

        # Transport Security (20 points)
        if scan_result.get('mta_sts_enabled'):
            score += 10
        if scan_result.get('smtp_starttls_25') and scan_result.get('smtp_starttls_587'):
            score += 10
        elif scan_result.get('smtp_starttls_587'):  # At least submission port
            score += 5

        # Advanced Features (15 points)
        if scan_result.get('caa_enabled'):
            score += 5
        if scan_result.get('tlsa_enabled'):
            score += 5
        if scan_result.get('bimi_enabled'):
            score += 5

        return min(score, 100)

    @staticmethod
    def _score_to_grade(score):
        """Convert numeric score to letter grade"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
