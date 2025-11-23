#!/usr/bin/env python3
"""
DNS Science CLI - Feature-Rich Command Line Interface
Comprehensive CLI tool for DNS Science platform

Usage:
    dnsscience scan <domain> [options]
    dnsscience cert <domain> [options]
    dnsscience email <domain> [options]
    dnsscience reverse-dns <ip> [options]
    dnsscience threat-intel <domain> [options]
    dnsscience ip scan <ip> [options]
    dnsscience ip reputation <ip>
    dnsscience ip asn <asn>
    dnsscience report generate <domain> [options]
    dnsscience user profile
    dnsscience user usage
    dnsscience apikeys list
    dnsscience apikeys create <name>
    dnsscience apikeys revoke <key_id>
    dnsscience config set <key> <value>
    dnsscience login
    dnsscience logout

Examples:
    dnsscience scan example.com --type full --output json
    dnsscience cert google.com --port 443 --format table
    dnsscience threat-intel evil.com --sources all
    dnsscience ip scan 8.8.8.8 --format table
    dnsscience ip reputation 1.2.3.4
    dnsscience ip asn 15169
    dnsscience report generate example.com --format pdf --output report.pdf
"""

import argparse
import sys
import os
import json
import requests
import time
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path
import configparser
from tabulate import tabulate
from colorama import init, Fore, Back, Style
import keyring

# Initialize colorama for cross-platform colored output
init(autoreset=True)

VERSION = "1.0.0"
CONFIG_DIR = Path.home() / ".dnsscience"
CONFIG_FILE = CONFIG_DIR / "config.ini"
API_BASE_URL = "https://api.dnsscience.io/v1"


class DNSScienceCLI:
    """Main CLI application class"""

    def __init__(self):
        self.config = self.load_config()
        self.api_key = self.get_api_key()
        self.api_base_url = self.config.get('api', 'base_url', fallback=API_BASE_URL)

    def load_config(self) -> configparser.ConfigParser:
        """Load CLI configuration"""
        config = configparser.ConfigParser()

        if CONFIG_FILE.exists():
            config.read(CONFIG_FILE)
        else:
            # Create default config
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            config['api'] = {
                'base_url': API_BASE_URL,
                'timeout': '30'
            }
            config['output'] = {
                'format': 'table',
                'color': 'true'
            }
            with open(CONFIG_FILE, 'w') as f:
                config.write(f)

        return config

    def save_config(self):
        """Save configuration to file"""
        with open(CONFIG_FILE, 'w') as f:
            self.config.write(f)

    def get_api_key(self) -> Optional[str]:
        """Get API key from keyring or environment"""
        # Try environment variable first
        api_key = os.getenv('DNSSCIENCE_API_KEY')

        if not api_key:
            # Try keyring
            try:
                api_key = keyring.get_password('dnsscience', 'api_key')
            except:
                pass

        return api_key

    def set_api_key(self, api_key: str):
        """Store API key securely in keyring"""
        try:
            keyring.set_password('dnsscience', 'api_key', api_key)
            self.api_key = api_key
            print_success("API key stored securely")
        except Exception as e:
            print_error(f"Failed to store API key: {e}")

    def api_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make API request with authentication"""
        if not self.api_key:
            print_error("No API key found. Run 'dnsscience login' first.")
            sys.exit(1)

        url = f"{self.api_base_url}/{endpoint.lstrip('/')}"
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f"Bearer {self.api_key}"
        headers['User-Agent'] = f"DNS Science CLI/{VERSION}"
        kwargs['headers'] = headers

        timeout = int(self.config.get('api', 'timeout', fallback='30'))
        kwargs.setdefault('timeout', timeout)

        try:
            response = requests.request(method, url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print_error(f"API request failed: {e}")
            sys.exit(1)

    def scan_domain(self, domain: str, scan_type: str = 'standard', options: Dict = None) -> Dict:
        """Scan a domain"""
        print_info(f"Initiating {scan_type} scan for {domain}...")

        payload = {
            'domain': domain,
            'scan_type': scan_type,
            'options': options or {}
        }

        response = self.api_request('POST', '/domains/scan', json=payload)

        if response.status_code == 201:
            scan_data = response.json()
            scan_id = scan_data['scan_id']

            print_success(f"Scan queued (ID: {scan_id})")
            print_info("Waiting for scan to complete...")

            # Poll for results
            return self.wait_for_scan(scan_id)
        else:
            print_error(f"Scan failed: {response.json().get('message', 'Unknown error')}")
            sys.exit(1)

    def wait_for_scan(self, scan_id: str, max_wait: int = 300) -> Dict:
        """Wait for scan to complete"""
        start_time = time.time()

        with ProgressSpinner(f"Scanning"):
            while time.time() - start_time < max_wait:
                response = self.api_request('GET', f'/scans/{scan_id}')

                if response.status_code != 200:
                    print_error("Failed to fetch scan status")
                    sys.exit(1)

                data = response.json()
                status = data['status']

                if status == 'completed':
                    print_success(f"Scan completed in {data.get('scan_duration_ms', 0) / 1000:.2f}s")
                    return data
                elif status == 'failed':
                    print_error(f"Scan failed: {data.get('error', 'Unknown error')}")
                    sys.exit(1)

                time.sleep(2)

        print_error("Scan timed out")
        sys.exit(1)

    def display_scan_results(self, results: Dict, format: str = 'table'):
        """Display scan results in specified format"""
        if format == 'json':
            print(json.dumps(results, indent=2))
        elif format == 'raw':
            print(json.dumps(results))
        else:
            # Table format
            self.display_scan_results_table(results)

    def display_scan_results_table(self, results: Dict):
        """Display scan results as formatted tables"""
        domain = results['domain']
        score = results.get('score', {})

        # Header
        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}DNS Science Scan Results - {domain}")
        print(f"{Fore.CYAN}{'=' * 80}\n")

        # Overall Score
        overall_score = score.get('overall', 0)
        score_color = get_score_color(overall_score)

        print(f"{score_color}Overall Security Score: {overall_score}/100\n")

        # DNS Results
        if 'dns' in results['results']:
            print(f"{Fore.YELLOW}DNS Configuration:")
            dns = results['results']['dns']

            dns_table = []

            if 'nameservers' in dns:
                ns_list = ', '.join([ns['hostname'] for ns in dns['nameservers']])
                dns_table.append(['Nameservers', ns_list])

            if 'a_records' in dns:
                a_list = ', '.join([a['ip'] for a in dns['a_records']])
                dns_table.append(['A Records', a_list])

            if 'dnssec' in dns:
                dnssec_status = f"{'✓ Enabled' if dns['dnssec']['enabled'] else '✗ Disabled'}"
                dns_table.append(['DNSSEC', dnssec_status])

            print(tabulate(dns_table, tablefmt='simple'))
            print()

        # SSL/TLS Results
        if 'ssl' in results['results']:
            print(f"{Fore.YELLOW}SSL/TLS Configuration:")
            ssl = results['results']['ssl']

            if 'certificates' in ssl and ssl['certificates']:
                cert = ssl['certificates'][0]

                ssl_table = [
                    ['Common Name', cert['common_name']],
                    ['Issuer', cert['issuer']],
                    ['Valid Until', cert['valid_until']],
                    ['Days Until Expiry', cert['days_until_expiry']],
                    ['Status', '✓ Valid' if cert['is_valid'] else '✗ Invalid']
                ]

                print(tabulate(ssl_table, tablefmt='simple'))
            print()

        # Email Security
        if 'email' in results['results']:
            print(f"{Fore.YELLOW}Email Security:")
            email = results['results']['email']

            email_table = []

            if 'spf' in email:
                spf_status = f"{'✓ Valid' if email['spf']['valid'] else '✗ Invalid'}"
                email_table.append(['SPF', spf_status])

            if 'dmarc' in email:
                dmarc_status = f"{'✓ Valid' if email['dmarc']['valid'] else '✗ Invalid'}"
                dmarc_policy = email['dmarc'].get('policy', 'none')
                email_table.append(['DMARC', f"{dmarc_status} (policy: {dmarc_policy})"])

            if 'dkim' in email:
                dkim_count = len(email['dkim'].get('selectors_found', []))
                email_table.append(['DKIM Selectors', f"{dkim_count} found"])

            print(tabulate(email_table, tablefmt='simple'))
            print()

        # Threat Intelligence
        if 'threat_intel' in results['results']:
            print(f"{Fore.YELLOW}Threat Intelligence:")
            threat = results['results']['threat_intel']

            threat_color = Fore.GREEN if threat['threats_found'] == 0 else Fore.RED

            threat_table = [
                ['Threats Found', f"{threat_color}{threat['threats_found']}"],
                ['Reputation Score', f"{threat['reputation_score']}/100"],
                ['Blacklists', f"{threat['blacklists']['listed_count']}/{threat['blacklists']['total_checked']}"]
            ]

            print(tabulate(threat_table, tablefmt='simple'))
            print()

        # Compliance Scores
        if 'compliance' in results['results']:
            print(f"{Fore.YELLOW}Compliance Scores:")
            compliance = results['results']['compliance']

            comp_table = [
                ['NIST CSF', f"{compliance.get('nist_csf_score', 0)}/100"],
                ['PCI DSS', f"{compliance.get('pci_dss_score', 0)}/100"],
                ['ISO 27001', f"{compliance.get('iso27001_score', 0)}/100"],
                ['CIS Controls', f"{compliance.get('cis_controls_score', 0)}/100"]
            ]

            print(tabulate(comp_table, tablefmt='simple'))
            print()

        print(f"{Fore.CYAN}{'=' * 80}\n")

    def get_certificate_info(self, domain: str, port: int = 443):
        """Get certificate information"""
        print_info(f"Fetching certificate for {domain}:{port}...")

        response = self.api_request('GET', f'/certificates/{domain}?port={port}')

        if response.status_code == 200:
            return response.json()
        else:
            print_error(f"Failed to fetch certificate: {response.json().get('message', 'Unknown error')}")
            sys.exit(1)

    def display_certificate_info(self, cert_data: Dict, format: str = 'table'):
        """Display certificate information"""
        if format == 'json':
            print(json.dumps(cert_data, indent=2))
        else:
            cert = cert_data['certificate']

            print(f"\n{Fore.CYAN}{'=' * 80}")
            print(f"{Fore.CYAN}SSL/TLS Certificate Information")
            print(f"{Fore.CYAN}{'=' * 80}\n")

            cert_table = [
                ['Domain', cert_data['domain']],
                ['Port', cert_data['port']],
                ['Common Name', cert['subject']['common_name']],
                ['Organization', cert['subject'].get('organization', 'N/A')],
                ['Issuer', cert['issuer']['common_name']],
                ['Valid From', cert['valid_from']],
                ['Valid Until', cert['valid_until']],
                ['Days Until Expiry', cert['days_until_expiry']],
                ['Signature Algorithm', cert['signature_algorithm']],
                ['Key Size', f"{cert['public_key_size']} bits"],
                ['Status', '✓ Valid & Trusted' if cert['is_valid'] and cert['is_trusted'] else '✗ Invalid']
            ]

            print(tabulate(cert_table, tablefmt='simple'))

            # SANs
            if 'subject_alternative_names' in cert:
                print(f"\n{Fore.YELLOW}Subject Alternative Names:")
                for san in cert['subject_alternative_names'][:10]:
                    print(f"  • {san}")
                if len(cert['subject_alternative_names']) > 10:
                    print(f"  ... and {len(cert['subject_alternative_names']) - 10} more")

            print(f"\n{Fore.CYAN}{'=' * 80}\n")

    def generate_report(self, domain: str, format: str = 'pdf', output: Optional[str] = None):
        """Generate report"""
        print_info(f"Generating {format.upper()} report for {domain}...")

        payload = {
            'domain': domain,
            'format': format,
            'sections': [
                'executive_summary',
                'dns_analysis',
                'ssl_certificates',
                'email_security',
                'threat_intelligence',
                'compliance'
            ]
        }

        response = self.api_request('POST', '/reports/generate', json=payload)

        if response.status_code == 201:
            report_data = response.json()
            report_id = report_data['report_id']

            print_success(f"Report queued (ID: {report_id})")
            print_info("Waiting for report generation...")

            # Poll for completion
            report = self.wait_for_report(report_id)

            # Download report
            if output:
                self.download_report(report['download_url'], output)
            else:
                print_success(f"Report available at: {report['download_url']}")

        else:
            print_error(f"Report generation failed: {response.json().get('message', 'Unknown error')}")
            sys.exit(1)

    def wait_for_report(self, report_id: str, max_wait: int = 120) -> Dict:
        """Wait for report generation"""
        start_time = time.time()

        with ProgressSpinner("Generating report"):
            while time.time() - start_time < max_wait:
                response = self.api_request('GET', f'/reports/{report_id}')

                if response.status_code != 200:
                    print_error("Failed to fetch report status")
                    sys.exit(1)

                data = response.json()
                status = data['status']

                if status == 'completed':
                    print_success("Report generated successfully")
                    return data
                elif status == 'failed':
                    print_error(f"Report generation failed: {data.get('error', 'Unknown error')}")
                    sys.exit(1)

                time.sleep(3)

        print_error("Report generation timed out")
        sys.exit(1)

    def download_report(self, url: str, output_path: str):
        """Download report file"""
        print_info(f"Downloading report to {output_path}...")

        response = requests.get(url, stream=True)

        if response.status_code == 200:
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print_success(f"Report saved to {output_path}")
        else:
            print_error("Failed to download report")
            sys.exit(1)

    def _api_request(self, method: str, url: str, params: Dict = None) -> Dict:
        """Helper method for API requests that returns JSON directly"""
        response = self.api_request(method, url.replace(self.api_base_url, ''), params=params)

        if response.status_code in [200, 201]:
            return response.json()
        else:
            error_msg = response.json().get('message', 'Unknown error') if response.text else 'Unknown error'
            print_error(f"API request failed: {error_msg}")
            sys.exit(1)

    def _print_header(self, title: str):
        """Print a formatted header"""
        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}{title}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

    def cmd_ip_scan(self, ip: str, output_format: str = 'table', force: bool = False, advanced: bool = False, expert: bool = False):
        """Scan an IP address for intelligence data"""
        url = f"{self.api_base_url}/ip/{ip}/scan"
        params = {}
        if force:
            params['force_refresh'] = 'true'
        if advanced:
            params['advanced'] = 'true'
        if expert:
            params['expert'] = 'true'
            # Default expert options - user can customize via config later
            params['options'] = json.dumps({
                "geo": ["ipinfo", "maxmind", "bgp", "ripestat"],
                "security": ["abuseipdb", "rbl", "threatintel"],
                "advanced": ["cloudflare", "privacy", "reverse-dns", "whois"]
            })

        response = self._api_request('GET', url, params=params)

        if output_format == 'json':
            print(json.dumps(response, indent=2))
            return

        # Table format
        scan_mode = response.get('scan_mode', 'standard')
        if expert:
            header_suffix = f" [{Fore.MAGENTA}EXPERT MODE{Style.RESET_ALL}]"
        elif scan_mode == 'advanced':
            header_suffix = f" [{Fore.CYAN}ADVANCED MODE{Style.RESET_ALL}]"
        else:
            header_suffix = ""
        self._print_header(f"IP Intelligence: {ip}{header_suffix}")

        # Show advanced features status if advanced mode
        if scan_mode == 'advanced' and 'advanced_features' in response:
            features = response['advanced_features']
            print(f"\n{Fore.YELLOW}🔬 Advanced Features:{Style.RESET_ALL}")
            print(f"  Cloudflare API:        {'✓' if features.get('cloudflare_enabled') else '✗'}")
            print(f"  IPInfo Privacy:        {'✓' if features.get('ipinfo_privacy_detection') else '✗'}")
            print(f"  AbuseIPDB Intel:       {'✓' if features.get('abuseipdb_threat_intel') else '✗'}")
            print(f"  BGP Analysis:          {'✓' if features.get('bgp_analysis') else '✗'}")
            print(f"  Comprehensive RBL:     {'✓' if features.get('rbl_comprehensive') else '✗'}")

        geo = response.get('geolocation', {})
        net = response.get('network', {})
        rep = response.get('reputation', {})
        bgp = response.get('bgp', {})

        # Geolocation table
        if geo:
            data = [
                ['Country', geo.get('country', 'N/A')],
                ['Region', geo.get('region', 'N/A')],
                ['City', geo.get('city', 'N/A')],
                ['Timezone', geo.get('timezone', 'N/A')]
            ]
            print(f"\n{Fore.CYAN}Geolocation:{Style.RESET_ALL}")
            print(tabulate(data, tablefmt='simple'))

        # Network table
        if net:
            data = [
                ['ASN', f"AS{net.get('asn', 'N/A')}"],
                ['AS Name', net.get('asn_name', 'N/A')],
                ['Organization', net.get('organization', 'N/A')],
                ['ISP', net.get('isp', 'N/A')]
            ]
            print(f"\n{Fore.CYAN}Network:{Style.RESET_ALL}")
            print(tabulate(data, tablefmt='simple'))

            # Privacy detection (advanced feature)
            if net.get('is_vpn') is not None:
                privacy_data = [
                    ['VPN', f"{Fore.YELLOW if net.get('is_vpn') else Fore.GREEN}{'Yes' if net.get('is_vpn') else 'No'}{Style.RESET_ALL}"],
                    ['Proxy', f"{Fore.YELLOW if net.get('is_proxy') else Fore.GREEN}{'Yes' if net.get('is_proxy') else 'No'}{Style.RESET_ALL}"],
                    ['Tor', f"{Fore.RED if net.get('is_tor') else Fore.GREEN}{'Yes' if net.get('is_tor') else 'No'}{Style.RESET_ALL}"],
                    ['Hosting', f"{Fore.YELLOW if net.get('is_hosting') else Fore.GREEN}{'Yes' if net.get('is_hosting') else 'No'}{Style.RESET_ALL}"]
                ]
                print(f"\n{Fore.YELLOW}Privacy Detection:{Style.RESET_ALL}")
                print(tabulate(privacy_data, tablefmt='simple'))

        # Reputation table
        if rep:
            abuse_conf = rep.get('abuse_confidence', 0)
            color = Fore.GREEN if abuse_conf < 25 else (Fore.YELLOW if abuse_conf < 75 else Fore.RED)

            data = [
                ['Abuse Confidence', f"{color}{abuse_conf}%{Style.RESET_ALL}"],
                ['Total Reports', rep.get('total_reports', 0)],
                ['Whitelisted', rep.get('is_whitelisted', False)],
                ['Blacklist Hits', rep.get('blacklists', {}).get('hit_count', 0)]
            ]
            print(f"\n{Fore.CYAN}Reputation:{Style.RESET_ALL}")
            print(tabulate(data, tablefmt='simple'))

    def cmd_ip_reputation(self, ip: str):
        """Quick IP reputation check"""
        url = f"{self.api_base_url}/ip/{ip}/reputation"
        response = self._api_request('GET', url)

        abuse_conf = response.get('abuse_confidence', 0)
        color = Fore.GREEN if abuse_conf < 25 else (Fore.YELLOW if abuse_conf < 75 else Fore.RED)

        print(f"\n{Fore.CYAN}IP Reputation: {ip}{Style.RESET_ALL}")
        print(f"  Abuse Confidence: {color}{abuse_conf}%{Style.RESET_ALL}")
        print(f"  Total Reports: {response.get('total_reports', 0)}")
        print(f"  Blacklist Hits: {response.get('rbl_hit_count', 0)}")

    def cmd_asn_lookup(self, asn: int):
        """Lookup Autonomous System information"""
        url = f"{self.api_base_url}/asn/{asn}"
        response = self._api_request('GET', url)

        print(f"\n{Fore.CYAN}AS{asn} Information:{Style.RESET_ALL}")
        print(f"  Name: {response.get('as_name', 'N/A')}")
        print(f"  Organization: {response.get('organization', 'N/A')}")
        print(f"  Country: {response.get('country', 'N/A')}")
        print(f"  Prefixes: {len(response.get('prefixes', []))}")


# Utility functions
def print_success(message: str):
    """Print success message"""
    print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")


def print_error(message: str):
    """Print error message"""
    print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}", file=sys.stderr)


def print_info(message: str):
    """Print info message"""
    print(f"{Fore.CYAN}ℹ {message}{Style.RESET_ALL}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")


def get_score_color(score: int) -> str:
    """Get color for score value"""
    if score >= 90:
        return Fore.GREEN
    elif score >= 70:
        return Fore.YELLOW
    else:
        return Fore.RED


class ProgressSpinner:
    """Animated progress spinner"""

    def __init__(self, message: str):
        self.message = message
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.idx = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        sys.stdout.write('\r' + ' ' * (len(self.message) + 5) + '\r')
        sys.stdout.flush()


# Main CLI parser
def main():
    parser = argparse.ArgumentParser(
        description='DNS Science CLI - Enterprise DNS Security Intelligence',
        epilog=f'Version {VERSION} | https://dnsscience.io'
    )

    parser.add_argument('--version', action='version', version=f'DNS Science CLI {VERSION}')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a domain')
    scan_parser.add_argument('domain', help='Domain to scan')
    scan_parser.add_argument('--type', choices=['quick', 'standard', 'full'], default='standard', help='Scan type')
    scan_parser.add_argument('--format', choices=['table', 'json', 'raw'], default='table', help='Output format')
    scan_parser.add_argument('--output', help='Output file (JSON format)')

    # Certificate command
    cert_parser = subparsers.add_parser('cert', help='Get certificate information')
    cert_parser.add_argument('domain', help='Domain to check')
    cert_parser.add_argument('--port', type=int, default=443, help='Port number')
    cert_parser.add_argument('--format', choices=['table', 'json'], default='table', help='Output format')

    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report')
    report_parser.add_argument('action', choices=['generate'], help='Report action')
    report_parser.add_argument('domain', help='Domain for report')
    report_parser.add_argument('--format', choices=['pdf', 'html', 'json', 'csv'], default='pdf', help='Report format')
    report_parser.add_argument('--output', help='Output file path')

    # IP Intelligence commands
    ip_parser = subparsers.add_parser('ip', help='IP intelligence operations')
    ip_subparsers = ip_parser.add_subparsers(dest='ip_action')

    scan_parser = ip_subparsers.add_parser('scan', help='Scan IP address')
    scan_parser.add_argument('ip', help='IP address')
    scan_parser.add_argument('--format', choices=['table', 'json'], default='table')
    scan_parser.add_argument('--force', action='store_true', help='Force refresh')
    scan_parser.add_argument('--advanced', action='store_true', help='Advanced mode with Cloudflare, IPInfo privacy, AbuseIPDB threat intel')
    scan_parser.add_argument('--expert', action='store_true', help='Expert mode with customizable intelligence sources')

    rep_parser = ip_subparsers.add_parser('reputation', help='Check IP reputation')
    rep_parser.add_argument('ip', help='IP address')

    asn_parser = ip_subparsers.add_parser('asn', help='Lookup ASN')
    asn_parser.add_argument('asn', type=int, help='AS number')

    # Login command
    login_parser = subparsers.add_parser('login', help='Login and store API key')

    # User command
    user_parser = subparsers.add_parser('user', help='User management')
    user_parser.add_argument('action', choices=['profile', 'usage'], help='User action')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cli = DNSScienceCLI()

    # Execute command
    if args.command == 'scan':
        results = cli.scan_domain(args.domain, scan_type=args.type)
        cli.display_scan_results(results, format=args.format)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print_success(f"Results saved to {args.output}")

    elif args.command == 'cert':
        cert_info = cli.get_certificate_info(args.domain, args.port)
        cli.display_certificate_info(cert_info, format=args.format)

    elif args.command == 'report':
        if args.action == 'generate':
            cli.generate_report(args.domain, format=args.format, output=args.output)

    elif args.command == 'ip':
        if args.ip_action == 'scan':
            cli.cmd_ip_scan(args.ip, output_format=args.format, force=args.force, advanced=args.advanced, expert=getattr(args, 'expert', False))
        elif args.ip_action == 'reputation':
            cli.cmd_ip_reputation(args.ip)
        elif args.ip_action == 'asn':
            cli.cmd_asn_lookup(args.asn)

    elif args.command == 'login':
        print_info("DNS Science CLI Login")
        print("Get your API key from: https://dnsscience.io/dashboard/api-keys")
        api_key = input("Enter API key: ").strip()
        cli.set_api_key(api_key)

    elif args.command == 'user':
        if args.action == 'profile':
            response = cli.api_request('GET', '/user/profile')
            if response.status_code == 200:
                data = response.json()
                print(json.dumps(data, indent=2))
            else:
                print_error("Failed to fetch user profile")

        elif args.action == 'usage':
            response = cli.api_request('GET', '/subscription/usage')
            if response.status_code == 200:
                data = response.json()
                print(json.dumps(data, indent=2))
            else:
                print_error("Failed to fetch usage stats")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
