#!/usr/bin/env python3
"""
DNSScience.io CLI Tool
Comprehensive DNS Intelligence Command Line Interface

Usage:
    dnsscience <command> [arguments]

Commands:
    autodetect          - Detect your IP, resolver, EDNS, and security
    email <domain>      - Analyze email security (DMARC, SPF, DKIM, etc.)
    value <domain>      - Estimate domain valuation
    ssl <domain>        - Analyze SSL certificate
    rdap <domain>       - RDAP lookup
    threat <ip>         - Threat intelligence lookup
    trace <target>      - Visual traceroute
    batch <file>        - Process multiple domains
    config              - Configure CLI settings
"""

import click
import requests
import json
import os
import sys
from tabulate import tabulate
from datetime import datetime
import yaml

# Configuration
CONFIG_FILE = os.path.expanduser('~/.dnsscience.conf')
DEFAULT_API_URL = 'https://dnsscience.io'

class DNSScienceConfig:
    """Configuration manager"""
    def __init__(self):
        self.config = self.load_config()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {
            'api_url': DEFAULT_API_URL,
            'api_key': None,
            'output_format': 'table'
        }

    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)

    def set(self, key, value):
        self.config[key] = value
        self.save_config()

    def get(self, key, default=None):
        return self.config.get(key, default)

config = DNSScienceConfig()

class OutputFormatter:
    """Format output in multiple formats"""
    @staticmethod
    def format_output(data, format_type='table'):
        if format_type == 'json':
            return json.dumps(data, indent=2)
        elif format_type == 'yaml':
            return yaml.dump(data, default_flow_style=False)
        elif format_type == 'csv':
            return OutputFormatter.to_csv(data)
        else:
            return OutputFormatter.to_table(data)

    @staticmethod
    def to_table(data):
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            headers = data[0].keys()
            rows = [list(item.values()) for item in data]
            return tabulate(rows, headers=headers, tablefmt='grid')
        elif isinstance(data, dict):
            rows = [[k, v] for k, v in data.items()]
            return tabulate(rows, headers=['Key', 'Value'], tablefmt='grid')
        return str(data)

    @staticmethod
    def to_csv(data):
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            headers = ','.join(data[0].keys())
            rows = '\n'.join([','.join(str(v) for v in item.values()) for item in data])
            return f"{headers}\n{rows}"
        return str(data)

def make_request(endpoint, method='GET', data=None):
    """Make API request with error handling"""
    url = f"{config.get('api_url')}{endpoint}"
    headers = {}

    if config.get('api_key'):
        headers['Authorization'] = f"Bearer {config.get('api_key')}"

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=30)
        elif method == 'POST':
            headers['Content-Type'] = 'application/json'
            response = requests.post(url, json=data, headers=headers, timeout=30)
        else:
            raise ValueError(f"Unsupported method: {method}")

        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """DNSScience.io CLI - Advanced DNS Intelligence"""
    pass

@cli.command()
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml', 'csv']),
              default=None, help='Output format')
def autodetect(format):
    """Detect your IP, resolver, EDNS, and security score"""
    click.echo("Detecting DNS configuration...")

    data = make_request('/api/autolookup/all')

    if not data:
        click.echo("Error: No data returned", err=True)
        return

    output_format = format or config.get('output_format', 'table')

    if output_format == 'table':
        # Custom table for autodetect
        click.echo("\n" + "="*60)
        click.echo("DNS AUTO-DETECTION RESULTS")
        click.echo("="*60 + "\n")

        if 'ip_info' in data:
            click.echo("IP Information:")
            click.echo(f"  IP Address: {data['ip_info'].get('ip', 'N/A')}")
            click.echo(f"  Location: {data['ip_info'].get('city', 'N/A')}, {data['ip_info'].get('country', 'N/A')}")
            click.echo(f"  ISP: {data['ip_info'].get('org', 'N/A')}")
            click.echo()

        if 'resolver' in data:
            click.echo("DNS Resolver:")
            click.echo(f"  Server: {data['resolver'].get('server', 'N/A')}")
            click.echo(f"  Provider: {data['resolver'].get('provider', 'N/A')}")
            click.echo(f"  DNSSEC: {data['resolver'].get('dnssec', 'N/A')}")
            click.echo()

        if 'edns' in data:
            click.echo("EDNS Information:")
            click.echo(f"  Support: {data['edns'].get('support', 'N/A')}")
            click.echo(f"  Client Subnet: {data['edns'].get('ecs', 'N/A')}")
            click.echo()

        if 'security_score' in data:
            score = data['security_score']
            click.echo(f"Security Score: {score}/100")
            click.echo()
    else:
        click.echo(OutputFormatter.format_output(data, output_format))

@cli.command()
@click.argument('domain')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml', 'csv']),
              default=None, help='Output format')
def email(domain, format):
    """Analyze email security (DMARC, SPF, DKIM, DANE, MTA-STS)"""
    click.echo(f"Analyzing email security for {domain}...")

    data = make_request(f'/api/email-security/{domain}')

    output_format = format or config.get('output_format', 'table')

    if output_format == 'table':
        click.echo("\n" + "="*60)
        click.echo(f"EMAIL SECURITY ANALYSIS: {domain}")
        click.echo("="*60 + "\n")

        # DMARC
        if 'dmarc' in data:
            click.echo("DMARC:")
            dmarc = data['dmarc']
            click.echo(f"  Policy: {dmarc.get('policy', 'None')}")
            click.echo(f"  Subdomain Policy: {dmarc.get('subdomain_policy', 'None')}")
            click.echo(f"  Percentage: {dmarc.get('pct', '100')}%")
            click.echo(f"  Status: {'✓ PASS' if dmarc.get('valid') else '✗ FAIL'}")
            click.echo()

        # SPF
        if 'spf' in data:
            click.echo("SPF:")
            spf = data['spf']
            click.echo(f"  Record: {spf.get('record', 'None')}")
            click.echo(f"  Status: {'✓ PASS' if spf.get('valid') else '✗ FAIL'}")
            click.echo()

        # DKIM
        if 'dkim' in data:
            click.echo("DKIM:")
            dkim = data['dkim']
            click.echo(f"  Selectors Found: {len(dkim.get('selectors', []))}")
            click.echo(f"  Status: {'✓ PASS' if dkim.get('valid') else '✗ FAIL'}")
            click.echo()

        # MTA-STS
        if 'mta_sts' in data:
            click.echo("MTA-STS:")
            mta = data['mta_sts']
            click.echo(f"  Mode: {mta.get('mode', 'None')}")
            click.echo(f"  Status: {'✓ ENABLED' if mta.get('enabled') else '✗ DISABLED'}")
            click.echo()

        # Security Score
        if 'security_score' in data:
            score = data['security_score']
            click.echo(f"Overall Security Score: {score}/100")
            click.echo()
    else:
        click.echo(OutputFormatter.format_output(data, output_format))

@cli.command()
@click.argument('domain')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml', 'csv']),
              default=None, help='Output format')
def value(domain, format):
    """Estimate domain valuation"""
    click.echo(f"Calculating valuation for {domain}...")

    data = make_request(f'/api/domain-value/{domain}')

    output_format = format or config.get('output_format', 'table')

    if output_format == 'table':
        click.echo("\n" + "="*60)
        click.echo(f"DOMAIN VALUATION: {domain}")
        click.echo("="*60 + "\n")

        if 'estimated_value' in data:
            click.echo(f"Estimated Value: ${data['estimated_value']:,.2f}")
            click.echo(f"Confidence: {data.get('confidence', 'N/A')}")
            click.echo()

        if 'factors' in data:
            click.echo("Valuation Factors:")
            for factor, value in data['factors'].items():
                click.echo(f"  {factor}: {value}")
            click.echo()
    else:
        click.echo(OutputFormatter.format_output(data, output_format))

@cli.command()
@click.argument('domain')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml', 'csv']),
              default=None, help='Output format')
def ssl(domain, format):
    """Analyze SSL certificate"""
    click.echo(f"Analyzing SSL certificate for {domain}...")

    data = make_request(f'/api/ssl/{domain}')

    output_format = format or config.get('output_format', 'table')

    if output_format == 'table':
        click.echo("\n" + "="*60)
        click.echo(f"SSL CERTIFICATE ANALYSIS: {domain}")
        click.echo("="*60 + "\n")

        if 'certificate' in data:
            cert = data['certificate']
            click.echo("Certificate Information:")
            click.echo(f"  Subject: {cert.get('subject', 'N/A')}")
            click.echo(f"  Issuer: {cert.get('issuer', 'N/A')}")
            click.echo(f"  Valid From: {cert.get('valid_from', 'N/A')}")
            click.echo(f"  Valid Until: {cert.get('valid_until', 'N/A')}")
            click.echo(f"  Serial: {cert.get('serial', 'N/A')}")
            click.echo()

        if 'chain' in data:
            click.echo(f"Certificate Chain: {len(data['chain'])} certificates")
            click.echo()

        if 'security' in data:
            sec = data['security']
            click.echo("Security:")
            click.echo(f"  Valid: {'✓ YES' if sec.get('valid') else '✗ NO'}")
            click.echo(f"  Days Until Expiry: {sec.get('days_until_expiry', 'N/A')}")
            click.echo()
    else:
        click.echo(OutputFormatter.format_output(data, output_format))

@cli.command()
@click.argument('domain')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml', 'csv']),
              default=None, help='Output format')
def rdap(domain, format):
    """RDAP lookup (registration data)"""
    click.echo(f"RDAP lookup for {domain}...")

    data = make_request(f'/api/rdap/{domain}')

    output_format = format or config.get('output_format', 'table')

    if output_format == 'table':
        click.echo("\n" + "="*60)
        click.echo(f"RDAP LOOKUP: {domain}")
        click.echo("="*60 + "\n")

        if 'domain' in data:
            info = data['domain']
            click.echo("Domain Information:")
            click.echo(f"  Domain: {info.get('ldhName', 'N/A')}")
            click.echo(f"  Status: {', '.join(info.get('status', []))}")
            click.echo()

        if 'nameservers' in data:
            click.echo("Nameservers:")
            for ns in data['nameservers']:
                click.echo(f"  - {ns}")
            click.echo()

        if 'events' in data:
            click.echo("Events:")
            for event in data['events']:
                click.echo(f"  {event.get('eventAction', 'N/A')}: {event.get('eventDate', 'N/A')}")
            click.echo()
    else:
        click.echo(OutputFormatter.format_output(data, output_format))

@cli.command()
@click.argument('ip')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml', 'csv']),
              default=None, help='Output format')
def threat(ip, format):
    """Threat intelligence lookup"""
    click.echo(f"Threat intelligence lookup for {ip}...")

    data = make_request(f'/api/threat/{ip}')

    output_format = format or config.get('output_format', 'table')

    if output_format == 'table':
        click.echo("\n" + "="*60)
        click.echo(f"THREAT INTELLIGENCE: {ip}")
        click.echo("="*60 + "\n")

        if 'threat_score' in data:
            score = data['threat_score']
            status = "CLEAN" if score < 30 else "SUSPICIOUS" if score < 70 else "MALICIOUS"
            click.echo(f"Threat Score: {score}/100 ({status})")
            click.echo()

        if 'feeds' in data:
            click.echo("Threat Feeds:")
            for feed, result in data['feeds'].items():
                status_icon = "✓" if result.get('clean') else "✗"
                click.echo(f"  {status_icon} {feed}: {result.get('status', 'N/A')}")
            click.echo()

        if 'geolocation' in data:
            geo = data['geolocation']
            click.echo(f"Location: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}")
            click.echo()
    else:
        click.echo(OutputFormatter.format_output(data, output_format))

@cli.command()
@click.argument('target')
@click.option('--max-hops', '-m', default=30, help='Maximum number of hops')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml', 'csv']),
              default=None, help='Output format')
def trace(target, max_hops, format):
    """Visual traceroute (CLI version)"""
    click.echo(f"Traceroute to {target} (max {max_hops} hops)...")

    data = make_request('/api/traceroute', method='POST', data={
        'target': target,
        'source': 'local',
        'max_hops': max_hops
    })

    output_format = format or config.get('output_format', 'table')

    if output_format == 'table':
        click.echo("\n" + "="*60)
        click.echo(f"TRACEROUTE: {target}")
        click.echo("="*60 + "\n")

        if 'hops' in data:
            rows = []
            for hop in data['hops']:
                location = hop.get('location', {})
                rows.append([
                    hop.get('hop'),
                    hop.get('ip', '*'),
                    hop.get('hostname', '*'),
                    f"{hop.get('latency', 0):.2f}ms" if hop.get('latency') else '*',
                    f"{location.get('city', '')}, {location.get('country', '')}" if location else ''
                ])

            click.echo(tabulate(rows, headers=['Hop', 'IP', 'Hostname', 'Latency', 'Location'], tablefmt='grid'))
            click.echo()

        if 'stats' in data:
            stats = data['stats']
            click.echo(f"Total Hops: {stats.get('total_hops', 0)}")
            click.echo(f"Total Latency: {stats.get('total_latency_ms', 0):.2f}ms")
            click.echo(f"Countries Traversed: {stats.get('countries_traversed', 0)}")
    else:
        click.echo(OutputFormatter.format_output(data, output_format))

@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--checks', '-c', default='email,ssl,rdap',
              help='Comma-separated list of checks (email,ssl,rdap,threat,value)')
@click.option('--output', '-o', type=click.Path(), help='Output file')
@click.option('--format', '-f', type=click.Choice(['json', 'csv']),
              default='json', help='Output format')
def batch(file, checks, output, format):
    """Process multiple domains from a file"""
    check_list = [c.strip() for c in checks.split(',')]

    with open(file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    click.echo(f"Processing {len(domains)} domains with checks: {', '.join(check_list)}")

    results = []

    with click.progressbar(domains, label='Processing domains') as bar:
        for domain in bar:
            domain_result = {'domain': domain}

            for check in check_list:
                try:
                    if check == 'email':
                        data = make_request(f'/api/email-security/{domain}')
                    elif check == 'ssl':
                        data = make_request(f'/api/ssl/{domain}')
                    elif check == 'rdap':
                        data = make_request(f'/api/rdap/{domain}')
                    elif check == 'threat':
                        data = make_request(f'/api/threat/{domain}')
                    elif check == 'value':
                        data = make_request(f'/api/domain-value/{domain}')
                    else:
                        data = {'error': f'Unknown check: {check}'}

                    domain_result[check] = data
                except Exception as e:
                    domain_result[check] = {'error': str(e)}

            results.append(domain_result)

    # Output results
    output_data = OutputFormatter.format_output(results, format)

    if output:
        with open(output, 'w') as f:
            f.write(output_data)
        click.echo(f"\nResults saved to {output}")
    else:
        click.echo("\n" + output_data)

@cli.command()
@click.option('--api-key', help='Set API key')
@click.option('--api-url', help='Set API URL')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml', 'csv']),
              help='Set default output format')
@click.option('--show', is_flag=True, help='Show current configuration')
def config_cmd(api_key, api_url, format, show):
    """Configure CLI settings"""
    if show:
        click.echo("\nCurrent Configuration:")
        click.echo(f"  API URL: {config.get('api_url')}")
        click.echo(f"  API Key: {'*' * 10 if config.get('api_key') else 'Not set'}")
        click.echo(f"  Output Format: {config.get('output_format')}")
        click.echo()
        return

    if api_key:
        config.set('api_key', api_key)
        click.echo("API key updated")

    if api_url:
        config.set('api_url', api_url)
        click.echo("API URL updated")

    if format:
        config.set('output_format', format)
        click.echo("Output format updated")

    if not any([api_key, api_url, format]):
        click.echo("Use --help to see available options")

# Rename config command to avoid conflict
cli.add_command(config_cmd, name='config')

if __name__ == '__main__':
    cli()
