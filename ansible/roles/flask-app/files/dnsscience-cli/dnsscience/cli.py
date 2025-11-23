#!/usr/bin/env python3
"""DNS Science CLI - Command Line Interface"""
import click
import requests
import json
import os
from tabulate import tabulate
from datetime import datetime
import sys


class Config:
    """CLI Configuration"""
    def __init__(self):
        self.api_url = os.getenv('DNSSCIENCE_API_URL', 'https://dnsscience.io')
        self.api_key = os.getenv('DNSSCIENCE_API_KEY', None)
        self.config_file = os.path.expanduser('~/.dnsscience/config.json')
        self.load_config()

    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.api_url = config.get('api_url', self.api_url)
                    self.api_key = config.get('api_key', self.api_key)
            except Exception:
                pass

    def save_config(self):
        """Save configuration to file"""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump({
                'api_url': self.api_url,
                'api_key': self.api_key
            }, f, indent=2)


config = Config()


def make_request(endpoint, method='GET', data=None, params=None):
    """Make API request"""
    url = f"{config.api_url}{endpoint}"
    headers = {}

    if config.api_key:
        headers['Authorization'] = f'Bearer {config.api_key}'

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, params=params, timeout=30)
        elif method == 'POST':
            headers['Content-Type'] = 'application/json'
            response = requests.post(url, headers=headers, json=data, timeout=30)
        else:
            raise ValueError(f'Unsupported method: {method}')

        response.raise_for_status()
        return response.json()

    except requests.exceptions.Timeout:
        click.echo('Error: Request timed out', err=True)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        click.echo(f'Error: {str(e)}', err=True)
        sys.exit(1)


@click.group()
@click.version_option(version='1.0.0')
def main():
    """DNS Science CLI - DNS and Email Security Scanner"""
    pass


@main.command()
@click.argument('domain')
@click.option('--ssl/--no-ssl', default=True, help='Check SSL certificates')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def scan(domain, ssl, output_json):
    """Scan a domain for DNS and email security"""
    click.echo(f'Scanning {domain}...')

    result = make_request('/api/scan', method='POST', data={
        'domain': domain,
        'check_ssl': ssl
    })

    if output_json:
        click.echo(json.dumps(result, indent=2))
        return

    # Display results in a nice table format
    click.echo('\n=== DNS Records ===')
    if result.get('dns_records'):
        for record_type, records in result['dns_records'].items():
            if records:
                click.echo(f'\n{record_type} Records:')
                if isinstance(records, list):
                    for record in records:
                        click.echo(f'  - {record}')
                else:
                    click.echo(f'  {records}')

    click.echo('\n=== Email Security ===')
    email_checks = [
        ('SPF', result.get('spf_valid')),
        ('DKIM', result.get('dkim_valid')),
        ('DMARC', result.get('dmarc_enabled')),
        ('MTA-STS', result.get('mta_sts_enabled')),
    ]

    for check, value in email_checks:
        status = '✓' if value else '✗'
        color = 'green' if value else 'red'
        click.echo(click.style(f'{status} {check}', fg=color))

    click.echo('\n=== DNS Security ===')
    security_checks = [
        ('DNSSEC Enabled', result.get('dnssec_enabled')),
        ('DNSSEC Valid', result.get('dnssec_valid')),
        ('CAA Records', result.get('caa_records')),
    ]

    for check, value in security_checks:
        status = '✓' if value else '✗'
        color = 'green' if value else 'red'
        click.echo(click.style(f'{status} {check}', fg=color))

    if ssl and result.get('ssl_certificates'):
        click.echo('\n=== SSL Certificates ===')
        for cert in result['ssl_certificates']:
            click.echo(f"\nPort {cert.get('port', 'N/A')}:")
            click.echo(f"  Subject: {cert.get('subject', 'N/A')}")
            click.echo(f"  Issuer: {cert.get('issuer', 'N/A')}")
            click.echo(f"  Valid From: {cert.get('not_before', 'N/A')}")
            click.echo(f"  Valid Until: {cert.get('not_after', 'N/A')}")
            click.echo(f"  Serial: {cert.get('serial_number', 'N/A')}")


@main.command()
@click.argument('query')
@click.option('--limit', default=50, help='Maximum number of results')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def search(query, limit, output_json):
    """Search for domains"""
    result = make_request('/api/search', params={'q': query, 'limit': limit})

    if output_json:
        click.echo(json.dumps(result, indent=2))
        return

    domains = result.get('domains', [])

    if not domains:
        click.echo('No domains found')
        return

    click.echo(f"\nFound {len(domains)} domain(s):\n")

    # Display as table
    headers = ['Domain', 'First Checked', 'Last Checked']
    rows = []

    for domain in domains:
        rows.append([
            domain.get('domain_name', 'N/A'),
            domain.get('first_checked', 'N/A'),
            domain.get('last_checked', 'N/A')
        ])

    click.echo(tabulate(rows, headers=headers, tablefmt='grid'))


@main.command()
@click.argument('domain')
@click.option('--limit', default=100, help='Maximum number of history entries')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def history(domain, limit, output_json):
    """View scan history for a domain"""
    result = make_request(f'/api/domain/{domain}/history', params={'limit': limit})

    if output_json:
        click.echo(json.dumps(result, indent=2))
        return

    history_entries = result.get('history', [])

    if not history_entries:
        click.echo(f'No history found for {domain}')
        return

    click.echo(f"\nScan history for {domain} ({len(history_entries)} entries):\n")

    headers = ['Timestamp', 'DNSSEC', 'SPF', 'DKIM', 'DMARC']
    rows = []

    for entry in history_entries:
        rows.append([
            entry.get('scan_timestamp', 'N/A'),
            '✓' if entry.get('dnssec_enabled') else '✗',
            '✓' if entry.get('spf_valid') else '✗',
            '✓' if entry.get('dkim_valid') else '✗',
            '✓' if entry.get('dmarc_enabled') else '✗'
        ])

    click.echo(tabulate(rows, headers=headers, tablefmt='grid'))


@main.command()
@click.argument('domain')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def info(domain, output_json):
    """Get latest scan information for a domain"""
    result = make_request(f'/api/domain/{domain}')

    if output_json:
        click.echo(json.dumps(result, indent=2))
        return

    if 'error' in result:
        click.echo(f"Error: {result['error']}", err=True)
        return

    click.echo(f"\n=== Domain Information: {domain} ===\n")

    # Basic info
    click.echo(f"First Checked: {result.get('first_checked', 'N/A')}")
    click.echo(f"Last Checked: {result.get('last_checked', 'N/A')}")

    # Security summary
    click.echo("\n=== Security Summary ===")
    security_items = [
        ('DNSSEC Enabled', result.get('dnssec_enabled')),
        ('DNSSEC Valid', result.get('dnssec_valid')),
        ('SPF Valid', result.get('spf_valid')),
        ('DKIM Valid', result.get('dkim_valid')),
        ('DMARC Enabled', result.get('dmarc_enabled')),
        ('MTA-STS Enabled', result.get('mta_sts_enabled')),
    ]

    for item, value in security_items:
        status = '✓' if value else '✗'
        color = 'green' if value else 'red'
        click.echo(click.style(f'{status} {item}', fg=color))


@main.command()
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def stats(output_json):
    """View platform statistics"""
    result = make_request('/api/stats/live')

    if output_json:
        click.echo(json.dumps(result, indent=2))
        return

    click.echo('\n=== DNS Science Platform Statistics ===\n')

    stats_items = [
        ('Total Domains', result.get('total_domains', 0)),
        ('SSL Certificates', result.get('ssl_certificates', 0)),
        ('Email Records', result.get('email_records', 0)),
        ('Drift Monitoring', result.get('drift_monitoring', 0)),
        ('IPs Tracked', result.get('ips_tracked', 0)),
        ('Active Feeds', result.get('active_feeds', 0)),
    ]

    for label, value in stats_items:
        click.echo(f'{label:20s}: {value:,}')

    if result.get('last_updated'):
        click.echo(f"\nLast Updated: {result['last_updated']}")


@main.command()
@click.option('--api-url', help='API URL (default: https://dnsscience.io)')
@click.option('--api-key', help='API key for authentication')
def config_set(api_url, api_key):
    """Configure DNS Science CLI"""
    if api_url:
        config.api_url = api_url
        click.echo(f'API URL set to: {api_url}')

    if api_key:
        config.api_key = api_key
        click.echo('API key configured')

    if api_url or api_key:
        config.save_config()
        click.echo(f'Configuration saved to {config.config_file}')
    else:
        click.echo('No configuration changes made')


@main.command()
def config_show():
    """Show current configuration"""
    click.echo('\n=== DNS Science CLI Configuration ===\n')
    click.echo(f'API URL: {config.api_url}')
    click.echo(f'API Key: {"Configured" if config.api_key else "Not configured"}')
    click.echo(f'Config File: {config.config_file}')


if __name__ == '__main__':
    main()
