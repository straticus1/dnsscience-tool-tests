#!/usr/bin/env python3
"""CLI tool for DNS Science Tracker - Bulk operations and automation"""
import argparse
import sys
import time
import json
from database import Database
from checkers import DomainScanner

def scan_domain(domain, db, scanner, verbose=False):
    """Scan a single domain and save results"""
    if verbose:
        print(f"Scanning {domain}...", end=' ', flush=True)

    result = scanner.scan_domain(domain)
    db.save_scan_result(domain, result)

    if verbose:
        status = "✓" if result['scan_status'] == 'completed' else "✗"
        print(f"{status}")

    return result

def bulk_scan(domains, db, scanner, delay=1, verbose=True):
    """Scan multiple domains with delay between scans"""
    results = []

    for i, domain in enumerate(domains, 1):
        if verbose:
            print(f"[{i}/{len(domains)}] ", end='')

        try:
            result = scan_domain(domain, db, scanner, verbose=verbose)
            results.append(result)

            # Rate limiting - be nice to DNS servers
            if i < len(domains):
                time.sleep(delay)

        except KeyboardInterrupt:
            print("\n\nScan interrupted by user.")
            break
        except Exception as e:
            if verbose:
                print(f"Error scanning {domain}: {e}")
            results.append({
                'domain': domain,
                'scan_status': 'failed',
                'error_message': str(e)
            })

    return results

def import_from_file(filename, db, scanner, delay=1):
    """Import domains from a text file (one per line)"""
    domains = []

    try:
        with open(filename, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    domains.append(domain)

        print(f"Loaded {len(domains)} domains from {filename}")
        return bulk_scan(domains, db, scanner, delay=delay)

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

def rescan_all(db, scanner, days=None, delay=1):
    """Rescan all domains or domains not scanned in X days"""
    domains = db.get_all_domains(limit=10000)

    if days:
        print(f"Rescanning domains not checked in last {days} days...")
        # Filter by last_checked date
        # TODO: Implement date filtering
    else:
        print(f"Rescanning all {len(domains)} tracked domains...")

    domain_names = [d['domain_name'] for d in domains]
    return bulk_scan(domain_names, db, scanner, delay=delay)

def export_results(db, output_file, format='json'):
    """Export all scan results"""
    domains = db.get_all_domains(limit=10000)
    results = []

    for domain in domains:
        latest = db.get_latest_scan(domain['domain_name'])
        if latest:
            results.append(latest)

    if format == 'json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Exported {len(results)} domains to {output_file}")

    elif format == 'csv':
        import csv
        with open(output_file, 'w', newline='') as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        print(f"Exported {len(results)} domains to {output_file}")

def show_stats(db):
    """Show database statistics"""
    domains = db.get_all_domains(limit=10000)

    print(f"\n📊 Database Statistics")
    print(f"{'='*50}")
    print(f"Total domains tracked: {len(domains)}")

    # Count by security features
    stats = {
        'dnssec': 0,
        'spf': 0,
        'dkim': 0,
        'mta_sts': 0,
        'starttls_25': 0,
        'starttls_587': 0
    }

    for domain in domains:
        latest = db.get_latest_scan(domain['domain_name'])
        if latest:
            if latest.get('dnssec_enabled'):
                stats['dnssec'] += 1
            if latest.get('spf_valid'):
                stats['spf'] += 1
            if latest.get('dkim_valid'):
                stats['dkim'] += 1
            if latest.get('mta_sts_enabled'):
                stats['mta_sts'] += 1
            if latest.get('smtp_starttls_25'):
                stats['starttls_25'] += 1
            if latest.get('smtp_starttls_587'):
                stats['starttls_587'] += 1

    print(f"\nSecurity Feature Adoption:")
    print(f"  DNSSEC:           {stats['dnssec']:5d} ({stats['dnssec']/len(domains)*100:.1f}%)")
    print(f"  SPF:              {stats['spf']:5d} ({stats['spf']/len(domains)*100:.1f}%)")
    print(f"  DKIM:             {stats['dkim']:5d} ({stats['dkim']/len(domains)*100:.1f}%)")
    print(f"  MTA-STS:          {stats['mta_sts']:5d} ({stats['mta_sts']/len(domains)*100:.1f}%)")
    print(f"  STARTTLS (25):    {stats['starttls_25']:5d} ({stats['starttls_25']/len(domains)*100:.1f}%)")
    print(f"  STARTTLS (587):   {stats['starttls_587']:5d} ({stats['starttls_587']/len(domains)*100:.1f}%)")
    print()

def main():
    parser = argparse.ArgumentParser(
        description='DNS Science Tracker - CLI Tool',
        epilog='Examples:\n'
               '  %(prog)s scan example.com\n'
               '  %(prog)s import domains.txt\n'
               '  %(prog)s rescan --days 7\n'
               '  %(prog)s export results.json\n'
               '  %(prog)s stats\n',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a single domain')
    scan_parser.add_argument('domain', help='Domain to scan')
    scan_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    # Import command
    import_parser = subparsers.add_parser('import', help='Import domains from file')
    import_parser.add_argument('file', help='Text file with domains (one per line)')
    import_parser.add_argument('-d', '--delay', type=float, default=1,
                              help='Delay between scans in seconds (default: 1)')

    # Rescan command
    rescan_parser = subparsers.add_parser('rescan', help='Rescan all tracked domains')
    rescan_parser.add_argument('--days', type=int,
                              help='Only rescan domains not checked in X days')
    rescan_parser.add_argument('-d', '--delay', type=float, default=1,
                              help='Delay between scans in seconds (default: 1)')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export scan results')
    export_parser.add_argument('output', help='Output file path')
    export_parser.add_argument('-f', '--format', choices=['json', 'csv'],
                              default='json', help='Output format (default: json)')

    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')

    # List command
    list_parser = subparsers.add_parser('list', help='List all tracked domains')
    list_parser.add_argument('-l', '--limit', type=int, default=100,
                            help='Max domains to show (default: 100)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Initialize
    db = Database()
    scanner = DomainScanner()

    # Execute command
    if args.command == 'scan':
        result = scan_domain(args.domain, db, scanner, verbose=True)
        if args.verbose:
            print(json.dumps(result, indent=2))

    elif args.command == 'import':
        import_from_file(args.file, db, scanner, delay=args.delay)

    elif args.command == 'rescan':
        rescan_all(db, scanner, days=args.days, delay=args.delay)

    elif args.command == 'export':
        export_results(db, args.output, format=args.format)

    elif args.command == 'stats':
        show_stats(db)

    elif args.command == 'list':
        domains = db.get_all_domains(limit=args.limit)
        print(f"\nTracked domains ({len(domains)}):")
        print(f"{'='*70}")
        for domain in domains:
            last_checked = domain['last_checked'] or 'Never'
            print(f"  {domain['domain_name']:40s} {last_checked}")

if __name__ == '__main__':
    main()
