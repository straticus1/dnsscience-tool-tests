#!/usr/bin/env python3
"""
DNS Science - DNS Comparison Tool
Compares DNS records between old and new servers to verify migration integrity.
Supports BIND9 zone files and live DNS server queries.
"""

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import argparse
import sys
import json
from typing import Dict, List, Set, Tuple
from collections import defaultdict
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class DNSComparer:
    """Compare DNS records between old and new servers"""

    def __init__(self, old_server: str = None, new_server: str = None,
                 old_zone_file: str = None, new_zone_file: str = None,
                 named_conf: str = None):
        self.old_server = old_server
        self.new_server = new_server
        self.old_zone_file = old_zone_file
        self.new_zone_file = new_zone_file
        self.named_conf = named_conf

        # Records to ignore differences (expected to be different)
        self.ignore_types = {'SOA'}  # SOA records are expected to be different

        # Results storage
        self.missing_records = []  # Records in old but not in new
        self.extra_records = []     # Records in new but not in old
        self.different_records = [] # Records that exist in both but have different values
        self.ns_differences = []    # NS/Glue record differences (informational)
        self.matching_records = []  # Records that match perfectly

    def load_zone_from_file(self, zone_file: str, origin: str = None) -> Dict:
        """Load DNS zone from BIND9 zone file"""
        try:
            if origin:
                zone = dns.zone.from_file(zone_file, origin=origin, relativize=False)
            else:
                zone = dns.zone.from_file(zone_file, relativize=False)

            records = defaultdict(list)
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    rtype = dns.rdatatype.to_text(rdataset.rdtype)
                    for rdata in rdataset:
                        record_key = f"{name}.{zone.origin}" if name != '@' else str(zone.origin)
                        records[record_key].append({
                            'type': rtype,
                            'ttl': rdataset.ttl,
                            'value': str(rdata)
                        })

            return dict(records)
        except Exception as e:
            print(f"{Fore.RED}✗ Error loading zone file {zone_file}: {e}{Style.RESET_ALL}")
            return {}

    def query_live_server(self, domain: str, server: str) -> Dict:
        """Query live DNS server for all records of a domain"""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        resolver.timeout = 5
        resolver.lifetime = 5

        records = defaultdict(list)

        # Common record types to check
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'CAA']

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    records[domain].append({
                        'type': rtype,
                        'ttl': answers.rrset.ttl,
                        'value': str(rdata)
                    })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception as e:
                if 'timeout' not in str(e).lower():
                    print(f"{Fore.YELLOW}⚠ Warning querying {domain} {rtype} from {server}: {e}{Style.RESET_ALL}")

        return dict(records)

    def normalize_record_value(self, value: str, rtype: str) -> str:
        """Normalize record values for comparison"""
        # Remove trailing dots for CNAME, MX, NS, etc.
        if rtype in ['CNAME', 'MX', 'NS', 'SRV', 'PTR']:
            value = value.rstrip('.')

        # Normalize TXT records (remove quotes, normalize spacing)
        if rtype == 'TXT':
            value = value.strip('"').strip()

        # Normalize MX records (format: priority target)
        if rtype == 'MX' and ' ' in value:
            parts = value.split(maxsplit=1)
            if len(parts) == 2:
                value = f"{parts[0]} {parts[1].rstrip('.')}"

        return value.lower()

    def compare_records(self, old_records: Dict, new_records: Dict, domain: str = None):
        """Compare DNS records between old and new"""

        # Convert to sets for comparison (ignoring TTL differences)
        old_set = set()
        new_set = set()

        for name, recs in old_records.items():
            for rec in recs:
                if rec['type'] not in self.ignore_types:
                    normalized = self.normalize_record_value(rec['value'], rec['type'])
                    old_set.add((name, rec['type'], normalized))

        for name, recs in new_records.items():
            for rec in recs:
                if rec['type'] not in self.ignore_types:
                    normalized = self.normalize_record_value(rec['value'], rec['type'])
                    new_set.add((name, rec['type'], normalized))

        # Find differences
        missing = old_set - new_set
        extra = new_set - old_set
        matching = old_set & new_set

        # Check for NS/Glue record differences separately (informational only)
        old_ns = {(n, t, v) for n, t, v in old_set if t == 'NS'}
        new_ns = {(n, t, v) for n, t, v in new_set if t == 'NS'}

        if old_ns != new_ns:
            self.ns_differences.append({
                'domain': domain or 'zone',
                'old_ns': list(old_ns),
                'new_ns': list(new_ns)
            })

        # Store results
        for name, rtype, value in missing:
            self.missing_records.append({
                'name': name,
                'type': rtype,
                'value': value,
                'severity': 'high' if rtype not in ['NS'] else 'medium'
            })

        for name, rtype, value in extra:
            self.extra_records.append({
                'name': name,
                'type': rtype,
                'value': value,
                'severity': 'low' if rtype not in ['NS'] else 'medium'
            })

        for name, rtype, value in matching:
            self.matching_records.append({
                'name': name,
                'type': rtype,
                'value': value
            })

    def compare_zone_files(self, domain: str = None):
        """Compare two zone files"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"DNS Zone File Comparison")
        print(f"{'='*70}{Style.RESET_ALL}\n")

        if self.old_zone_file:
            print(f"{Fore.BLUE}📄 Loading old zone file: {self.old_zone_file}{Style.RESET_ALL}")
            old_records = self.load_zone_from_file(self.old_zone_file, origin=domain)
        else:
            print(f"{Fore.RED}✗ No old zone file specified{Style.RESET_ALL}")
            return False

        if self.new_zone_file:
            print(f"{Fore.BLUE}📄 Loading new zone file: {self.new_zone_file}{Style.RESET_ALL}")
            new_records = self.load_zone_from_file(self.new_zone_file, origin=domain)
        else:
            print(f"{Fore.RED}✗ No new zone file specified{Style.RESET_ALL}")
            return False

        if not old_records or not new_records:
            print(f"{Fore.RED}✗ Failed to load zone files{Style.RESET_ALL}")
            return False

        print(f"\n{Fore.GREEN}✓ Zone files loaded successfully{Style.RESET_ALL}")
        print(f"  Old zone: {len(old_records)} names")
        print(f"  New zone: {len(new_records)} names")

        self.compare_records(old_records, new_records, domain)
        return True

    def compare_live_servers(self, domain: str):
        """Compare DNS records between two live servers"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"Live DNS Server Comparison")
        print(f"{'='*70}{Style.RESET_ALL}\n")

        print(f"{Fore.BLUE}🔍 Querying old server: {self.old_server} for {domain}{Style.RESET_ALL}")
        old_records = self.query_live_server(domain, self.old_server)

        print(f"{Fore.BLUE}🔍 Querying new server: {self.new_server} for {domain}{Style.RESET_ALL}")
        new_records = self.query_live_server(domain, self.new_server)

        if not old_records and not new_records:
            print(f"{Fore.RED}✗ No records returned from either server{Style.RESET_ALL}")
            return False

        print(f"\n{Fore.GREEN}✓ Servers queried successfully{Style.RESET_ALL}")
        print(f"  Old server: {sum(len(v) for v in old_records.values())} records")
        print(f"  New server: {sum(len(v) for v in new_records.values())} records")

        self.compare_records(old_records, new_records, domain)
        return True

    def print_report(self):
        """Print comprehensive comparison report"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"DNS COMPARISON REPORT")
        print(f"{'='*70}{Style.RESET_ALL}\n")

        # Summary
        total_issues = len(self.missing_records) + len(self.extra_records)

        if total_issues == 0 and len(self.ns_differences) == 0:
            print(f"{Fore.GREEN}✓ ALL RECORDS MATCH PERFECTLY!{Style.RESET_ALL}")
            print(f"  {len(self.matching_records)} records verified identical")
            return True

        # Missing Records (HIGH PRIORITY)
        if self.missing_records:
            print(f"{Fore.RED}{'─'*70}")
            print(f"⚠  MISSING RECORDS (exist in old, not in new): {len(self.missing_records)}")
            print(f"{'─'*70}{Style.RESET_ALL}\n")

            for rec in self.missing_records:
                severity_color = Fore.RED if rec['severity'] == 'high' else Fore.YELLOW
                print(f"{severity_color}  ✗ {rec['name']:<40} {rec['type']:<10} {rec['value']}{Style.RESET_ALL}")

        # Extra Records (INFORMATIONAL)
        if self.extra_records:
            print(f"\n{Fore.YELLOW}{'─'*70}")
            print(f"ℹ  EXTRA RECORDS (exist in new, not in old): {len(self.extra_records)}")
            print(f"{'─'*70}{Style.RESET_ALL}\n")

            for rec in self.extra_records:
                print(f"{Fore.YELLOW}  + {rec['name']:<40} {rec['type']:<10} {rec['value']}{Style.RESET_ALL}")

        # NS Record Differences (INFORMATIONAL - EXPECTED)
        if self.ns_differences:
            print(f"\n{Fore.CYAN}{'─'*70}")
            print(f"ℹ  NS RECORD DIFFERENCES (informational - may be expected)")
            print(f"{'─'*70}{Style.RESET_ALL}\n")

            for diff in self.ns_differences:
                print(f"  Domain: {diff['domain']}")
                print(f"  Old NS: {', '.join([f'{n[2]}' for n in diff['old_ns']])}")
                print(f"  New NS: {', '.join([f'{n[2]}' for n in diff['new_ns']])}\n")

        # Matching Records
        if self.matching_records:
            print(f"\n{Fore.GREEN}{'─'*70}")
            print(f"✓ MATCHING RECORDS: {len(self.matching_records)}")
            print(f"{'─'*70}{Style.RESET_ALL}\n")

        # Final Status
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"SUMMARY")
        print(f"{'='*70}{Style.RESET_ALL}\n")

        if len(self.missing_records) > 0:
            print(f"{Fore.RED}✗ MIGRATION VERIFICATION FAILED{Style.RESET_ALL}")
            print(f"  {len(self.missing_records)} missing records must be addressed")
            return False
        elif len(self.extra_records) > 0:
            print(f"{Fore.YELLOW}⚠ MIGRATION VERIFICATION PASSED WITH WARNINGS{Style.RESET_ALL}")
            print(f"  {len(self.extra_records)} extra records found (review recommended)")
            return True
        else:
            print(f"{Fore.GREEN}✓ MIGRATION VERIFICATION SUCCESSFUL{Style.RESET_ALL}")
            print(f"  All records match between old and new servers")
            return True

    def export_json(self, output_file: str):
        """Export comparison results to JSON"""
        results = {
            'summary': {
                'matching_records': len(self.matching_records),
                'missing_records': len(self.missing_records),
                'extra_records': len(self.extra_records),
                'ns_differences': len(self.ns_differences),
                'status': 'pass' if len(self.missing_records) == 0 else 'fail'
            },
            'missing_records': self.missing_records,
            'extra_records': self.extra_records,
            'ns_differences': self.ns_differences,
            'matching_records': self.matching_records[:100]  # Limit for size
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n{Fore.GREEN}✓ Results exported to {output_file}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description='DNS Science - DNS Migration Verification Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare zone files
  %(prog)s --old-zone old.zone --new-zone new.zone --domain example.com

  # Compare live servers
  %(prog)s --old-server 8.8.8.8 --new-server 1.1.1.1 --domain example.com

  # Mixed comparison (zone file vs live server)
  %(prog)s --old-zone old.zone --new-server 1.1.1.1 --domain example.com

  # Export results to JSON
  %(prog)s --old-zone old.zone --new-zone new.zone --domain example.com --output results.json
        """
    )

    parser.add_argument('--old-zone', help='Path to old BIND9 zone file')
    parser.add_argument('--new-zone', help='Path to new BIND9 zone file')
    parser.add_argument('--old-server', help='IP address of old DNS server')
    parser.add_argument('--new-server', help='IP address of new DNS server')
    parser.add_argument('--domain', required=True, help='Domain name to compare')
    parser.add_argument('--named-conf', help='Path to BIND9 named.conf (optional)')
    parser.add_argument('--output', help='Export results to JSON file')
    parser.add_argument('--ignore-ns', action='store_true', help='Ignore NS record differences entirely')

    args = parser.parse_args()

    # Validate inputs
    if not args.old_zone and not args.old_server:
        print(f"{Fore.RED}✗ Error: Must specify either --old-zone or --old-server{Style.RESET_ALL}")
        sys.exit(1)

    if not args.new_zone and not args.new_server:
        print(f"{Fore.RED}✗ Error: Must specify either --new-zone or --new-server{Style.RESET_ALL}")
        sys.exit(1)

    # Create comparer
    comparer = DNSComparer(
        old_server=args.old_server,
        new_server=args.new_server,
        old_zone_file=args.old_zone,
        new_zone_file=args.new_zone,
        named_conf=args.named_conf
    )

    # Perform comparison
    if args.old_zone and args.new_zone:
        # Zone file comparison
        success = comparer.compare_zone_files(args.domain)
    elif args.old_server and args.new_server:
        # Live server comparison
        success = comparer.compare_live_servers(args.domain)
    else:
        # Mixed comparison
        if args.old_zone:
            print(f"{Fore.BLUE}Loading old records from zone file...{Style.RESET_ALL}")
            old_records = comparer.load_zone_from_file(args.old_zone, origin=args.domain)
        else:
            print(f"{Fore.BLUE}Querying old server {args.old_server}...{Style.RESET_ALL}")
            old_records = comparer.query_live_server(args.domain, args.old_server)

        if args.new_zone:
            print(f"{Fore.BLUE}Loading new records from zone file...{Style.RESET_ALL}")
            new_records = comparer.load_zone_from_file(args.new_zone, origin=args.domain)
        else:
            print(f"{Fore.BLUE}Querying new server {args.new_server}...{Style.RESET_ALL}")
            new_records = comparer.query_live_server(args.domain, args.new_server)

        comparer.compare_records(old_records, new_records, args.domain)
        success = True

    if not success:
        sys.exit(1)

    # Print report
    verification_passed = comparer.print_report()

    # Export to JSON if requested
    if args.output:
        comparer.export_json(args.output)

    # Exit with appropriate code
    sys.exit(0 if verification_passed else 1)

if __name__ == '__main__':
    main()
