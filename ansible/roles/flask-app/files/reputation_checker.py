#!/usr/bin/env python3
"""
Spam Reputation and Blacklist Checker

Integrates with various spam reputation services and blacklists.
Useful for tracking spammers and email security research.
"""
import dns.resolver
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Top 25 DNS Blacklists (DNSBLs) - Most comprehensive coverage
DNSBLS = [
    # Tier 1: Major RBLs (highest accuracy)
    'zen.spamhaus.org',           # Spamhaus composite (SBL, XBL, PBL)
    'bl.spamcop.net',             # SpamCop - user reported spam
    'b.barracudacentral.org',     # Barracuda Reputation Block List
    'dnsbl.sorbs.net',            # SORBS - spam sources

    # Tier 2: Widely used RBLs
    'ix.dnsbl.manitu.net',        # Manitu - German RBL
    'dnsbl.dronebl.org',          # DroneBL - IRC spam sources
    'psbl.surriel.com',           # PSBL - passive spam block list
    'ubl.unsubscore.com',         # Unsubscribe Tracking
    'dnsbl.spfbl.net',            # SPFBL - Brazilian RBL
    'spam.dnsbl.anonmails.de',    # AnonMails DNSBL

    # Tier 3: Specialized RBLs
    'multi.uribl.com',            # URIBL - URI blacklist
    'dbl.spamhaus.org',           # Spamhaus Domain Block List
    'multi.surbl.org',            # SURBL - spam URI realtime blocklists
    'rhsbl.sorbs.net',            # SORBS RHS (right-hand side)
    'noptr.spamrats.com',         # SpamRats - no PTR record
    'spam.spamrats.com',          # SpamRats - spam sources

    # Tier 4: Additional coverage
    'cbl.abuseat.org',            # Composite Blocking List
    'cdl.anti-spam.org.cn',       # Chinese Anti-Spam
    'combined.rbl.msrbl.net',     # MSRBL - Microsoft focused
    'db.wpbl.info',               # Weighted Private Block List
    'rbl.interserver.net',        # InterServer RBL
    'bogons.cymru.com',           # Bogon IP addresses
    'dyna.spamrats.com',          # SpamRats - dynamic IPs
    'bl.mailspike.net',           # Mailspike blacklist
    'z.mailspike.net',            # Mailspike reputation
]

class ReputationChecker:
    """Check domain/IP reputation across multiple services"""

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def check_dnsbl(self, ip_address):
        """
        Check if IP is listed in DNSBLs.

        Args:
            ip_address: IP address to check

        Returns:
            dict with blacklist results
        """
        results = {
            'ip': ip_address,
            'listed_in': [],
            'clean_in': [],
            'errors': []
        }

        # Reverse IP for DNSBL lookup (1.2.3.4 -> 4.3.2.1)
        reversed_ip = '.'.join(reversed(ip_address.split('.')))

        def check_single_dnsbl(dnsbl):
            query = f"{reversed_ip}.{dnsbl}"
            try:
                self.resolver.resolve(query, 'A')
                return ('listed', dnsbl)
            except dns.resolver.NXDOMAIN:
                return ('clean', dnsbl)
            except Exception as e:
                return ('error', dnsbl, str(e))

        # Check all DNSBLs in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_single_dnsbl, dnsbl): dnsbl
                      for dnsbl in DNSBLS}

            for future in as_completed(futures):
                result = future.result()
                if result[0] == 'listed':
                    results['listed_in'].append(result[1])
                elif result[0] == 'clean':
                    results['clean_in'].append(result[1])
                else:
                    results['errors'].append(f"{result[1]}: {result[2]}")

        results['is_blacklisted'] = len(results['listed_in']) > 0
        results['blacklist_count'] = len(results['listed_in'])

        return results

    def check_mx_reputation(self, domain):
        """Check reputation of domain's MX servers"""
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            mx_hosts = [str(rdata.exchange).rstrip('.') for rdata in mx_records]

            results = {
                'domain': domain,
                'mx_hosts': mx_hosts,
                'mx_reputation': []
            }

            for mx_host in mx_hosts:
                # Resolve MX to IPs
                try:
                    a_records = self.resolver.resolve(mx_host, 'A')
                    for ip in a_records:
                        ip_str = str(ip)
                        dnsbl_result = self.check_dnsbl(ip_str)
                        results['mx_reputation'].append({
                            'mx_host': mx_host,
                            'ip': ip_str,
                            'blacklist_result': dnsbl_result
                        })
                except Exception as e:
                    logger.warning(f"Could not resolve {mx_host}: {e}")

            return results

        except Exception as e:
            logger.error(f"Error checking MX reputation for {domain}: {e}")
            return None

    def check_domain_age(self, domain):
        """
        Check domain age using WHOIS (requires whois package).
        Newer domains are often associated with spam.
        """
        try:
            import whois
            w = whois.whois(domain)

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            from datetime import datetime
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                return {
                    'creation_date': str(creation_date),
                    'age_days': age_days,
                    'is_new': age_days < 30  # Flag domains less than 30 days old
                }

        except ImportError:
            logger.warning("whois package not installed: pip install python-whois")
        except Exception as e:
            logger.warning(f"Could not check domain age: {e}")

        return None

    def check_google_safe_browsing(self, domain, api_key=None):
        """
        Check Google Safe Browsing API.
        Requires API key from: https://developers.google.com/safe-browsing/v4/get-started
        """
        if not api_key:
            logger.warning("Google Safe Browsing API key not provided")
            return None

        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

        payload = {
            "client": {
                "clientId": "dnsscience",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": domain}
                ]
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                data = response.json()
                is_threat = 'matches' in data

                return {
                    'is_threat': is_threat,
                    'threats': data.get('matches', [])
                }

        except Exception as e:
            logger.error(f"Google Safe Browsing check failed: {e}")

        return None

    def comprehensive_check(self, domain):
        """Run all reputation checks on a domain"""
        logger.info(f"Running comprehensive reputation check on {domain}")

        results = {
            'domain': domain,
            'mx_reputation': self.check_mx_reputation(domain),
            'domain_age': self.check_domain_age(domain),
            'risk_score': 0
        }

        # Calculate risk score
        risk_factors = []

        # Factor 1: MX servers blacklisted
        if results['mx_reputation']:
            for mx_rep in results['mx_reputation']['mx_reputation']:
                if mx_rep['blacklist_result']['is_blacklisted']:
                    risk_factors.append(f"MX {mx_rep['mx_host']} blacklisted")
                    results['risk_score'] += 3

        # Factor 2: New domain
        if results['domain_age'] and results['domain_age'].get('is_new'):
            risk_factors.append("Domain less than 30 days old")
            results['risk_score'] += 2

        results['risk_factors'] = risk_factors
        results['risk_level'] = (
            'HIGH' if results['risk_score'] >= 5 else
            'MEDIUM' if results['risk_score'] >= 3 else
            'LOW'
        )

        return results


def main():
    """CLI for reputation checking"""
    import argparse

    parser = argparse.ArgumentParser(description='Spam Reputation Checker')

    subparsers = parser.add_subparsers(dest='command', help='Command')

    # Check IP
    check_ip_parser = subparsers.add_parser('check-ip', help='Check IP blacklist status')
    check_ip_parser.add_argument('ip', help='IP address to check')

    # Check MX
    check_mx_parser = subparsers.add_parser('check-mx', help='Check MX server reputation')
    check_mx_parser.add_argument('domain', help='Domain to check')

    # Comprehensive check
    check_domain_parser = subparsers.add_parser('check-domain', help='Comprehensive domain check')
    check_domain_parser.add_argument('domain', help='Domain to check')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    checker = ReputationChecker()

    if args.command == 'check-ip':
        result = checker.check_dnsbl(args.ip)

        print(f"\n🔍 DNSBL Check for {result['ip']}")
        print("=" * 60)

        if result['is_blacklisted']:
            print(f"⚠️  BLACKLISTED in {result['blacklist_count']} list(s):")
            for bl in result['listed_in']:
                print(f"  ✗ {bl}")
        else:
            print(f"✓ Clean (checked {len(result['clean_in'])} lists)")

        if result['errors']:
            print(f"\nErrors:")
            for error in result['errors']:
                print(f"  {error}")

    elif args.command == 'check-mx':
        result = checker.check_mx_reputation(args.domain)

        if result:
            print(f"\n📧 MX Reputation for {result['domain']}")
            print("=" * 60)

            for mx_rep in result['mx_reputation']:
                print(f"\n{mx_rep['mx_host']} ({mx_rep['ip']})")
                bl_result = mx_rep['blacklist_result']

                if bl_result['is_blacklisted']:
                    print(f"  ⚠️  BLACKLISTED in {bl_result['blacklist_count']} list(s):")
                    for bl in bl_result['listed_in']:
                        print(f"    ✗ {bl}")
                else:
                    print(f"  ✓ Clean")

    elif args.command == 'check-domain':
        result = checker.comprehensive_check(args.domain)

        print(f"\n🔍 Comprehensive Check for {result['domain']}")
        print("=" * 60)

        print(f"\nRisk Score: {result['risk_score']}")
        print(f"Risk Level: {result['risk_level']}")

        if result['risk_factors']:
            print(f"\n⚠️  Risk Factors:")
            for factor in result['risk_factors']:
                print(f"  - {factor}")
        else:
            print(f"\n✓ No risk factors detected")

        if result['domain_age']:
            print(f"\nDomain Age: {result['domain_age']['age_days']} days")


if __name__ == '__main__':
    main()
