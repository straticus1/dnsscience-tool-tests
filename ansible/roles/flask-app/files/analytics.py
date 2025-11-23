#!/usr/bin/env python3
"""
Analytics and Trend Analysis Tools

Generate reports and analyze trends in email security adoption.
"""
import json
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Analytics:
    """Analytics engine for security trend analysis"""

    def __init__(self, db):
        self.db = db

    def security_adoption_report(self):
        """Generate security feature adoption statistics"""
        logger.info("Generating security adoption report...")

        # Get latest scan for all domains
        domains = self.db.get_all_domains(limit=100000)

        stats = {
            'total_domains': len(domains),
            'scanned_domains': 0,
            'dnssec': {'enabled': 0, 'valid': 0},
            'spf': {'valid': 0},
            'dkim': {'valid': 0},
            'mta_sts': {'enabled': 0},
            'starttls': {'port_25': 0, 'port_587': 0, 'both': 0},
            'full_compliance': 0  # All features enabled
        }

        for domain in domains:
            latest = self.db.get_latest_scan(domain['domain_name'])
            if not latest:
                continue

            stats['scanned_domains'] += 1

            # Count features
            dnssec_ok = latest.get('dnssec_enabled')
            dnssec_valid = latest.get('dnssec_valid')
            spf_ok = latest.get('spf_valid')
            dkim_ok = latest.get('dkim_valid')
            mta_sts_ok = latest.get('mta_sts_enabled')
            tls_25 = latest.get('smtp_starttls_25')
            tls_587 = latest.get('smtp_starttls_587')

            if dnssec_ok:
                stats['dnssec']['enabled'] += 1
            if dnssec_valid:
                stats['dnssec']['valid'] += 1
            if spf_ok:
                stats['spf']['valid'] += 1
            if dkim_ok:
                stats['dkim']['valid'] += 1
            if mta_sts_ok:
                stats['mta_sts']['enabled'] += 1
            if tls_25:
                stats['starttls']['port_25'] += 1
            if tls_587:
                stats['starttls']['port_587'] += 1
            if tls_25 and tls_587:
                stats['starttls']['both'] += 1

            # Full compliance check
            if all([dnssec_valid, spf_ok, dkim_ok, mta_sts_ok, tls_25, tls_587]):
                stats['full_compliance'] += 1

        # Calculate percentages
        if stats['scanned_domains'] > 0:
            total = stats['scanned_domains']
            stats['percentages'] = {
                'dnssec_enabled': (stats['dnssec']['enabled'] / total) * 100,
                'dnssec_valid': (stats['dnssec']['valid'] / total) * 100,
                'spf': (stats['spf']['valid'] / total) * 100,
                'dkim': (stats['dkim']['valid'] / total) * 100,
                'mta_sts': (stats['mta_sts']['enabled'] / total) * 100,
                'starttls_25': (stats['starttls']['port_25'] / total) * 100,
                'starttls_587': (stats['starttls']['port_587'] / total) * 100,
                'full_compliance': (stats['full_compliance'] / total) * 100
            }

        return stats

    def drift_analysis(self, days=30):
        """Analyze configuration drift over time"""
        logger.info(f"Analyzing drift over last {days} days...")

        domains = self.db.get_all_domains(limit=10000)
        drift_report = {
            'total_domains': len(domains),
            'domains_with_drift': 0,
            'drift_by_feature': defaultdict(int),
            'drift_examples': []
        }

        for domain in domains:
            history = self.db.get_scan_history(domain['domain_name'], limit=100)

            if len(history) < 2:
                continue

            # Compare recent scans
            changes = []
            for i in range(len(history) - 1):
                newer = history[i]
                older = history[i + 1]

                # Check each feature for changes
                features = [
                    ('dnssec_enabled', 'DNSSEC'),
                    ('spf_valid', 'SPF'),
                    ('dkim_valid', 'DKIM'),
                    ('mta_sts_enabled', 'MTA-STS'),
                    ('smtp_starttls_25', 'STARTTLS-25'),
                    ('smtp_starttls_587', 'STARTTLS-587')
                ]

                for field, label in features:
                    if newer.get(field) != older.get(field):
                        changes.append({
                            'feature': label,
                            'old': older.get(field),
                            'new': newer.get(field),
                            'timestamp': newer.get('scan_timestamp')
                        })
                        drift_report['drift_by_feature'][label] += 1

            if changes:
                drift_report['domains_with_drift'] += 1
                drift_report['drift_examples'].append({
                    'domain': domain['domain_name'],
                    'changes': changes
                })

        return drift_report

    def top_vulnerable_domains(self, limit=100):
        """Identify domains with worst security posture"""
        logger.info("Identifying most vulnerable domains...")

        domains = self.db.get_all_domains(limit=10000)
        scored_domains = []

        for domain in domains:
            latest = self.db.get_latest_scan(domain['domain_name'])
            if not latest:
                continue

            # Calculate security score (lower is worse)
            score = 0
            if latest.get('dnssec_valid'):
                score += 2
            if latest.get('spf_valid'):
                score += 2
            if latest.get('dkim_valid'):
                score += 2
            if latest.get('mta_sts_enabled'):
                score += 2
            if latest.get('smtp_starttls_25'):
                score += 1
            if latest.get('smtp_starttls_587'):
                score += 1

            scored_domains.append({
                'domain': domain['domain_name'],
                'score': score,
                'max_score': 10,
                'dnssec': latest.get('dnssec_valid'),
                'spf': latest.get('spf_valid'),
                'dkim': latest.get('dkim_valid'),
                'mta_sts': latest.get('mta_sts_enabled'),
                'starttls_25': latest.get('smtp_starttls_25'),
                'starttls_587': latest.get('smtp_starttls_587')
            })

        # Sort by score (worst first)
        scored_domains.sort(key=lambda x: x['score'])

        return scored_domains[:limit]

    def certificate_adoption_report(self):
        """Generate SSL certificate adoption and health statistics"""
        logger.info("Generating certificate adoption report...")

        domains = self.db.get_all_domains(limit=100000)

        stats = {
            'total_domains': len(domains),
            'domains_with_ssl': 0,
            'by_port': {},
            'by_issuer': defaultdict(int),
            'expired': 0,
            'expiring_soon': 0,
            'certificate_changes': 0
        }

        # Initialize port stats
        for port in [443, 25, 587, 993, 995, 636]:
            stats['by_port'][port] = {
                'total': 0,
                'expired': 0,
                'expiring_soon': 0
            }

        for domain in domains:
            certs = self.db.get_latest_certificates(domain['domain_name'])

            if certs:
                stats['domains_with_ssl'] += 1

                for cert in certs:
                    port = cert.get('port')

                    if port in stats['by_port']:
                        stats['by_port'][port]['total'] += 1

                        if cert.get('is_expired'):
                            stats['by_port'][port]['expired'] += 1
                            stats['expired'] += 1

                        if cert.get('days_until_expiry') and 0 < cert['days_until_expiry'] < 30:
                            stats['by_port'][port]['expiring_soon'] += 1
                            stats['expiring_soon'] += 1

                    # Track issuers
                    issuer = cert.get('issuer_cn', 'Unknown')
                    stats['by_issuer'][issuer] += 1

        # Count certificate changes
        changes = self.db.get_certificate_changes(days=30)
        stats['certificate_changes'] = len(changes)

        # Convert defaultdict to regular dict for JSON serialization
        stats['by_issuer'] = dict(stats['by_issuer'])

        # Calculate percentages
        if stats['total_domains'] > 0:
            stats['percentages'] = {
                'ssl_adoption': (stats['domains_with_ssl'] / stats['total_domains']) * 100
            }

        # Top issuers
        top_issuers = sorted(stats['by_issuer'].items(), key=lambda x: x[1], reverse=True)
        stats['top_issuers'] = top_issuers[:10]

        return stats

    def certificate_expiry_timeline(self, days=90):
        """
        Get certificate expiration timeline for next N days.

        Returns dict with buckets: expired, 0-7 days, 8-30 days, 31-90 days
        """
        logger.info(f"Generating certificate expiry timeline for next {days} days...")

        domains = self.db.get_all_domains(limit=100000)

        timeline = {
            'expired': [],
            '0-7_days': [],
            '8-30_days': [],
            '31-90_days': []
        }

        for domain in domains:
            certs = self.db.get_latest_certificates(domain['domain_name'])

            for cert in certs:
                days_left = cert.get('days_until_expiry')

                if days_left is None:
                    continue

                cert_info = {
                    'domain': domain['domain_name'],
                    'port': cert.get('port'),
                    'subject': cert.get('subject_cn'),
                    'issuer': cert.get('issuer_cn'),
                    'days_until_expiry': days_left,
                    'not_after': cert.get('not_after')
                }

                if days_left < 0:
                    timeline['expired'].append(cert_info)
                elif 0 <= days_left <= 7:
                    timeline['0-7_days'].append(cert_info)
                elif 8 <= days_left <= 30:
                    timeline['8-30_days'].append(cert_info)
                elif 31 <= days_left <= 90:
                    timeline['31-90_days'].append(cert_info)

        return timeline

    def generate_report(self, output_file='report.json'):
        """Generate comprehensive analysis report"""
        logger.info("Generating comprehensive report...")

        report = {
            'generated_at': datetime.now().isoformat(),
            'adoption': self.security_adoption_report(),
            'drift': self.drift_analysis(),
            'vulnerable': self.top_vulnerable_domains(limit=50),
            'certificates': self.certificate_adoption_report(),
            'certificate_expiry': self.certificate_expiry_timeline()
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"✓ Report saved to {output_file}")
        return report

    def print_summary(self):
        """Print a summary to console"""
        stats = self.security_adoption_report()

        print("\n" + "=" * 70)
        print("📊 EMAIL SECURITY ADOPTION REPORT")
        print("=" * 70)

        print(f"\nDataset: {stats['scanned_domains']:,} domains")

        if 'percentages' in stats:
            pct = stats['percentages']
            print(f"\n🔒 Security Feature Adoption:")
            print(f"  DNSSEC Enabled:    {pct['dnssec_enabled']:6.2f}%  ({stats['dnssec']['enabled']:,} domains)")
            print(f"  DNSSEC Valid:      {pct['dnssec_valid']:6.2f}%  ({stats['dnssec']['valid']:,} domains)")
            print(f"  SPF Valid:         {pct['spf']:6.2f}%  ({stats['spf']['valid']:,} domains)")
            print(f"  DKIM Valid:        {pct['dkim']:6.2f}%  ({stats['dkim']['valid']:,} domains)")
            print(f"  MTA-STS:           {pct['mta_sts']:6.2f}%  ({stats['mta_sts']['enabled']:,} domains)")
            print(f"  STARTTLS (25):     {pct['starttls_25']:6.2f}%  ({stats['starttls']['port_25']:,} domains)")
            print(f"  STARTTLS (587):    {pct['starttls_587']:6.2f}%  ({stats['starttls']['port_587']:,} domains)")
            print(f"\n⭐ Full Compliance:  {pct['full_compliance']:6.2f}%  ({stats['full_compliance']:,} domains)")

        print("\n" + "=" * 70 + "\n")


def main():
    """CLI for analytics"""
    import argparse
    import os

    parser = argparse.ArgumentParser(description='Security Analytics Tool')

    parser.add_argument('command',
                       choices=['adoption', 'drift', 'vulnerable', 'report', 'summary',
                               'certificates', 'cert-expiry', 'cert-changes'],
                       help='Analysis command')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--postgres', action='store_true', help='Use PostgreSQL')
    parser.add_argument('--days', type=int, default=30, help='Days for time-based queries')

    args = parser.parse_args()

    # Select database
    if args.postgres or os.environ.get('DATABASE_URL'):
        from database_postgres import PostgresDatabase
        db = PostgresDatabase()
    else:
        from database import Database
        db = Database()

    analytics = Analytics(db)

    if args.command == 'adoption':
        stats = analytics.security_adoption_report()
        print(json.dumps(stats, indent=2))

    elif args.command == 'drift':
        drift = analytics.drift_analysis()
        print(json.dumps(drift, indent=2))

    elif args.command == 'vulnerable':
        vulnerable = analytics.top_vulnerable_domains()
        print(json.dumps(vulnerable, indent=2))

    elif args.command == 'report':
        output = args.output or 'report.json'
        analytics.generate_report(output_file=output)

    elif args.command == 'summary':
        analytics.print_summary()

    elif args.command == 'certificates':
        cert_stats = analytics.certificate_adoption_report()
        print(json.dumps(cert_stats, indent=2, default=str))

    elif args.command == 'cert-expiry':
        timeline = analytics.certificate_expiry_timeline(days=args.days)
        print(f"\n📅 Certificate Expiry Timeline (next {args.days} days)")
        print("=" * 70)
        print(f"Expired: {len(timeline['expired'])}")
        print(f"0-7 days: {len(timeline['0-7_days'])}")
        print(f"8-30 days: {len(timeline['8-30_days'])}")
        print(f"31-90 days: {len(timeline['31-90_days'])}")

        if timeline['0-7_days']:
            print(f"\n⚠️  URGENT - Expiring in 0-7 days:")
            for cert in timeline['0-7_days'][:10]:
                print(f"  {cert['domain']}:{cert['port']} - {cert['days_until_expiry']} days")

    elif args.command == 'cert-changes':
        changes = db.get_certificate_changes(days=args.days)
        print(f"\n🔄 Certificate Changes (last {args.days} days)")
        print("=" * 70)
        print(f"Total changes: {len(changes)}")

        for change in changes[:20]:
            print(f"\n{change['domain_name']}:{change['port']} - {change['change_timestamp']}")
            print(f"  Old: {change['old_subject']} ({change['old_issuer']})")
            print(f"  New: {change['new_subject']} ({change['new_issuer']})")


if __name__ == '__main__':
    main()
