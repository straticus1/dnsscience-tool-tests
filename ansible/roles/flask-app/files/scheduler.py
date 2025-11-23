#!/usr/bin/env python3
"""Scheduled scanner for tracking domain security drift over time"""
import time
import schedule
import logging
from datetime import datetime
from database import Database
from checkers import DomainScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)

class ScheduledScanner:
    """Automated scanner that runs on schedule"""

    def __init__(self, scan_interval_hours=24, batch_size=100, delay=2):
        self.db = Database()
        self.scanner = DomainScanner()
        self.scan_interval_hours = scan_interval_hours
        self.batch_size = batch_size
        self.delay = delay
        self.is_running = False

    def scan_all_domains(self):
        """Scan all tracked domains"""
        if self.is_running:
            logging.warning("Scan already in progress, skipping...")
            return

        self.is_running = True
        logging.info("Starting scheduled scan of all domains")

        try:
            domains = self.db.get_all_domains(limit=10000)
            total = len(domains)
            logging.info(f"Found {total} domains to scan")

            scanned = 0
            failed = 0

            for domain in domains:
                domain_name = domain['domain_name']

                try:
                    logging.info(f"Scanning {domain_name} ({scanned + 1}/{total})")
                    result = self.scanner.scan_domain(domain_name)
                    self.db.save_scan_result(domain_name, result)

                    if result['scan_status'] == 'completed':
                        scanned += 1
                    else:
                        failed += 1
                        logging.warning(f"Scan failed for {domain_name}: {result.get('error_message')}")

                    # Rate limiting
                    time.sleep(self.delay)

                except Exception as e:
                    failed += 1
                    logging.error(f"Error scanning {domain_name}: {e}")

            logging.info(f"Scan completed: {scanned} succeeded, {failed} failed")

        except Exception as e:
            logging.error(f"Scheduled scan error: {e}")

        finally:
            self.is_running = False

    def check_for_drift(self):
        """Check for security drift in recently scanned domains"""
        logging.info("Checking for security drift...")

        try:
            domains = self.db.get_all_domains(limit=10000)

            for domain in domains:
                domain_name = domain['domain_name']
                history = self.db.get_scan_history(domain_name, limit=2)

                if len(history) < 2:
                    continue

                # Compare last two scans
                latest = history[0]
                previous = history[1]

                changes = []

                # Check for changes
                fields = [
                    ('dnssec_enabled', 'DNSSEC'),
                    ('spf_valid', 'SPF'),
                    ('dkim_valid', 'DKIM'),
                    ('mta_sts_enabled', 'MTA-STS'),
                    ('smtp_starttls_25', 'STARTTLS-25'),
                    ('smtp_starttls_587', 'STARTTLS-587')
                ]

                for field, label in fields:
                    if latest.get(field) != previous.get(field):
                        changes.append(f"{label}: {previous.get(field)} → {latest.get(field)}")

                if changes:
                    logging.warning(f"DRIFT DETECTED for {domain_name}:")
                    for change in changes:
                        logging.warning(f"  - {change}")

        except Exception as e:
            logging.error(f"Drift check error: {e}")

    def start(self):
        """Start the scheduled scanner"""
        logging.info(f"Starting scheduler (scan every {self.scan_interval_hours} hours)")

        # Schedule tasks
        schedule.every(self.scan_interval_hours).hours.do(self.scan_all_domains)
        schedule.every(self.scan_interval_hours).hours.do(self.check_for_drift)

        # Run initial scan
        logging.info("Running initial scan...")
        self.scan_all_domains()
        self.check_for_drift()

        # Keep running
        logging.info("Scheduler started. Press Ctrl+C to stop.")

        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute

        except KeyboardInterrupt:
            logging.info("Scheduler stopped by user")

def main():
    """Run the scheduled scanner"""
    import argparse

    parser = argparse.ArgumentParser(description='DNS Science Tracker - Scheduled Scanner')
    parser.add_argument('-i', '--interval', type=int, default=24,
                       help='Scan interval in hours (default: 24)')
    parser.add_argument('-d', '--delay', type=int, default=2,
                       help='Delay between domain scans in seconds (default: 2)')
    parser.add_argument('-b', '--batch-size', type=int, default=100,
                       help='Batch size for scanning (default: 100)')

    args = parser.parse_args()

    scanner = ScheduledScanner(
        scan_interval_hours=args.interval,
        batch_size=args.batch_size,
        delay=args.delay
    )

    scanner.start()

if __name__ == '__main__':
    main()
