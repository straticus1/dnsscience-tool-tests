#!/usr/bin/env python3
"""
Data Ingestion Monitor
Monitors the progress of data ingestion daemons and prints statistics
"""
import psycopg2
import time
from datetime import datetime
import os
import sys

# Add parent directory to path to import database module
sys.path.insert(0, '/var/www/dnsscience')

class IngestionMonitor:
    def __init__(self):
        # Load environment variables - NO DEFAULTS for credentials
        self.db_config = {
            'host': os.getenv('DB_HOST'),
            'port': int(os.getenv('DB_PORT', '5432')),
            'database': os.getenv('DB_NAME', 'dnsscience'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASS')
        }

        # Validate required credentials
        if not self.db_config['host']:
            raise ValueError("DB_HOST environment variable is required")
        if not self.db_config['user']:
            raise ValueError("DB_USER environment variable is required")
        if not self.db_config['password']:
            raise ValueError("DB_PASS environment variable is required")

        self.last_stats = None
        
    def get_connection(self):
        """Get database connection"""
        return psycopg2.connect(**self.db_config)
    
    def get_current_stats(self):
        """Get current database statistics"""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                stats = {}
                
                # Total domains scanned
                cur.execute("SELECT COUNT(DISTINCT domain_name) FROM domains")
                stats['total_domains'] = cur.fetchone()[0] or 0
                
                # Total scan records
                cur.execute("SELECT COUNT(*) FROM dns_scans")
                stats['total_scans'] = cur.fetchone()[0] or 0
                
                # SSL certificates
                cur.execute("SELECT COUNT(*) FROM ssl_certificates")
                stats['ssl_certificates'] = cur.fetchone()[0] or 0
                
                # DNS records (estimate from scans with dns_records)
                cur.execute("SELECT COUNT(*) FROM dns_scans WHERE dns_records IS NOT NULL")
                stats['dns_data_records'] = cur.fetchone()[0] or 0
                
                # Email security records
                cur.execute("""
                    SELECT COUNT(*) FROM dns_scans 
                    WHERE spf_record IS NOT NULL 
                       OR dkim_valid IS NOT NULL 
                       OR dmarc_record IS NOT NULL
                """)
                stats['email_security_records'] = cur.fetchone()[0] or 0
                
                # DNSSEC records
                cur.execute("SELECT COUNT(*) FROM dns_scans WHERE dnssec_enabled = TRUE")
                stats['dnssec_records'] = cur.fetchone()[0] or 0
                
                # Recent activity (last hour)
                cur.execute("""
                    SELECT COUNT(*) FROM dns_scans 
                    WHERE scan_timestamp > NOW() - INTERVAL '1 hour'
                """)
                stats['scans_last_hour'] = cur.fetchone()[0] or 0
                
                # Recent domains (last hour)
                cur.execute("""
                    SELECT COUNT(DISTINCT domain_name) FROM dns_scans 
                    WHERE scan_timestamp > NOW() - INTERVAL '1 hour'
                """)
                stats['domains_last_hour'] = cur.fetchone()[0] or 0
                
                stats['timestamp'] = datetime.now()
                
                return stats
                
        finally:
            conn.close()
    
    def calculate_delta(self, current_stats):
        """Calculate change since last check"""
        if self.last_stats is None:
            return None
            
        delta = {}
        for key in current_stats:
            if key == 'timestamp':
                continue
            if isinstance(current_stats[key], (int, float)):
                delta[key] = current_stats[key] - self.last_stats.get(key, 0)
        
        time_diff = (current_stats['timestamp'] - self.last_stats['timestamp']).total_seconds()
        delta['time_seconds'] = time_diff
        
        return delta
    
    def print_stats(self, stats, delta=None):
        """Print statistics in a nice format"""
        timestamp = stats['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        print("\n" + "="*80)
        print(f"DNS Science Data Ingestion Monitor - {timestamp}")
        print("="*80)
        
        print("\n📊 CUMULATIVE STATISTICS:")
        print(f"  Total Domains Scanned:        {stats['total_domains']:,}")
        print(f"  Total Scan Records:           {stats['total_scans']:,}")
        print(f"  SSL Certificates:             {stats['ssl_certificates']:,}")
        print(f"  DNS Data Records:             {stats['dns_data_records']:,}")
        print(f"  Email Security Records:       {stats['email_security_records']:,}")
        print(f"  DNSSEC Records:               {stats['dnssec_records']:,}")
        
        print("\n🕐 RECENT ACTIVITY (Last Hour):")
        print(f"  Scans Completed:              {stats['scans_last_hour']:,}")
        print(f"  Domains Scanned:              {stats['domains_last_hour']:,}")
        
        if delta:
            print(f"\n📈 CHANGES (Last {int(delta['time_seconds'])} seconds):")
            print(f"  New Domains:                  +{delta.get('total_domains', 0):,}")
            print(f"  New Scans:                    +{delta.get('total_scans', 0):,}")
            print(f"  New SSL Certificates:         +{delta.get('ssl_certificates', 0):,}")
            print(f"  New DNS Records:              +{delta.get('dns_data_records', 0):,}")
            print(f"  New Email Security Records:   +{delta.get('email_security_records', 0):,}")
            
            # Calculate rate
            if delta['time_seconds'] > 0:
                scans_per_min = (delta.get('total_scans', 0) / delta['time_seconds']) * 60
                print(f"\n⚡ INGESTION RATE:")
                print(f"  Scans per minute:             {scans_per_min:.2f}")
        
        print("\n" + "="*80 + "\n")
    
    def monitor(self, interval_seconds=300):
        """
        Monitor data ingestion continuously
        
        Args:
            interval_seconds: How often to check (default: 300 = 5 minutes)
        """
        print(f"🚀 Starting Data Ingestion Monitor")
        print(f"📡 Checking every {interval_seconds} seconds")
        print(f"🛑 Press Ctrl+C to stop\n")
        
        try:
            while True:
                try:
                    stats = self.get_current_stats()
                    delta = self.calculate_delta(stats)
                    self.print_stats(stats, delta)
                    self.last_stats = stats
                    
                except psycopg2.Error as e:
                    print(f"❌ Database error: {e}")
                    print("   Retrying in 30 seconds...")
                    time.sleep(30)
                    continue
                except Exception as e:
                    print(f"❌ Unexpected error: {e}")
                    import traceback
                    traceback.print_exc()
                
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Monitor stopped by user")
            print("📊 Final Statistics:")
            if self.last_stats:
                self.print_stats(self.last_stats)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Monitor DNS Science data ingestion')
    parser.add_argument(
        '--interval',
        type=int,
        default=300,
        help='Check interval in seconds (default: 300)'
    )
    parser.add_argument(
        '--once',
        action='store_true',
        help='Run once and exit (do not loop)'
    )
    
    args = parser.parse_args()
    
    monitor = IngestionMonitor()
    
    if args.once:
        stats = monitor.get_current_stats()
        monitor.print_stats(stats)
    else:
        monitor.monitor(interval_seconds=args.interval)


if __name__ == '__main__':
    main()
