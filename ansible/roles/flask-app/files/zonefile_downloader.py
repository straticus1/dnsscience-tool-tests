#!/usr/bin/env python3
"""
Zone File Downloader - Access TLD zone files for internet-scale analysis

ICANN CZDS (Centralized Zone Data Service): https://czds.icann.org/
Requires registration and approval per TLD.

Free/Public Zone Files:
- Many ccTLDs provide free access
- Some gTLDs available with registration
- .com/.net require justification
"""
import os
import requests
import gzip
import logging
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ZoneFileDownloader:
    """Download and manage TLD zone files"""

    def __init__(self, output_dir="zonefiles"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # CZDS credentials (set via environment or config)
        self.czds_username = os.environ.get('CZDS_USERNAME')
        self.czds_password = os.environ.get('CZDS_PASSWORD')
        self.czds_token = None

    def authenticate_czds(self):
        """Authenticate with ICANN CZDS"""
        if not self.czds_username or not self.czds_password:
            logger.error("CZDS credentials not set. Set CZDS_USERNAME and CZDS_PASSWORD environment variables")
            return False

        logger.info("Authenticating with ICANN CZDS...")

        auth_url = "https://account-api.icann.org/api/authenticate"

        try:
            response = requests.post(
                auth_url,
                json={
                    'username': self.czds_username,
                    'password': self.czds_password
                },
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                self.czds_token = data.get('accessToken')
                logger.info("✓ CZDS authentication successful")
                return True
            else:
                logger.error(f"CZDS authentication failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"CZDS authentication error: {e}")
            return False

    def get_approved_zones(self):
        """Get list of TLDs you have access to via CZDS"""
        if not self.czds_token:
            if not self.authenticate_czds():
                return []

        logger.info("Fetching approved zone list from CZDS...")

        try:
            response = requests.get(
                "https://czds-api.icann.org/czds/downloads/links",
                headers={'Authorization': f'Bearer {self.czds_token}'},
                timeout=30
            )

            if response.status_code == 200:
                links = response.json()
                logger.info(f"✓ Access to {len(links)} zone files")
                return links
            else:
                logger.error(f"Failed to get zone list: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error fetching zone list: {e}")
            return []

    def download_czds_zone(self, zone_url, tld):
        """Download a zone file from CZDS"""
        if not self.czds_token:
            if not self.authenticate_czds():
                return None

        logger.info(f"Downloading {tld} zone file from CZDS...")

        output_file = self.output_dir / f"{tld}.zone.gz"

        try:
            response = requests.get(
                zone_url,
                headers={'Authorization': f'Bearer {self.czds_token}'},
                stream=True,
                timeout=300
            )

            if response.status_code == 200:
                with open(output_file, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                logger.info(f"✓ Downloaded {tld} to {output_file}")
                return output_file
            else:
                logger.error(f"Failed to download {tld}: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error downloading {tld}: {e}")
            return None

    def download_all_approved_zones(self):
        """Download all zone files you have access to"""
        zones = self.get_approved_zones()

        if not zones:
            logger.warning("No approved zones found. Apply at https://czds.icann.org/")
            return []

        downloaded = []

        for zone_url in zones:
            # Extract TLD from URL
            tld = zone_url.split('/')[-1].replace('.zone', '')

            result = self.download_czds_zone(zone_url, tld)
            if result:
                downloaded.append(result)

        logger.info(f"Downloaded {len(downloaded)}/{len(zones)} zone files")
        return downloaded

    def download_public_zone(self, tld, url):
        """Download a publicly available zone file"""
        logger.info(f"Downloading {tld} zone file from public source...")

        output_file = self.output_dir / f"{tld}.zone.gz"

        try:
            response = requests.get(url, stream=True, timeout=300)

            if response.status_code == 200:
                with open(output_file, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                logger.info(f"✓ Downloaded {tld} to {output_file}")
                return output_file
            else:
                logger.error(f"Failed to download {tld}: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error downloading {tld}: {e}")
            return None


class ZoneFileParser:
    """Parse zone files to extract domain names"""

    @staticmethod
    def parse_zone_file(zone_file_path, output_file=None, limit=None):
        """
        Parse a zone file and extract domain names.

        Args:
            zone_file_path: Path to zone file (.zone or .zone.gz)
            output_file: Optional output file for domain list
            limit: Optional limit on number of domains to extract

        Returns:
            List of domain names
        """
        logger.info(f"Parsing zone file: {zone_file_path}")

        domains = []
        count = 0

        try:
            # Handle gzip files
            if str(zone_file_path).endswith('.gz'):
                open_func = gzip.open
                mode = 'rt'
            else:
                open_func = open
                mode = 'r'

            with open_func(zone_file_path, mode) as f:
                for line in f:
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith(';'):
                        continue

                    # Parse zone file format
                    # Format: domain.tld IN NS nameserver
                    # We want just the domain part
                    parts = line.split()

                    if len(parts) >= 1:
                        domain = parts[0].lower()

                        # Remove trailing dot
                        if domain.endswith('.'):
                            domain = domain[:-1]

                        # Filter out invalid domains
                        if domain and '.' in domain:
                            domains.append(domain)
                            count += 1

                            if limit and count >= limit:
                                break

                            # Progress indicator
                            if count % 100000 == 0:
                                logger.info(f"Parsed {count:,} domains...")

            logger.info(f"✓ Extracted {len(domains):,} domains from {zone_file_path}")

            # Save to file if requested
            if output_file:
                with open(output_file, 'w') as f:
                    for domain in domains:
                        f.write(f"{domain}\n")
                logger.info(f"✓ Saved domain list to {output_file}")

            return domains

        except Exception as e:
            logger.error(f"Error parsing zone file: {e}")
            return []

    @staticmethod
    def parse_all_zones(zone_dir="zonefiles", output_file="all_domains.txt"):
        """Parse all zone files in a directory"""
        zone_dir = Path(zone_dir)

        all_domains = set()  # Use set to deduplicate

        for zone_file in zone_dir.glob("*.zone*"):
            logger.info(f"Processing {zone_file.name}...")

            domains = ZoneFileParser.parse_zone_file(zone_file)
            all_domains.update(domains)

            logger.info(f"Total unique domains: {len(all_domains):,}")

        # Save consolidated list
        logger.info(f"Saving {len(all_domains):,} unique domains to {output_file}")

        with open(output_file, 'w') as f:
            for domain in sorted(all_domains):
                f.write(f"{domain}\n")

        logger.info(f"✓ Complete! {len(all_domains):,} domains saved")
        return list(all_domains)


def main():
    """CLI for zone file operations"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Zone File Downloader - Access TLD zone files',
        epilog="""
SETUP:
1. Register at https://czds.icann.org/
2. Request access to TLDs you want to research
3. Set credentials:
   export CZDS_USERNAME="your_email"
   export CZDS_PASSWORD="your_password"

EXAMPLES:
  %(prog)s list
  %(prog)s download
  %(prog)s parse com.zone.gz
  %(prog)s parse-all
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Command')

    # List approved zones
    list_parser = subparsers.add_parser('list', help='List approved TLDs')

    # Download zones
    download_parser = subparsers.add_parser('download', help='Download zone files')
    download_parser.add_argument('--tld', help='Specific TLD to download')

    # Parse zone file
    parse_parser = subparsers.add_parser('parse', help='Parse a zone file')
    parse_parser.add_argument('zonefile', help='Zone file to parse')
    parse_parser.add_argument('-o', '--output', help='Output domain list file')
    parse_parser.add_argument('-l', '--limit', type=int, help='Limit number of domains')

    # Parse all zones
    parse_all_parser = subparsers.add_parser('parse-all', help='Parse all zone files')
    parse_all_parser.add_argument('-d', '--dir', default='zonefiles', help='Zone file directory')
    parse_all_parser.add_argument('-o', '--output', default='all_domains.txt', help='Output file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    downloader = ZoneFileDownloader()

    if args.command == 'list':
        zones = downloader.get_approved_zones()
        if zones:
            print(f"\nApproved TLDs ({len(zones)}):")
            print("=" * 50)
            for zone_url in zones:
                tld = zone_url.split('/')[-1].replace('.zone', '')
                print(f"  {tld}")
        else:
            print("\nNo approved zones. Apply at: https://czds.icann.org/")
            print("\nNote: .com and .net require strong justification")

    elif args.command == 'download':
        if args.tld:
            logger.info(f"Downloading {args.tld}...")
            # Would need to construct URL
        else:
            downloader.download_all_approved_zones()

    elif args.command == 'parse':
        ZoneFileParser.parse_zone_file(
            args.zonefile,
            output_file=args.output,
            limit=args.limit
        )

    elif args.command == 'parse-all':
        ZoneFileParser.parse_all_zones(
            zone_dir=args.dir,
            output_file=args.output
        )


if __name__ == '__main__':
    main()
