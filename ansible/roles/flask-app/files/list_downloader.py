#!/usr/bin/env python3
"""Download and import public domain lists"""
import requests
import gzip
import zipfile
import io
import os
from database import Database

DOMAIN_LISTS = {
    'tranco-1k': {
        'url': 'https://tranco-list.eu/download/M89ZW/1000',
        'description': 'Tranco Top 1000 domains',
        'format': 'csv'  # rank,domain
    },
    'tranco-10k': {
        'url': 'https://tranco-list.eu/download/M89ZW/10000',
        'description': 'Tranco Top 10K domains',
        'format': 'csv'
    },
    'cisco-umbrella-1m': {
        'url': 'http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
        'description': 'Cisco Umbrella Top 1M domains',
        'format': 'zip-csv'
    }
}

def download_list(list_name, output_file=None):
    """Download a domain list"""
    if list_name not in DOMAIN_LISTS:
        print(f"Unknown list: {list_name}")
        print(f"Available lists: {', '.join(DOMAIN_LISTS.keys())}")
        return None

    list_info = DOMAIN_LISTS[list_name]
    print(f"Downloading {list_info['description']}...")
    print(f"URL: {list_info['url']}")

    try:
        response = requests.get(list_info['url'], timeout=60)
        response.raise_for_status()

        domains = []

        if list_info['format'] == 'csv':
            # Parse CSV format (rank,domain)
            lines = response.text.strip().split('\n')
            for line in lines:
                parts = line.split(',')
                if len(parts) >= 2:
                    domain = parts[1].strip()
                    domains.append(domain)

        elif list_info['format'] == 'zip-csv':
            # Extract ZIP and parse CSV
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                for filename in z.namelist():
                    if filename.endswith('.csv'):
                        with z.open(filename) as f:
                            lines = f.read().decode('utf-8').strip().split('\n')
                            for line in lines:
                                parts = line.split(',')
                                if len(parts) >= 2:
                                    domain = parts[1].strip()
                                    domains.append(domain)

        print(f"Downloaded {len(domains)} domains")

        # Save to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                for domain in domains:
                    f.write(f"{domain}\n")
            print(f"Saved to {output_file}")

        return domains

    except requests.RequestException as e:
        print(f"Error downloading list: {e}")
        return None

def import_list(list_name, db=None):
    """Download and import a domain list to database"""
    if db is None:
        db = Database()

    domains = download_list(list_name)

    if not domains:
        return 0

    print(f"Importing {len(domains)} domains to database...")

    imported = 0
    for domain in domains:
        try:
            db.add_domain(domain)
            imported += 1
        except Exception as e:
            print(f"Error importing {domain}: {e}")

    print(f"Imported {imported} domains")
    return imported

def main():
    """CLI for list downloader"""
    import argparse

    parser = argparse.ArgumentParser(description='DNS Science - Domain List Downloader')

    subparsers = parser.add_subparsers(dest='command', help='Command')

    # List available lists
    list_parser = subparsers.add_parser('list', help='List available domain lists')

    # Download command
    download_parser = subparsers.add_parser('download', help='Download a domain list')
    download_parser.add_argument('list_name', help='Name of list to download')
    download_parser.add_argument('-o', '--output', help='Output file path')

    # Import command
    import_parser = subparsers.add_parser('import', help='Download and import to database')
    import_parser.add_argument('list_name', help='Name of list to import')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == 'list':
        print("\nAvailable domain lists:")
        print("=" * 70)
        for name, info in DOMAIN_LISTS.items():
            print(f"  {name:20s} - {info['description']}")
        print()

    elif args.command == 'download':
        download_list(args.list_name, output_file=args.output)

    elif args.command == 'import':
        import_list(args.list_name)

if __name__ == '__main__':
    main()
