#!/usr/bin/env python3
"""
Scan Worker Daemon - Background worker for processing async scan jobs

This daemon continuously processes scan jobs from the Redis queue.
Run this as a systemd service or in a separate process.
"""

import sys
import os

# Add the application directory to Python path
sys.path.insert(0, '/var/www/dnsscience')

from async_scanner import AsyncScanWorker

def main():
    """Run the scan worker"""
    print("=" * 80)
    print("DNS SCIENCE - ASYNC SCAN WORKER")
    print("=" * 80)
    print()

    worker = AsyncScanWorker()
    worker.run_worker()

if __name__ == '__main__':
    main()
