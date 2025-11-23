#!/usr/bin/env python3
"""Test OpenSRS domain lookup directly"""

import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from opensrs_integration import create_opensrs_client
from config import Config

# Create OpenSRS client
print("Creating OpenSRS client...")
print(f"Username: {Config.OPENSRS_USERNAME}")
print(f"Environment: {Config.OPENSRS_ENVIRONMENT}")
print()

client, domain_mgr, ssl_mgr, dns_mgr = create_opensrs_client(
    Config.OPENSRS_USERNAME,
    Config.OPENSRS_API_KEY,
    Config.OPENSRS_ENVIRONMENT
)

# Test domains
test_domains = [
    "ramstanis.com",  # Known registered
    "google.com",     # Known registered
    "thisdefinitelyshouldbeavailable987654321.com"  # Likely available
]

print("Checking domain availability via OpenSRS...\n")

for domain in test_domains:
    print(f"{'='*60}")
    print(f"Domain: {domain}")
    print('='*60)

    results = domain_mgr.check_availability([domain])

    if results and len(results) > 0:
        result = results[0]
        print(f"  Available: {result.available}")
        print(f"  Is Premium: {result.is_premium}")
        if result.error:
            print(f"  Error: {result.error}")

        # Determine if correct
        if domain in ["ramstanis.com", "google.com"]:
            expected_available = False
            if result.available == expected_available:
                print(f"  ✅ CORRECT: Should be TAKEN")
            else:
                print(f"  ❌ BUG: Should be TAKEN but showing as AVAILABLE")
        else:
            print(f"  ℹ️  Check manually if this is correct")
    else:
        print("  ❌ No results returned")

    print()
