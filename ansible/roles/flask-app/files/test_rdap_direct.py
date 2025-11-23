#!/usr/bin/env python3
"""Test RDAP lookup directly to understand the issue"""

import requests
import json

domains_to_test = [
    "ramstanis.com",  # Known registered domain
    "google.com",     # Known registered domain
    "thisdefinitelyshouldbeavailable123456789.com"  # Likely available
]

for domain in domains_to_test:
    print(f"\n{'='*60}")
    print(f"Testing: {domain}")
    print('='*60)

    tld = domain.split('.')[-1]
    rdap_url = f"https://rdap.verisign.com/{tld}/v1/domain/{domain}"

    print(f"RDAP URL: {rdap_url}")

    try:
        response = requests.get(rdap_url, timeout=10, headers={'Accept': 'application/json'})

        print(f"Status Code: {response.status_code}")

        if response.status_code == 404:
            print("✅ Domain NOT FOUND in registry = AVAILABLE")
            available = True
        elif response.status_code == 200:
            print("✅ Domain FOUND in registry = TAKEN/REGISTERED")
            available = False

            # Parse JSON to show status
            try:
                data = response.json()
                status = data.get('status', [])
                print(f"  Status flags: {status}")
                print(f"  LDH Name: {data.get('ldhName', 'N/A')}")
            except:
                pass
        else:
            print(f"⚠️  Unexpected status code: {response.status_code}")
            available = None

        print(f"\nConclusion: available = {available}")

    except Exception as e:
        print(f"❌ Request failed: {e}")
