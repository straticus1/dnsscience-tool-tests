#!/usr/bin/env python3
"""Test the registrar page search functionality"""

import requests
import json

print("Testing registrar page domain search...\n")

# Test multiple domains
test_domains = [
    ["ramstanis.com"],
    ["google.com"],
    ["thisshouldbeavaialble12345.com"]
]

for domains in test_domains:
    print(f"Testing: {domains[0]}")
    print("=" * 60)

    response = requests.post(
        "https://www.dnsscience.io/api/domains/search/public",
        json={"domains": domains},
        headers={"Content-Type": "application/json"},
        timeout=30
    )

    print(f"Status: {response.status_code}")

    if response.status_code == 200:
        data = response.json()
        if 'results' in data and len(data['results']) > 0:
            result = data['results'][0]
            print(f"Domain: {result['domain']}")
            print(f"Available: {result['available']}")
            print(f"Price: ${result.get('price', 'N/A')}")
            print(f"Mode: {'RDAP/WHOIS' if data.get('whois_mode') else 'OpenSRS'}")

            # Check correctness
            if domains[0] in ["ramstanis.com", "google.com"]:
                if result['available']:
                    print("❌ WRONG - Should be taken")
                else:
                    print("✅ CORRECT - Showing as taken")
            else:
                if result['available']:
                    print("✅ CORRECT - Showing as available")
                else:
                    print("⚠️  May be wrong - check manually")
        else:
            print("❌ No results returned")
            print(json.dumps(data, indent=2))
    else:
        print(f"❌ Error: {response.status_code}")
        print(response.text[:500])

    print()
