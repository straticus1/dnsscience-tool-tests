#!/usr/bin/env python3
"""Test domain search API endpoint"""

import requests
import json

# Test the domain search endpoint
url = "https://www.dnsscience.io/api/domains/search/public"

payload = {
    "domains": ["ramstanis.com"]
}

headers = {
    "Content-Type": "application/json"
}

print("Testing domain search for ramstanis.com...")
print(f"POST {url}")
print(f"Payload: {json.dumps(payload, indent=2)}")
print()

try:
    response = requests.post(url, json=payload, headers=headers, timeout=30)

    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    print()

    if response.ok:
        data = response.json()
        print("Response JSON:")
        print(json.dumps(data, indent=2))
        print()

        if 'results' in data and len(data['results']) > 0:
            result = data['results'][0]
            print(f"Domain: {result['domain']}")
            print(f"Available: {result['available']}")
            print(f"Price: ${result.get('price', 'N/A')}")
            print()

            if result['available']:
                print("❌ BUG CONFIRMED: ramstanis.com is shown as AVAILABLE but it's actually REGISTERED")
            else:
                print("✅ CORRECT: ramstanis.com is shown as TAKEN (registered)")
    else:
        print(f"Error Response: {response.text}")

except Exception as e:
    print(f"Request failed: {e}")
