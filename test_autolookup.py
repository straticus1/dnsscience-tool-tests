#!/usr/bin/env python3
"""
Test DNS Auto Lookup Deployment
Tests all API endpoints and main page
"""

import requests
import json
from datetime import datetime

BASE_URL = 'https://www.dnsscience.io'

def test_endpoint(endpoint, description):
    """Test a single API endpoint"""
    url = f"{BASE_URL}{endpoint}"
    print(f"\nTesting: {description}")
    print(f"URL: {url}")

    try:
        response = requests.get(url, timeout=10)
        print(f"Status: {response.status_code}")

        if response.status_code == 200:
            try:
                data = response.json()
                print(f"Response: {json.dumps(data, indent=2)}")
                return True
            except json.JSONDecodeError:
                print(f"Response (not JSON): {response.text[:200]}")
                return response.status_code == 200
        else:
            print(f"Error: {response.text[:200]}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {str(e)}")
        return False

def test_page(url, description):
    """Test that a page loads"""
    print(f"\nTesting: {description}")
    print(f"URL: {url}")

    try:
        response = requests.get(url, timeout=10)
        print(f"Status: {response.status_code}")

        if response.status_code == 200:
            # Check for key elements
            content = response.text
            if 'DNS Auto Lookup' in content:
                print("✓ Page contains 'DNS Auto Lookup'")
            if 'autolookup.css' in content:
                print("✓ CSS file linked")
            if 'autolookup.js' in content:
                print("✓ JavaScript file linked")

            return True
        else:
            print(f"Error: HTTP {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {str(e)}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("DNS Auto Lookup - Deployment Test Suite")
    print("=" * 60)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Base URL: {BASE_URL}")
    print("=" * 60)

    results = {}

    # Test main page
    print("\n" + "=" * 60)
    print("Testing Main Page")
    print("=" * 60)
    results['main_page'] = test_page(f"{BASE_URL}/autolookup", "DNS Auto Lookup Page")

    # Test API endpoints
    print("\n" + "=" * 60)
    print("Testing API Endpoints")
    print("=" * 60)

    results['api_ip'] = test_endpoint('/api/autolookup/ip', 'IP Detection API')
    results['api_resolver'] = test_endpoint('/api/autolookup/resolver', 'Resolver Detection API')
    results['api_edns'] = test_endpoint('/api/autolookup/edns', 'EDNS Detection API')
    results['api_security'] = test_endpoint('/api/autolookup/security', 'Security Assessment API')
    results['api_all'] = test_endpoint('/api/autolookup/all', 'Combined API')

    # Test static files
    print("\n" + "=" * 60)
    print("Testing Static Files")
    print("=" * 60)

    results['css'] = test_page(f"{BASE_URL}/static/css/autolookup.css", "CSS File")
    results['js'] = test_page(f"{BASE_URL}/static/js/autolookup.js", "JavaScript File")

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:10} - {test_name}")

    print("\n" + "=" * 60)
    print(f"Results: {passed}/{total} tests passed")
    print("=" * 60)

    if passed == total:
        print("\n✓ ALL TESTS PASSED - DNS Auto Lookup is fully functional!")
        print("\nAccess the tool at:")
        print(f"  {BASE_URL}/autolookup")
        return True
    else:
        print(f"\n⚠ {total - passed} test(s) failed - Please review errors above")
        return False

if __name__ == '__main__':
    import sys
    success = main()
    sys.exit(0 if success else 1)
