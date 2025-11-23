#!/usr/bin/env python3
"""
Direct test of OpenSRS integration to diagnose issues
"""
import sys
sys.path.insert(0, '/var/www/dnsscience')

try:
    print("=== OpenSRS Integration Direct Test ===")
    print("1. Importing modules...")
    from opensrs_integration import create_opensrs_client
    from config import Config
    print("   ✓ Imports successful")

    print("\n2. Checking credentials...")
    print(f"   Username: {Config.OPENSRS_USERNAME}")
    print(f"   API Key: {Config.OPENSRS_API_KEY[:20]}..." if Config.OPENSRS_API_KEY else "   API Key: None")
    print(f"   Environment: {Config.OPENSRS_ENVIRONMENT}")

    if not Config.OPENSRS_USERNAME or not Config.OPENSRS_API_KEY:
        print("   ✗ FAIL: Credentials not configured")
        sys.exit(1)
    print("   ✓ Credentials configured")

    print("\n3. Creating OpenSRS client...")
    client, domain_mgr, ssl_mgr, dns_mgr = create_opensrs_client(
        Config.OPENSRS_USERNAME,
        Config.OPENSRS_API_KEY,
        Config.OPENSRS_ENVIRONMENT
    )
    print("   ✓ Client created successfully")

    print("\n4. Testing domain availability check...")
    test_domains = ['example999777.com', 'testdomain123456.com']
    print(f"   Checking: {test_domains}")

    results = domain_mgr.check_availability(test_domains)
    print(f"   ✓ Got {len(results)} results")

    print("\n5. Results:")
    for result in results:
        print(f"   - {result.domain}: {'Available' if result.available else 'Unavailable'}")
        if result.error:
            print(f"     Error: {result.error}")
        if result.is_premium:
            print(f"     Premium: ${result.premium_price}")
        elif result.standard_price:
            print(f"     Price: ${result.standard_price}")

    print("\n=== TEST PASSED ===")
    sys.exit(0)

except Exception as e:
    print(f"\n✗ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
