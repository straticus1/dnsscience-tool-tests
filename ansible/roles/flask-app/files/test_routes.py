#!/usr/bin/env python3
"""
Test script to diagnose Flask route registration issues.
This will help identify why valuation routes return 404.
"""

import sys
sys.path.insert(0, '/var/www/dnsscience')

# Test 1: Check if app can be imported
print("=" * 70)
print("TEST 1: Import Flask App")
print("=" * 70)
try:
    from app import app
    print("✓ App imported successfully")
except Exception as e:
    print(f"✗ Failed to import app: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 2: List all registered routes
print("\n" + "=" * 70)
print("TEST 2: List All Registered Routes")
print("=" * 70)
routes = []
for rule in app.url_map.iter_rules():
    routes.append({
        'endpoint': rule.endpoint,
        'methods': ','.join(sorted(rule.methods - {'HEAD', 'OPTIONS'})),
        'path': str(rule)
    })

# Sort by path
routes.sort(key=lambda x: x['path'])

# Print valuation routes specifically
valuation_routes = [r for r in routes if 'valuation' in r['path'].lower()]
print(f"\nValuation Routes Found: {len(valuation_routes)}")
for route in valuation_routes:
    print(f"  {route['methods']:8} {route['path']}")

# Print all API routes
print(f"\nAll API Routes ({len([r for r in routes if '/api/' in r['path']])} total):")
api_routes = [r for r in routes if '/api/' in r['path']]
for route in api_routes[:20]:  # First 20
    print(f"  {route['methods']:8} {route['path']}")
if len(api_routes) > 20:
    print(f"  ... and {len(api_routes) - 20} more")

# Test 3: Check specific valuation endpoints
print("\n" + "=" * 70)
print("TEST 3: Check Specific Valuation Endpoints")
print("=" * 70)

expected_routes = [
    '/api/domain/<domain>/valuation',
    '/api/valuations/top',
    '/api/domain/<domain>/valuation/history'
]

for expected in expected_routes:
    # Flask uses <domain> in route definition but stores as <domain:domain>
    found = any(expected.replace('<domain>', '<domain:domain>') in r['path'] or
                expected in r['path'] for r in routes)
    status = "✓ FOUND" if found else "✗ MISSING"
    print(f"  {status}: {expected}")

# Test 4: Check if valuation_engine is initialized
print("\n" + "=" * 70)
print("TEST 4: Check valuation_engine Initialization")
print("=" * 70)
try:
    from app import valuation_engine
    print(f"✓ valuation_engine initialized: {type(valuation_engine)}")

    # Try to call estimate_value to see if it works
    result = valuation_engine.estimate_value(
        domain_name='test.com',
        domain_age_years=5,
        scan_data={}
    )
    print(f"✓ estimate_value() works: {result.get('estimated_value_mid', 'N/A')}")
except Exception as e:
    print(f"✗ Error with valuation_engine: {e}")
    import traceback
    traceback.print_exc()

# Test 5: Check Database connection and methods
print("\n" + "=" * 70)
print("TEST 5: Check Database Valuation Methods")
print("=" * 70)
try:
    from app import db
    print(f"✓ Database imported: {type(db)}")

    # Check if methods exist
    methods = ['save_domain_valuation', 'get_latest_valuation',
               'get_valuation_history', 'get_top_valued_domains']
    for method in methods:
        if hasattr(db, method):
            print(f"  ✓ db.{method}() exists")
        else:
            print(f"  ✗ db.{method}() MISSING")
except Exception as e:
    print(f"✗ Error checking database: {e}")
    import traceback
    traceback.print_exc()

# Test 6: Make a test request using Flask test client
print("\n" + "=" * 70)
print("TEST 6: Test Request to Valuation Endpoint")
print("=" * 70)
try:
    with app.test_client() as client:
        # Try accessing the valuation endpoint
        response = client.get('/api/domain/google.com/valuation')
        print(f"  Status Code: {response.status_code}")
        print(f"  Content-Type: {response.content_type}")
        if response.status_code == 200:
            print(f"  ✓ SUCCESS: Route works!")
            print(f"  Response: {response.get_json()}")
        elif response.status_code == 404:
            print(f"  ✗ 404 NOT FOUND")
            print(f"  Response: {response.get_data(as_text=True)[:200]}")
        elif response.status_code == 500:
            print(f"  ✗ 500 SERVER ERROR")
            print(f"  Response: {response.get_json()}")
        else:
            print(f"  Response: {response.get_data(as_text=True)[:200]}")
except Exception as e:
    print(f"✗ Error making test request: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("DIAGNOSIS COMPLETE")
print("=" * 70)
