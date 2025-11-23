#!/usr/bin/env python3
"""
Integration Script for Domain Marketplace & Acquisition Service

This script helps integrate the new features into the existing app.py
by providing code snippets and validation.
"""

import os
import sys

def check_file_exists(filepath):
    """Check if a file exists"""
    exists = os.path.exists(filepath)
    status = "✅" if exists else "❌"
    print(f"{status} {filepath}")
    return exists

def main():
    print("=" * 60)
    print("DOMAIN MARKETPLACE & ACQUISITION - INTEGRATION CHECK")
    print("=" * 60)
    print()

    # Check required files
    print("📁 Checking Required Files:\n")

    files_to_check = [
        "domain_acquisition_api.py",
        "domain_marketplace_api.py",
        "sql-files/migrations/013_domain_acquisition_and_marketplace.sql",
        "templates/marketplace/browse.html",
        "DOMAIN_MARKETPLACE_DEPLOYMENT.md"
    ]

    all_files_exist = True
    for filepath in files_to_check:
        if not check_file_exists(filepath):
            all_files_exist = False

    print()

    if not all_files_exist:
        print("❌ ERROR: Some required files are missing!")
        print("Please ensure all files are in place before integrating.")
        sys.exit(1)

    print("✅ All required files present!\n")

    # Display integration instructions
    print("=" * 60)
    print("INTEGRATION STEPS")
    print("=" * 60)
    print()

    print("Step 1: Add Blueprint Imports to app.py")
    print("-" * 60)
    print("""
Add these imports near the top of app.py (after other imports):

```python
from domain_acquisition_api import acquisition_bp
from domain_marketplace_api import marketplace_bp
```
""")

    print("\nStep 2: Register Blueprints")
    print("-" * 60)
    print("""
Add after other app initializations (around line 50):

```python
# Register marketplace and acquisition blueprints
app.register_blueprint(acquisition_bp)
app.register_blueprint(marketplace_bp)
```
""")

    print("\nStep 3: Add Page Routes")
    print("-" * 60)
    print("""
Add these routes to app.py (with other @app.route definitions):

```python
@app.route('/marketplace')
def marketplace_page():
    '''Domain marketplace homepage'''
    return render_template('marketplace/browse.html')

@app.route('/marketplace/listing/<int:listing_id>')
def marketplace_listing_detail(listing_id):
    '''Individual listing detail page'''
    return render_template('marketplace/listing_detail.html', listing_id=listing_id)

@app.route('/acquisition')
def acquisition_page():
    '''Domain acquisition service page'''
    return render_template('acquisition/request.html')

@app.route('/acquisition/success')
def acquisition_success():
    '''Acquisition payment success page'''
    return render_template('acquisition/success.html')

@app.route('/marketplace/purchase/success')
def marketplace_purchase_success():
    '''Marketplace purchase success page'''
    return render_template('marketplace/purchase_success.html')
```
""")

    print("\nStep 4: Database Migration")
    print("-" * 60)
    print("""
Run the database migration:

```bash
psql -h $DB_HOST -U $DB_USER -d dnsscience < sql-files/migrations/013_domain_acquisition_and_marketplace.sql
```

Or use pgAdmin/DBeaver to execute the migration file.
""")

    print("\nStep 5: Environment Variables")
    print("-" * 60)
    print("""
Add to .env.production:

```bash
# Stripe Webhook Secrets (get from Stripe Dashboard)
STRIPE_ACQUISITION_WEBHOOK_SECRET=whsec_...
STRIPE_MARKETPLACE_WEBHOOK_SECRET=whsec_...
```
""")

    print("\nStep 6: Configure Stripe Webhooks")
    print("-" * 60)
    print("""
In Stripe Dashboard > Developers > Webhooks:

1. Add endpoint: https://www.dnsscience.io/api/acquisition/webhook
   Events: checkout.session.completed, payment_intent.succeeded

2. Add endpoint: https://www.dnsscience.io/api/marketplace/webhook
   Events: checkout.session.completed, payment_intent.succeeded, payout.paid

Copy webhook secrets to .env.production
""")

    print("\nStep 7: Test Locally")
    print("-" * 60)
    print("""
```bash
# Start Flask app
python app.py

# Test marketplace
curl http://localhost:5000/api/marketplace/browse

# Open in browser
open http://localhost:5000/marketplace
```
""")

    print("\nStep 8: Deploy to Production")
    print("-" * 60)
    print("""
```bash
# Upload files
scp domain_acquisition_api.py user@server:/var/www/dnsscience/
scp domain_marketplace_api.py user@server:/var/www/dnsscience/
scp -r templates/marketplace/ user@server:/var/www/dnsscience/templates/

# Apply database migration
ssh user@server
cd /var/www/dnsscience
psql -h $DB_HOST -U $DB_USER -d dnsscience < sql-files/migrations/013_domain_acquisition_and_marketplace.sql

# Restart Apache
sudo systemctl restart apache2
```
""")

    print("\n" + "=" * 60)
    print("NEXT STEPS")
    print("=" * 60)
    print()
    print("1. Review DOMAIN_MARKETPLACE_DEPLOYMENT.md for full details")
    print("2. Follow integration steps above")
    print("3. Test locally before deploying to production")
    print("4. Set up Stripe webhooks")
    print("5. Monitor logs after deployment")
    print()
    print("For issues, check the troubleshooting section in:")
    print("DOMAIN_MARKETPLACE_DEPLOYMENT.md")
    print()

    # Check if app.py exists and show quick diff
    if os.path.exists('app.py'):
        print("\n" + "=" * 60)
        print("QUICK CHECK: Does app.py already have the blueprints?")
        print("=" * 60)

        with open('app.py', 'r') as f:
            content = f.read()

        has_acquisition = 'acquisition_bp' in content
        has_marketplace = 'marketplace_bp' in content

        if has_acquisition and has_marketplace:
            print("✅ Blueprints already registered in app.py!")
        elif has_acquisition or has_marketplace:
            print("⚠️  Partial integration detected")
            print(f"   acquisition_bp: {'✅' if has_acquisition else '❌'}")
            print(f"   marketplace_bp: {'✅' if has_marketplace else '❌'}")
        else:
            print("❌ Blueprints NOT YET integrated into app.py")
            print("   Follow Step 1-3 above to integrate")

    print()
    print("✅ Integration check complete!")
    print()

if __name__ == '__main__':
    main()
