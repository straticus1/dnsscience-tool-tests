"""
Script to integrate authentication system into app.py
This adds all necessary imports, initializations, and endpoints
"""

import re

def integrate_auth_into_app(app_py_path):
    """Add authentication system to app.py"""
    
    with open(app_py_path, 'r') as f:
        content = f.read()
    
    # 1. Add imports after existing imports (after line with "from certificate_tools import")
    new_imports = '''from auth import UserAuth, PasswordHasher, login_required, optional_auth
from api_key_manager import APIKeyManager
from flask import g
import time'''
    
    # Find the certificate_tools import block and add after it
    content = content.replace(
        'from certificate_tools import (',
        new_imports + '\n\nfrom certificate_tools import ('
    )
    
    # 2. Initialize auth after db initialization
    auth_init = '''
# Initialize authentication system
user_auth = UserAuth(db)
api_key_manager = APIKeyManager(db)
'''
    
    # Add after "db = Database()"
    content = content.replace(
        'db = Database()\n',
        'db = Database()\n' + auth_init
    )
    
    # 3. Add before_request handler after the db initialization section
    before_request_handler = '''

@app.before_request
def load_auth():
    """Make auth available in Flask g for all requests"""
    g.auth = user_auth
    g.api_key_manager = api_key_manager
'''
    
    # Add before the first @app.route
    first_route_match = re.search(r'@app\.route\(', content)
    if first_route_match:
        insert_pos = first_route_match.start()
        content = content[:insert_pos] + before_request_handler + '\n\n' + content[insert_pos:]
    
    # 4. Update the scan endpoint to support authenticated users
    # Find and replace the scan_domain function
    old_scan = '''    try:
        # Track scan status in session
        if 'scan_status' not in session:
            session['scan_status'] = {}
        session['scan_status'][domain] = 'scanning'
        session.modified = True

        # Perform synchronous scan
        scan_result = scanner.scan_domain(domain, check_ssl=check_ssl)

        # Save to database
        db.save_scan_result(domain, scan_result)

        # Save SSL certificates if present
        if 'ssl_certificates' in scan_result and scan_result['ssl_certificates']:
            db.save_certificates_batch(domain, scan_result['ssl_certificates'])

        # Track user's scan in session
        if 'my_scans' not in session:
            session['my_scans'] = []
        if domain not in session['my_scans']:
            session['my_scans'].append(domain)

        # Update scan status to completed
        session['scan_status'][domain] = 'completed'
        session.modified = True

        return jsonify(scan_result)
    except Exception as e:
        # Mark scan as failed in session
        if 'scan_status' not in session:
            session['scan_status'] = {}
        session['scan_status'][domain] = 'failed'
        session.modified = True
        return jsonify({'error': str(e), 'domain': domain}), 500'''
    
    new_scan = '''    # Check authentication and rate limits
    user_id = session.get('user_id')
    api_key_id = None
    
    # Check API key authentication
    api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
    if api_key:
        user_id, api_key_id, auth_error = user_auth.verify_api_key(api_key)
        if auth_error:
            return jsonify({'error': auth_error}), 401
    
    # Check rate limits
    allowed, remaining, limit_type = user_auth.check_rate_limit(user_id)
    if not allowed:
        return jsonify({
            'error': 'Rate limit exceeded',
            'limit_type': limit_type,
            'scans_remaining': remaining,
            'upgrade_url': '/pricing' if not user_id else '/account/upgrade'
        }), 429
    
    try:
        # Track scan status in session
        if 'scan_status' not in session:
            session['scan_status'] = {}
        session['scan_status'][domain] = 'scanning'
        session.modified = True

        # Record scan start time
        scan_start = time.time()

        # Perform synchronous scan
        scan_result = scanner.scan_domain(domain, check_ssl=check_ssl)

        # Calculate scan duration
        scan_duration_ms = int((time.time() - scan_start) * 1000)

        # Save to database
        db.save_scan_result(domain, scan_result)

        # Get domain_id for tracking
        domain_id = db.get_domain_id(domain)

        # Save SSL certificates if present
        if 'ssl_certificates' in scan_result and scan_result['ssl_certificates']:
            db.save_certificates_batch(domain, scan_result['ssl_certificates'])

        # Record scan for user (authenticated or anonymous)
        try:
            user_auth.record_scan(
                user_id=user_id,
                domain_id=domain_id,
                scan_duration_ms=scan_duration_ms,
                scan_source='api' if api_key_id else 'web',
                api_key_id=api_key_id
            )
        except Exception as e:
            # Don't fail the scan if tracking fails
            print(f"Warning: Failed to record scan: {e}")

        # Track user's scan in session (for anonymous users)
        if not user_id:
            if 'my_scans' not in session:
                session['my_scans'] = []
            if domain not in session['my_scans']:
                session['my_scans'].append(domain)

        # Update scan status to completed
        session['scan_status'][domain] = 'completed'
        session.modified = True

        # Add rate limit info to response
        scan_result['rate_limit'] = {
            'scans_remaining': remaining - 1,
            'limit_type': limit_type
        }

        return jsonify(scan_result)
    except Exception as e:
        # Mark scan as failed in session
        if 'scan_status' not in session:
            session['scan_status'] = {}
        session['scan_status'][domain] = 'failed'
        session.modified = True
        return jsonify({'error': str(e), 'domain': domain}), 500'''
    
    content = content.replace(old_scan, new_scan)
    
    # 5. Add all auth endpoints before "if __name__ == '__main__':"
    auth_endpoints = '''

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user account"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    email = data.get('email', '').strip()
    password = data.get('password', '')
    full_name = data.get('full_name', '').strip()
    company = data.get('company', '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user_id, error = user_auth.register_user(
        email=email,
        password=password,
        full_name=full_name if full_name else None,
        company=company if company else None
    )

    if error:
        return jsonify({'error': error}), 400

    # Auto-login after registration
    user_data, login_error = user_auth.login_user(email, password)
    if login_error:
        return jsonify({
            'success': True,
            'user_id': user_id,
            'message': 'Account created successfully. Please log in.'
        }), 201

    return jsonify({
        'success': True,
        'user': {
            'id': user_data['id'],
            'email': user_data['email'],
            'full_name': user_data.get('full_name')
        }
    }), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login with email and password"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    email = data.get('email', '').strip()
    password = data.get('password', '')
    remember_me = data.get('remember_me', False)

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user_data, error = user_auth.login_user(email, password, remember_me)
    if error:
        return jsonify({'error': error}), 401

    plan = user_auth.get_user_plan(user_data['id'])
    return jsonify({
        'success': True,
        'user': {
            'id': user_data['id'],
            'email': user_data['email'],
            'full_name': user_data.get('full_name'),
            'plan': plan['name'] if plan else 'free'
        }
    }), 200


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout current user"""
    user_auth.logout_user()
    return jsonify({'success': True}), 200


@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user_info():
    """Get current logged-in user information"""
    user = user_auth.get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    allowed, remaining, limit_type = user_auth.check_rate_limit(user['id'])
    return jsonify({
        'user': {
            'id': user['id'],
            'email': user['email'],
            'full_name': user.get('full_name'),
            'company': user.get('company'),
            'plan': user.get('plan_name', 'free'),
            'plan_display_name': user.get('plan_display_name', 'Free')
        },
        'usage': {
            'scans_remaining_today': remaining,
            'rate_limit_exceeded': not allowed
        }
    }), 200


# ============================================================================
# ACCOUNT MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/account/plan', methods=['GET'])
@login_required
def get_account_plan():
    """Get user's subscription plan details"""
    user_id = session.get('user_id')
    plan = user_auth.get_user_plan(user_id)
    if not plan:
        return jsonify({'error': 'No active subscription'}), 404

    return jsonify({'plan': plan}), 200


@app.route('/api/account/api-keys', methods=['GET'])
@login_required
def list_api_keys():
    """List all API keys for current user"""
    user_id = session.get('user_id')
    keys = api_key_manager.list_api_keys(user_id)
    return jsonify({'api_keys': keys}), 200


@app.route('/api/account/api-keys', methods=['POST'])
@login_required
def create_api_key():
    """Create a new API key"""
    user_id = session.get('user_id')
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    if not name:
        return jsonify({'error': 'API key name is required'}), 400

    api_key, key_id, error = api_key_manager.create_api_key(
        user_id=user_id,
        name=name,
        description=description if description else None
    )

    if error:
        return jsonify({'error': error}), 400

    return jsonify({
        'success': True,
        'api_key': api_key,
        'key_id': key_id,
        'message': 'API key created. Save this - you won\\'t see it again!'
    }), 201


@app.route('/api/account/api-keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    """Delete an API key"""
    user_id = session.get('user_id')
    success, error = api_key_manager.delete_api_key(user_id, key_id)
    if error:
        return jsonify({'error': error}), 404
    return jsonify({'success': True}), 200

'''
    
    # Add auth endpoints before if __name__
    content = content.replace(
        "\nif __name__ == '__main__':",
        auth_endpoints + "\nif __name__ == '__main__':"
    )
    
    # Write the updated content
    with open(app_py_path, 'w') as f:
        f.write(content)
    
    print("✅ Authentication system integrated into app.py")
    print("   - Added imports for UserAuth and APIKeyManager")
    print("   - Initialized auth system")
    print("   - Added before_request handler")
    print("   - Updated scan endpoint with rate limiting")
    print("   - Added authentication endpoints")
    print("   - Added account management endpoints")

if __name__ == '__main__':
    integrate_auth_into_app('/Users/ryan/development/afterdarksys.com/subdomains/dnsscience/app.py')
