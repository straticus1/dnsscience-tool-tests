"""
Authentication and Account Management Endpoints
Add these to app.py
"""

# Add to imports at top of app.py:
# from auth import UserAuth, PasswordHasher, login_required, optional_auth
# from api_key_manager import APIKeyManager
# from flask import g

# Initialize after db = Database():
# user_auth = UserAuth(db)
# api_key_manager = APIKeyManager(db)

# Add before_request handler to make auth available in g
# @app.before_request
# def load_auth():
#     g.auth = user_auth
#     g.api_key_manager = api_key_manager


def register_auth_endpoints(app, user_auth, api_key_manager, db):
    """Register all authentication and account endpoints"""

    # ============================================================================
    # AUTHENTICATION ENDPOINTS
    # ============================================================================

    @app.route('/api/auth/register', methods=['POST'])
    def register():
        """
        Register a new user account.
        POST /api/auth/register
        Body: {"email": "user@example.com", "password": "password123", "full_name": "John Doe", "company": "Acme Inc"}
        """
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        email = data.get('email', '').strip()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()
        company = data.get('company', '').strip()

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        # Register user
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
            # Registration succeeded but login failed - shouldn't happen
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
                'full_name': user_data.get('full_name'),
                'email_verified': user_data.get('email_verified', False)
            },
            'message': 'Account created successfully'
        }), 201

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        """
        Login with email and password.
        POST /api/auth/login
        Body: {"email": "user@example.com", "password": "password123", "remember_me": false}
        """
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        email = data.get('email', '').strip()
        password = data.get('password', '')
        remember_me = data.get('remember_me', False)

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        # Login user
        user_data, error = user_auth.login_user(email, password, remember_me)

        if error:
            return jsonify({'error': error}), 401

        # Get user's plan
        plan = user_auth.get_user_plan(user_data['id'])

        return jsonify({
            'success': True,
            'user': {
                'id': user_data['id'],
                'email': user_data['email'],
                'full_name': user_data.get('full_name'),
                'email_verified': user_data.get('email_verified', False),
                'plan': plan['name'] if plan else 'free'
            }
        }), 200

    @app.route('/api/auth/logout', methods=['POST'])
    def logout():
        """Logout current user"""
        user_auth.logout_user()
        return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

    @app.route('/api/auth/me', methods=['GET'])
    @login_required
    def get_current_user_info():
        """Get current logged-in user information"""
        user = user_auth.get_current_user()

        if not user:
            return jsonify({'error': 'Not authenticated'}), 401

        # Get usage stats
        allowed, remaining, limit_type = user_auth.check_rate_limit(user['id'])

        return jsonify({
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user.get('full_name'),
                'company': user.get('company'),
                'email_verified': user.get('email_verified', False),
                'created_at': user.get('created_at').isoformat() if user.get('created_at') else None,
                'last_login': user.get('last_login').isoformat() if user.get('last_login') else None,
                'plan': user.get('plan_name', 'free'),
                'plan_display_name': user.get('plan_display_name', 'Free'),
                'subscription_status': user.get('subscription_status', 'active')
            },
            'usage': {
                'scans_remaining_today': remaining,
                'limit_type': limit_type,
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

        return jsonify({
            'plan': {
                'name': plan['name'],
                'display_name': plan['display_name'],
                'description': plan.get('description'),
                'max_scans_per_day': plan['max_scans_per_day'],
                'max_scans_per_month': plan['max_scans_per_month'],
                'max_api_keys': plan['max_api_keys'],
                'has_api_access': plan['has_api_access'],
                'api_rate_limit': plan['api_rate_limit'],
                'features': {
                    'ssl_monitoring': plan.get('has_ssl_monitoring', False),
                    'webhooks': plan.get('has_webhooks', False),
                    'bulk_scanning': plan.get('has_bulk_scanning', False),
                    'custom_reports': plan.get('has_custom_reports', False),
                    'priority_support': plan.get('has_priority_support', False),
                    'historical_data': plan.get('has_historical_data', False),
                    'history_days': plan.get('history_days', 30)
                }
            }
        }), 200

    @app.route('/api/account/usage', methods=['GET'])
    @login_required
    def get_account_usage():
        """Get user's usage statistics"""
        user_id = session.get('user_id')

        # Get today's usage
        allowed, remaining_today, limit_type = user_auth.check_rate_limit(user_id)

        # Get monthly scan count
        conn = db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT COALESCE(SUM(scan_count), 0) as total_scans
                    FROM usage_tracking
                    WHERE user_id = %s
                      AND usage_date >= DATE_TRUNC('month', CURRENT_DATE)
                """, (user_id,))

                result = cursor.fetchone()
                scans_this_month = result[0] if result else 0

        finally:
            db.return_connection(conn)

        plan = user_auth.get_user_plan(user_id)

        return jsonify({
            'usage': {
                'scans_today': (plan['max_scans_per_day'] - remaining_today) if plan else 0,
                'scans_remaining_today': remaining_today,
                'max_scans_per_day': plan['max_scans_per_day'] if plan else 0,
                'scans_this_month': scans_this_month,
                'max_scans_per_month': plan['max_scans_per_month'] if plan else 0
            }
        }), 200

    # ============================================================================
    # API KEY ENDPOINTS
    # ============================================================================

    @app.route('/api/account/api-keys', methods=['GET'])
    @login_required
    def list_api_keys():
        """List all API keys for current user"""
        user_id = session.get('user_id')
        keys = api_key_manager.list_api_keys(user_id)

        return jsonify({
            'api_keys': keys
        }), 200

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

        # Create API key
        api_key, key_id, error = api_key_manager.create_api_key(
            user_id=user_id,
            name=name,
            description=description if description else None
        )

        if error:
            return jsonify({'error': error}), 400

        return jsonify({
            'success': True,
            'api_key': api_key,  # ONLY time we return the full key
            'key_id': key_id,
            'message': 'API key created successfully. Save this key - you won\'t see it again!'
        }), 201

    @app.route('/api/account/api-keys/<int:key_id>', methods=['DELETE'])
    @login_required
    def delete_api_key(key_id):
        """Delete an API key"""
        user_id = session.get('user_id')

        success, error = api_key_manager.delete_api_key(user_id, key_id)

        if error:
            return jsonify({'error': error}), 404

        return jsonify({
            'success': True,
            'message': 'API key deleted successfully'
        }), 200

    @app.route('/api/account/api-keys/<int:key_id>/toggle', methods=['POST'])
    @login_required
    def toggle_api_key(key_id):
        """Enable or disable an API key"""
        user_id = session.get('user_id')
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        is_active = data.get('is_active', True)

        success, error = api_key_manager.toggle_api_key(user_id, key_id, is_active)

        if error:
            return jsonify({'error': error}), 404

        return jsonify({
            'success': True,
            'message': f'API key {"enabled" if is_active else "disabled"} successfully'
        }), 200

    @app.route('/api/account/api-keys/<int:key_id>/stats', methods=['GET'])
    @login_required
    def get_api_key_stats(key_id):
        """Get usage statistics for an API key"""
        user_id = session.get('user_id')

        stats, error = api_key_manager.get_api_key_stats(user_id, key_id)

        if error:
            return jsonify({'error': error}), 404

        return jsonify(stats), 200

    return app
