"""
Authentication and User Management for DNS Science
Supports both anonymous users (session-based) and registered users (database-backed)
"""
import hashlib
import secrets
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, jsonify, g
import psycopg2
import psycopg2.extras


class PasswordHasher:
    """Secure password hashing using SHA256 with salt"""

    @staticmethod
    def hash_password(password, salt=None):
        """Hash a password with a salt"""
        if salt is None:
            salt = secrets.token_hex(32)

        # Create hash with salt
        hash_obj = hashlib.sha256((salt + password).encode('utf-8'))
        password_hash = hash_obj.hexdigest()

        return f"{salt}${password_hash}"

    @staticmethod
    def verify_password(password, stored_hash):
        """Verify a password against a stored hash"""
        try:
            salt, expected_hash = stored_hash.split('$')
            hash_obj = hashlib.sha256((salt + password).encode('utf-8'))
            actual_hash = hash_obj.hexdigest()
            return secrets.compare_digest(actual_hash, expected_hash)
        except ValueError:
            return False


class APIKeyGenerator:
    """Generate and hash API keys"""

    @staticmethod
    def generate_key():
        """Generate a new API key"""
        # Format: dns_live_<32 random hex chars>
        key = f"dns_live_{secrets.token_hex(32)}"
        return key

    @staticmethod
    def hash_key(api_key):
        """Hash an API key for storage"""
        return hashlib.sha256(api_key.encode('utf-8')).hexdigest()

    @staticmethod
    def get_prefix(api_key):
        """Get the display prefix of an API key"""
        # Returns first 16 chars: dns_live_xxxxx...
        return api_key[:16] + "..."


class UserAuth:
    """User authentication and session management"""

    def __init__(self, db_connection_pool):
        self.db = db_connection_pool

    def register_user(self, email, password, full_name=None, company=None):
        """
        Register a new user account.
        Returns: (user_id, error_message)
        """
        # Validate email
        if not self._is_valid_email(email):
            return None, "Invalid email address"

        # Validate password strength
        if len(password) < 8:
            return None, "Password must be at least 8 characters"

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Check if email already exists
                cursor.execute("SELECT id FROM users WHERE email = %s", (email.lower(),))
                if cursor.fetchone():
                    return None, "Email already registered"

                # Hash password
                password_hash = PasswordHasher.hash_password(password)

                # Create user
                cursor.execute("""
                    INSERT INTO users (email, password_hash, username)
                    VALUES (%s, %s, %s)
                    RETURNING id
                """, (email.lower(), password_hash, full_name if full_name else email.split('@')[0]))

                user_id = cursor.fetchone()['id']

                # Create free subscription for new user
                cursor.execute("""
                    INSERT INTO user_subscriptions (user_id, plan_id, current_period_start, current_period_end, status)
                    SELECT %s, id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '100 years', 'active'
                    FROM plans WHERE name = 'free'
                """, (user_id,))

                conn.commit()

                # Log registration
                self._log_action(user_id, 'user_registered', 'user', user_id, 'success')

                return user_id, None

        except Exception as e:
            conn.rollback()
            return None, str(e)
        finally:
            self.db.return_connection(conn)

    def login_user(self, email, password, remember_me=False):
        """
        Authenticate a user and create a session.
        Returns: (user_data, error_message)
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Get user
                cursor.execute("""
                    SELECT id, email, password_hash, username as full_name, is_active, true as email_verified
                    FROM users WHERE email = %s
                """, (email.lower(),))

                user = cursor.fetchone()

                if not user:
                    self._log_action(None, 'login_failed', 'user', None, 'failure', 'User not found')
                    return None, "Invalid email or password"

                # Verify password
                if not PasswordHasher.verify_password(password, user['password_hash']):
                    self._log_action(user['id'], 'login_failed', 'user', user['id'], 'failure', 'Invalid password')
                    return None, "Invalid email or password"

                # Check if account is active
                if not user['is_active']:
                    return None, "Account is disabled"

                # Update last login
                cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user['id'],))
                conn.commit()

                # Create session
                session['user_id'] = user['id']
                session['user_email'] = user['email']
                session['logged_in'] = True
                session.permanent = remember_me  # Keep session alive longer if remember_me

                # Log successful login
                self._log_action(user['id'], 'login_success', 'user', user['id'], 'success')

                return dict(user), None

        except Exception as e:
            return None, str(e)
        finally:
            self.db.return_connection(conn)

    def logout_user(self):
        """Logout current user"""
        user_id = session.get('user_id')
        if user_id:
            self._log_action(user_id, 'logout', 'user', user_id, 'success')

        # Clear session but preserve anonymous scan history
        anonymous_scans = session.get('my_scans', [])
        session.clear()
        session['my_scans'] = anonymous_scans

    def get_current_user(self):
        """Get currently logged in user or None"""
        user_id = session.get('user_id')
        if not user_id:
            return None

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("""
                    SELECT u.id, u.email, u.username as full_name, '' as company, u.is_active,
                           true as email_verified, u.created_at, u.last_login,
                           p.name as plan_name, p.display_name as plan_display_name,
                           us.status as subscription_status
                    FROM users u
                    LEFT JOIN user_subscriptions us ON u.id = us.user_id AND us.status = 'active'
                    LEFT JOIN plans p ON us.plan_id = p.id
                    WHERE u.id = %s AND u.is_active = true
                """, (user_id,))

                user = cursor.fetchone()
                return dict(user) if user else None

        except Exception as e:
            return None
        finally:
            self.db.return_connection(conn)

    def get_user_plan(self, user_id):
        """Get user's current subscription plan"""
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("""
                    SELECT p.*
                    FROM user_subscriptions us
                    JOIN plans p ON us.plan_id = p.id
                    WHERE us.user_id = %s
                      AND us.status = 'active'
                      AND us.current_period_end > CURRENT_TIMESTAMP
                    ORDER BY us.created_at DESC
                    LIMIT 1
                """, (user_id,))

                plan = cursor.fetchone()
                return dict(plan) if plan else None

        except Exception as e:
            return None
        finally:
            self.db.return_connection(conn)

    def check_rate_limit(self, user_id=None):
        """
        Check if user has exceeded rate limits.
        Returns: (allowed, remaining_scans, limit_type)
        """
        if user_id is None:
            # Anonymous user - use session limits
            session_scans = session.get('scan_count_today', 0)
            anonymous_limit = 5  # Anonymous users get 5 scans per day
            return session_scans < anonymous_limit, anonymous_limit - session_scans, 'anonymous'

        # Get user's plan
        plan = self.get_user_plan(user_id)
        if not plan:
            return False, 0, 'no_plan'

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Count scans today
                cursor.execute("""
                    SELECT COALESCE(SUM(scan_count), 0) as total_scans
                    FROM usage_tracking
                    WHERE user_id = %s AND usage_date = CURRENT_DATE
                """, (user_id,))

                result = cursor.fetchone()
                scans_today = result['total_scans'] if result else 0
                remaining = plan['max_scans_per_day'] - scans_today

                return scans_today < plan['max_scans_per_day'], max(0, remaining), 'daily'

        except Exception as e:
            return False, 0, 'error'
        finally:
            self.db.return_connection(conn)

    def record_scan(self, user_id, domain_id, scan_duration_ms=None, scan_source='web', api_key_id=None):
        """Record a scan for usage tracking"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                if user_id:
                    # Record in user_scans for persistent history
                    cursor.execute("""
                        INSERT INTO user_scans (user_id, domain_id, scan_duration_ms, scan_source, api_key_id, ip_address, user_agent)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (user_id, domain_id, scan_duration_ms, scan_source, api_key_id,
                          request.remote_addr, request.headers.get('User-Agent')))

                    # Record usage for rate limiting
                    cursor.execute("SELECT record_usage(%s, 'scan')", (user_id,))

                else:
                    # Anonymous user - increment session counter
                    if 'scan_count_today' not in session:
                        session['scan_count_today'] = 0
                    session['scan_count_today'] += 1
                    session.modified = True

                conn.commit()

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.db.return_connection(conn)

    def verify_api_key(self, api_key):
        """
        Verify an API key and return user_id.
        Returns: (user_id, api_key_id, error_message)
        """
        if not api_key or not api_key.startswith('dns_'):
            return None, None, "Invalid API key format"

        key_hash = APIKeyGenerator.hash_key(api_key)

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("""
                    SELECT ak.id, ak.user_id, u.is_active, ak.is_active as key_active,
                           ak.expires_at, ak.rate_limit
                    FROM api_keys ak
                    JOIN users u ON ak.user_id = u.id
                    WHERE ak.key_hash = %s
                """, (key_hash,))

                key_data = cursor.fetchone()

                if not key_data:
                    return None, None, "Invalid API key"

                if not key_data['key_active']:
                    return None, None, "API key is disabled"

                if not key_data['is_active']:
                    return None, None, "User account is disabled"

                if key_data['expires_at'] and key_data['expires_at'] < datetime.now():
                    return None, None, "API key has expired"

                # Update last used timestamp
                cursor.execute("""
                    UPDATE api_keys
                    SET last_used = CURRENT_TIMESTAMP, total_requests = total_requests + 1
                    WHERE id = %s
                """, (key_data['id'],))

                conn.commit()

                return key_data['user_id'], key_data['id'], None

        except Exception as e:
            return None, None, str(e)
        finally:
            self.db.return_connection(conn)

    def _is_valid_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def _log_action(self, user_id, action, resource_type=None, resource_id=None, status='success', error_message=None):
        """Log action to audit log"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO audit_log (user_id, action, resource_type, resource_id, ip_address, user_agent, status, error_message)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_id, action, resource_type, resource_id,
                      request.remote_addr if request else None,
                      request.headers.get('User-Agent') if request else None,
                      status, error_message))
                conn.commit()
        except Exception:
            conn.rollback()
        finally:
            self.db.return_connection(conn)


# Flask decorators for authentication
def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def api_key_or_session_required(f):
    """Decorator to require either API key or session auth"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key in header
        api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')

        if api_key:
            # Verify API key
            auth = g.get('auth')  # Get auth instance from Flask g
            user_id, api_key_id, error = auth.verify_api_key(api_key)

            if error:
                return jsonify({'error': error}), 401

            # Store user_id in g for this request
            g.user_id = user_id
            g.api_key_id = api_key_id
            g.auth_method = 'api_key'

        elif 'user_id' in session:
            # Session auth
            g.user_id = session['user_id']
            g.api_key_id = None
            g.auth_method = 'session'

        else:
            return jsonify({'error': 'Authentication required'}), 401

        return f(*args, **kwargs)
    return decorated_function


def optional_auth(f):
    """Decorator for endpoints that work with or without auth"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key
        api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')

        if api_key:
            auth = g.get('auth')
            user_id, api_key_id, error = auth.verify_api_key(api_key)
            if not error:
                g.user_id = user_id
                g.api_key_id = api_key_id
                g.auth_method = 'api_key'

        elif 'user_id' in session:
            g.user_id = session['user_id']
            g.api_key_id = None
            g.auth_method = 'session'

        else:
            g.user_id = None
            g.api_key_id = None
            g.auth_method = 'anonymous'

        return f(*args, **kwargs)
    return decorated_function
