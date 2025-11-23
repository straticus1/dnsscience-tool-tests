"""
API Key Management for DNS Science
Handles creation, listing, and revocation of API keys
"""
from auth import APIKeyGenerator
import psycopg2.extras


class APIKeyManager:
    """Manage API keys for users"""

    def __init__(self, db_connection_pool):
        self.db = db_connection_pool

    def create_api_key(self, user_id, name, description=None, scopes=None, rate_limit=None):
        """
        Create a new API key for a user.
        Returns: (api_key, key_id, error_message)
        """
        # Check if user has reached max API keys limit
        user_plan = self._get_user_plan(user_id)
        if not user_plan:
            return None, None, "No active subscription plan"

        current_key_count = self._count_user_keys(user_id)
        if current_key_count >= user_plan['max_api_keys']:
            return None, None, f"Maximum API keys limit reached ({user_plan['max_api_keys']})"

        # Generate new API key
        api_key = APIKeyGenerator.generate_key()
        key_hash = APIKeyGenerator.hash_key(api_key)
        key_prefix = APIKeyGenerator.get_prefix(api_key)

        # Default scopes
        if scopes is None:
            scopes = ['read', 'scan']

        # Default rate limit from plan
        if rate_limit is None:
            rate_limit = user_plan['api_rate_limit']

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("""
                    INSERT INTO api_keys (user_id, key_hash, key_prefix, name, description, scopes, rate_limit, is_active)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, true)
                    RETURNING id
                """, (user_id, key_hash, key_prefix, name, description,
                      psycopg2.extras.Json(scopes), rate_limit))

                key_id = cursor.fetchone()['id']
                conn.commit()

                return api_key, key_id, None

        except Exception as e:
            conn.rollback()
            return None, None, str(e)
        finally:
            self.db.return_connection(conn)

    def list_api_keys(self, user_id):
        """List all API keys for a user"""
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("""
                    SELECT id, key_prefix, name, description, scopes, rate_limit,
                           is_active, created_at, last_used, total_requests, expires_at
                    FROM api_keys
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))

                keys = cursor.fetchall()
                return [dict(key) for key in keys]

        except Exception as e:
            return []
        finally:
            self.db.return_connection(conn)

    def delete_api_key(self, user_id, key_id):
        """Delete/revoke an API key"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    DELETE FROM api_keys
                    WHERE id = %s AND user_id = %s
                    RETURNING id
                """, (key_id, user_id))

                deleted = cursor.fetchone()
                conn.commit()

                return deleted is not None, None if deleted else "API key not found"

        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            self.db.return_connection(conn)

    def toggle_api_key(self, user_id, key_id, is_active):
        """Enable or disable an API key"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE api_keys
                    SET is_active = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s AND user_id = %s
                    RETURNING id
                """, (is_active, key_id, user_id))

                updated = cursor.fetchone()
                conn.commit()

                return updated is not None, None if updated else "API key not found"

        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            self.db.return_connection(conn)

    def get_api_key_stats(self, user_id, key_id):
        """Get usage statistics for an API key"""
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Get key details
                cursor.execute("""
                    SELECT id, name, total_requests, last_used, created_at
                    FROM api_keys
                    WHERE id = %s AND user_id = %s
                """, (key_id, user_id))

                key_info = cursor.fetchone()
                if not key_info:
                    return None, "API key not found"

                # Get scans performed with this key
                cursor.execute("""
                    SELECT COUNT(*) as scan_count,
                           MIN(scan_timestamp) as first_scan,
                           MAX(scan_timestamp) as last_scan
                    FROM user_scans
                    WHERE user_id = %s AND api_key_id = %s
                """, (user_id, key_id))

                scan_stats = cursor.fetchone()

                return {
                    'key_info': dict(key_info),
                    'scan_stats': dict(scan_stats) if scan_stats else {}
                }, None

        except Exception as e:
            return None, str(e)
        finally:
            self.db.return_connection(conn)

    def _get_user_plan(self, user_id):
        """Get user's current plan"""
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

        except Exception:
            return None
        finally:
            self.db.return_connection(conn)

    def _count_user_keys(self, user_id):
        """Count active API keys for a user"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) FROM api_keys WHERE user_id = %s AND is_active = true
                """, (user_id,))

                count = cursor.fetchone()[0]
                return count

        except Exception:
            return 0
        finally:
            self.db.return_connection(conn)
