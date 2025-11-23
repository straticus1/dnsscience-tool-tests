"""
DNS Science Rate Limiting System
Enforces subscription tier limits for web and API requests
"""

import time
import functools
from datetime import datetime, timedelta
from flask import request, jsonify, g, session
from typing import Optional, Tuple, Dict, Any
import redis
from config import Config

class RateLimiter:
    """Rate limiting enforcement for subscription tiers"""

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """
        Initialize rate limiter

        Args:
            redis_client: Redis connection for rate limit tracking
        """
        self.redis = redis_client or redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            decode_responses=True
        )

    def check_rate_limit(self, user_id: int, request_type: str = 'api') -> Tuple[bool, Dict[str, Any]]:
        """
        Check if user is within rate limits

        Args:
            user_id: User ID to check
            request_type: Type of request ('web' or 'api')

        Returns:
            Tuple of (allowed: bool, limit_info: dict)
        """
        from database import Database
        db = Database()

        try:
            # Get user's tier limits
            tier_info = db.execute_query("""
                SELECT
                    st.tier_slug,
                    st.requests_per_hour,
                    st.web_requests_per_month,
                    st.api_requests_per_month
                FROM user_subscriptions us
                JOIN subscription_tiers st ON us.tier_id = st.id
                WHERE us.user_id = %s AND us.status = 'active'
            """, (user_id,), fetch_one=True)

            if not tier_info:
                # No subscription = Free tier limits
                hourly_limit = 100
                monthly_limit = 1500
            else:
                hourly_limit = tier_info['requests_per_hour']
                monthly_limit = tier_info['web_requests_per_month'] if request_type == 'web' else tier_info['api_requests_per_month']

                # -1 means unlimited
                if hourly_limit == -1:
                    hourly_limit = float('inf')
                if monthly_limit == -1:
                    monthly_limit = float('inf')

            # Check hourly limit (using Redis for performance)
            hour_key = f"rate_limit:{user_id}:hour:{datetime.utcnow().strftime('%Y%m%d%H')}"
            hourly_count = int(self.redis.get(hour_key) or 0)

            if hourly_count >= hourly_limit:
                return False, {
                    'allowed': False,
                    'limit': hourly_limit,
                    'remaining': 0,
                    'reset': self._get_hour_reset(),
                    'retry_after': self._get_hour_reset(),
                    'limit_type': 'hourly',
                    'tier': tier_info['tier_slug'] if tier_info else 'free'
                }

            # Check monthly limit (from database)
            period_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            usage = db.execute_query("""
                SELECT
                    COALESCE(web_requests, 0) as web_requests,
                    COALESCE(api_requests, 0) as api_requests
                FROM usage_tracking
                WHERE user_id = %s AND period_start = %s
            """, (user_id, period_start), fetch_one=True)

            monthly_count = 0
            if usage:
                monthly_count = usage['web_requests'] if request_type == 'web' else usage['api_requests']

            if monthly_count >= monthly_limit:
                # Calculate overage
                overage = monthly_count - monthly_limit + 1
                overage_cost = overage * 0.002  # $0.002 per request

                return False, {
                    'allowed': False,
                    'limit': monthly_limit,
                    'remaining': 0,
                    'reset': self._get_month_reset(),
                    'retry_after': self._get_month_reset(),
                    'limit_type': 'monthly',
                    'tier': tier_info['tier_slug'] if tier_info else 'free',
                    'overage': overage,
                    'overage_cost': round(overage_cost, 2),
                    'upgrade_url': '/pricing'
                }

            # All checks passed - allow request
            return True, {
                'allowed': True,
                'hourly_limit': hourly_limit if hourly_limit != float('inf') else -1,
                'hourly_remaining': hourly_limit - hourly_count if hourly_limit != float('inf') else -1,
                'monthly_limit': monthly_limit if monthly_limit != float('inf') else -1,
                'monthly_remaining': monthly_limit - monthly_count if monthly_limit != float('inf') else -1,
                'reset': self._get_hour_reset(),
                'tier': tier_info['tier_slug'] if tier_info else 'free'
            }

        finally:
            db.close()

    def increment_usage(self, user_id: int, request_type: str = 'api'):
        """
        Increment usage counters for a user

        Args:
            user_id: User ID
            request_type: 'web' or 'api'
        """
        from database import Database
        db = Database()

        try:
            # Increment hourly counter in Redis
            hour_key = f"rate_limit:{user_id}:hour:{datetime.utcnow().strftime('%Y%m%d%H')}"
            self.redis.incr(hour_key)
            self.redis.expire(hour_key, 3600)  # Expire after 1 hour

            # Increment monthly counter in database
            db.execute_update("""
                SELECT increment_usage(%s, %s)
            """, (user_id, request_type))

        finally:
            db.close()

    def _get_hour_reset(self) -> int:
        """Get seconds until the current hour ends"""
        now = datetime.utcnow()
        next_hour = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        return int((next_hour - now).total_seconds())

    def _get_month_reset(self) -> int:
        """Get seconds until the current month ends"""
        now = datetime.utcnow()
        if now.month == 12:
            next_month = now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            next_month = now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)
        return int((next_month - now).total_seconds())


# Global rate limiter instance
rate_limiter = RateLimiter()


def require_tier(minimum_tier: str):
    """
    Decorator to require a minimum subscription tier

    Args:
        minimum_tier: Minimum tier slug required (e.g., 'essentials', 'professional')

    Example:
        @app.route('/api/advanced')
        @require_tier('professional')
        def advanced_endpoint():
            return jsonify({'data': 'advanced stuff'})
    """
    tier_hierarchy = {
        'free': 0,
        'essentials': 1,
        'professional': 2,
        'commercial': 3,
        'research': 2,  # Same level as professional
        'enterprise': 4
    }

    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            # Get user from session or API key
            user_id = session.get('user_id') or g.get('user_id')

            if not user_id:
                return jsonify({
                    'error': 'Authentication required',
                    'message': 'Please login or provide an API key',
                    'upgrade_url': '/pricing'
                }), 401

            from database import Database
            db = Database()

            try:
                # Get user's current tier
                user_tier = db.execute_query("""
                    SELECT st.tier_slug
                    FROM user_subscriptions us
                    JOIN subscription_tiers st ON us.tier_id = st.id
                    WHERE us.user_id = %s AND us.status = 'active'
                """, (user_id,), fetch_one=True)

                current_tier_slug = user_tier['tier_slug'] if user_tier else 'free'
                current_tier_level = tier_hierarchy.get(current_tier_slug, 0)
                required_tier_level = tier_hierarchy.get(minimum_tier, 999)

                if current_tier_level < required_tier_level:
                    return jsonify({
                        'error': 'Upgrade required',
                        'message': f'This feature requires {minimum_tier.title()} tier or higher',
                        'current_tier': current_tier_slug,
                        'required_tier': minimum_tier,
                        'upgrade_url': '/pricing'
                    }), 403

                return f(*args, **kwargs)

            finally:
                db.close()

        return wrapped
    return decorator


def rate_limit(request_type: str = 'api'):
    """
    Decorator to enforce rate limiting

    Args:
        request_type: Type of request ('web' or 'api')

    Example:
        @app.route('/api/scan')
        @rate_limit('api')
        def scan_endpoint():
            return jsonify({'data': 'scan results'})
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            # Get user from session or API key
            user_id = session.get('user_id') or g.get('user_id')

            if not user_id:
                # Anonymous users get minimal rate limit
                user_id = f"anon_{request.remote_addr}"

            # Check rate limit
            allowed, limit_info = rate_limiter.check_rate_limit(user_id, request_type)

            # Add rate limit headers to response
            if hasattr(g, 'rate_limit_info'):
                g.rate_limit_info.update(limit_info)
            else:
                g.rate_limit_info = limit_info

            if not allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'You have exceeded your {limit_info["limit_type"]} rate limit',
                    'limit': limit_info['limit'],
                    'remaining': limit_info['remaining'],
                    'reset': limit_info['reset'],
                    'tier': limit_info.get('tier', 'free'),
                    'upgrade_url': '/pricing'
                })

                # Add rate limit headers
                response.headers['X-RateLimit-Limit'] = str(limit_info['limit'])
                response.headers['X-RateLimit-Remaining'] = str(limit_info['remaining'])
                response.headers['X-RateLimit-Reset'] = str(limit_info['reset'])
                response.headers['Retry-After'] = str(limit_info['retry_after'])

                return response, 429

            # Increment usage counter
            rate_limiter.increment_usage(user_id, request_type)

            # Execute the actual endpoint
            response = f(*args, **kwargs)

            # Add rate limit headers to successful response
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(limit_info.get('hourly_limit', -1))
                response.headers['X-RateLimit-Remaining'] = str(limit_info.get('hourly_remaining', -1))
                response.headers['X-RateLimit-Reset'] = str(limit_info['reset'])
                response.headers['X-RateLimit-Tier'] = limit_info.get('tier', 'free')

            return response

        return wrapped
    return decorator


def require_feature(feature_name: str):
    """
    Decorator to require a specific feature based on tier

    Args:
        feature_name: Feature name to check (e.g., 'webhooks', 'slack_integration')

    Example:
        @app.route('/api/webhooks')
        @require_feature('webhooks')
        def webhooks_endpoint():
            return jsonify({'webhooks': []})
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            user_id = session.get('user_id') or g.get('user_id')

            if not user_id:
                return jsonify({
                    'error': 'Authentication required',
                    'upgrade_url': '/pricing'
                }), 401

            from database import Database
            db = Database()

            try:
                # Check if user has feature access
                has_access = db.execute_query("""
                    SELECT user_has_feature(%s, %s) as has_access
                """, (user_id, feature_name), fetch_one=True)

                if not has_access or not has_access['has_access']:
                    return jsonify({
                        'error': 'Feature not available',
                        'message': f'The {feature_name} feature is not available on your current tier',
                        'required_feature': feature_name,
                        'upgrade_url': '/pricing'
                    }), 403

                return f(*args, **kwargs)

            finally:
                db.close()

        return wrapped
    return decorator


@functools.lru_cache(maxsize=1000)
def get_user_limits(user_id: int) -> Dict[str, Any]:
    """
    Get user's current limits (cached for performance)

    Args:
        user_id: User ID

    Returns:
        Dictionary with limit information
    """
    from database import Database
    db = Database()

    try:
        limits = db.execute_query("""
            SELECT
                st.tier_name,
                st.tier_slug,
                st.web_requests_per_month,
                st.api_requests_per_month,
                st.requests_per_hour,
                st.max_domains,
                st.max_api_keys,
                st.history_retention_days,
                st.features
            FROM user_subscriptions us
            JOIN subscription_tiers st ON us.tier_id = st.id
            WHERE us.user_id = %s AND us.status = 'active'
        """, (user_id,), fetch_one=True)

        if not limits:
            # Default to free tier
            return {
                'tier_name': 'Free',
                'tier_slug': 'free',
                'web_requests_per_month': 1500,
                'api_requests_per_month': 1500,
                'requests_per_hour': 100,
                'max_domains': 10,
                'max_api_keys': 1,
                'history_retention_days': 90,
                'features': {}
            }

        return dict(limits)

    finally:
        db.close()
