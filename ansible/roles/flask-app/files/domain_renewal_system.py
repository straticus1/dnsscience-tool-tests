#!/usr/bin/env python3
"""
Domain Renewal System with Multi-Year Billing
Handles 1, 2, 3, 4+ year domain renewals with Stripe integration
"""

import os
import stripe
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from database import Database

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
logger = logging.getLogger(__name__)


class DomainRenewalSystem:
    """Manage domain renewals with multi-year billing options"""

    # Pricing structure with volume discounts
    RENEWAL_PRICING = {
        'com': {1: 12.99, 2: 24.99, 3: 35.99, 4: 46.99, 5: 57.99},
        'net': {1: 14.99, 2: 28.99, 3: 41.99, 4: 54.99, 5: 67.99},
        'org': {1: 14.99, 2: 28.99, 3: 41.99, 4: 54.99, 5: 67.99},
        'io': {1: 39.99, 2: 78.99, 3: 116.99, 4: 154.99, 5: 192.99},
        'ai': {1: 99.99, 2: 194.99, 3: 284.99, 4: 374.99, 5: 464.99},
        'co': {1: 29.99, 2: 58.99, 3: 86.99, 4: 114.99, 5: 142.99},
        'app': {1: 19.99, 2: 38.99, 3: 56.99, 4: 74.99, 5: 92.99},
        'dev': {1: 19.99, 2: 38.99, 3: 56.99, 4: 74.99, 5: 92.99},
        'tech': {1: 24.99, 2: 48.99, 3: 71.99, 4: 94.99, 5: 117.99},
        'online': {1: 9.99, 2: 19.49, 3: 28.49, 4: 37.49, 5: 46.49},
    }

    def __init__(self, db: Database):
        self.db = db

    def get_renewal_price(self, domain: str, years: int) -> float:
        """
        Get renewal price for domain with multi-year discount

        Args:
            domain: Domain name (e.g., example.com)
            years: Number of years (1-10)

        Returns:
            Price in USD
        """
        tld = domain.split('.')[-1].lower()

        # Get base pricing for this TLD
        tld_pricing = self.RENEWAL_PRICING.get(tld, {1: 19.99})

        # For years beyond 5, use linear pricing from year 5
        if years <= 5:
            return tld_pricing.get(years, tld_pricing[1] * years)
        else:
            year_5_price = tld_pricing.get(5, tld_pricing[1] * 5)
            annual_rate = tld_pricing[1]
            return year_5_price + (annual_rate * (years - 5))

    def create_renewal_checkout(self, user_id: int, domain: str,
                                years: int, auto_renew: bool = True) -> Dict:
        """
        Create Stripe checkout session for domain renewal

        Args:
            user_id: User ID
            domain: Domain to renew
            years: Number of years (1-10)
            auto_renew: Enable auto-renewal after this period

        Returns:
            {'success': True, 'checkout_url': '...', 'session_id': '...'}
        """
        try:
            # Validate years
            if years < 1 or years > 10:
                return {'success': False, 'error': 'Years must be between 1 and 10'}

            # Get pricing
            price = self.get_renewal_price(domain, years)

            # Get user info
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
                    user = cursor.fetchone()
                    if not user:
                        return {'success': False, 'error': 'User not found'}
                    email = user[0]
            finally:
                self.db.return_connection(conn)

            # Create Stripe checkout session
            session = stripe.checkout.Session.create(
                customer_email=email,
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'unit_amount': int(price * 100),  # Convert to cents
                        'product_data': {
                            'name': f'{domain} - {years} Year Renewal',
                            'description': f'Domain renewal for {domain} ({years} year{"s" if years > 1 else ""})',
                            'images': ['https://www.dnsscience.io/static/domain-icon.png']
                        }
                    },
                    'quantity': 1
                }],
                mode='payment',
                success_url=f'https://www.dnsscience.io/dashboard/domains?renewal=success&domain={domain}',
                cancel_url=f'https://www.dnsscience.io/dashboard/domains?renewal=cancelled',
                metadata={
                    'type': 'domain_renewal',
                    'user_id': str(user_id),
                    'domain': domain,
                    'years': str(years),
                    'auto_renew': str(auto_renew).lower()
                }
            )

            # Log renewal request
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO domain_transactions
                        (user_id, domain_name, transaction_type, amount, currency,
                         payment_status, stripe_payment_intent_id, metadata)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        user_id, domain, 'renewal', price, 'USD', 'pending',
                        session.id,
                        f'{{"years": {years}, "auto_renew": {str(auto_renew).lower()}}}'
                    ))
                    conn.commit()
            finally:
                self.db.return_connection(conn)

            return {
                'success': True,
                'checkout_url': session.url,
                'session_id': session.id,
                'amount': price,
                'years': years
            }

        except Exception as e:
            logger.error(f"Error creating renewal checkout: {e}")
            return {'success': False, 'error': str(e)}

    def process_renewal_webhook(self, session: Dict) -> bool:
        """
        Process successful renewal payment from Stripe webhook

        Args:
            session: Stripe checkout session object

        Returns:
            True if successful
        """
        try:
            metadata = session.get('metadata', {})
            user_id = int(metadata.get('user_id'))
            domain = metadata.get('domain')
            years = int(metadata.get('years', 1))
            auto_renew = metadata.get('auto_renew', 'true').lower() == 'true'

            logger.info(f"Processing renewal for {domain}: {years} years, auto_renew={auto_renew}")

            # Update domain expiry and renewal settings
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    # Get current expiry
                    cursor.execute("""
                        SELECT expires_at FROM user_domains
                        WHERE user_id = %s AND domain_name = %s
                    """, (user_id, domain))
                    result = cursor.fetchone()

                    if result:
                        current_expiry = result[0]
                        # Extend from current expiry or now (whichever is later)
                        base_date = max(current_expiry, datetime.now()) if current_expiry else datetime.now()
                    else:
                        base_date = datetime.now()

                    new_expiry = base_date + timedelta(days=365 * years)

                    # Update domain record
                    cursor.execute("""
                        UPDATE user_domains
                        SET expires_at = %s,
                            auto_renew = %s,
                            renewal_price = %s,
                            status = 'active',
                            updated_at = NOW()
                        WHERE user_id = %s AND domain_name = %s
                    """, (new_expiry, auto_renew, self.get_renewal_price(domain, 1), user_id, domain))

                    # Update transaction status
                    cursor.execute("""
                        UPDATE domain_transactions
                        SET payment_status = 'completed', updated_at = NOW()
                        WHERE stripe_payment_intent_id = %s
                    """, (session['id'],))

                    conn.commit()
                    logger.info(f"Renewed {domain} until {new_expiry}")

            finally:
                self.db.return_connection(conn)

            # TODO: Submit renewal to OpenSRS
            # This would call opensrs_integration.renew_domain(domain, years)

            return True

        except Exception as e:
            logger.error(f"Error processing renewal webhook: {e}")
            return False

    def setup_auto_renewal(self, user_id: int, domain: str,
                          years: int = 1, stripe_payment_method_id: str = None) -> Dict:
        """
        Set up automatic renewal with saved payment method

        Args:
            user_id: User ID
            domain: Domain to auto-renew
            years: Default renewal period
            stripe_payment_method_id: Stripe payment method ID (optional)

        Returns:
            {'success': True} or error
        """
        try:
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    # Enable auto-renewal
                    cursor.execute("""
                        UPDATE user_domains
                        SET auto_renew = TRUE,
                            renewal_price = %s,
                            updated_at = NOW()
                        WHERE user_id = %s AND domain_name = %s
                    """, (self.get_renewal_price(domain, years), user_id, domain))

                    # Store payment method if provided
                    if stripe_payment_method_id:
                        cursor.execute("""
                            UPDATE users
                            SET stripe_payment_method_id = %s
                            WHERE id = %s
                        """, (stripe_payment_method_id, user_id))

                    conn.commit()

            finally:
                self.db.return_connection(conn)

            return {'success': True, 'message': f'Auto-renewal enabled for {domain}'}

        except Exception as e:
            logger.error(f"Error setting up auto-renewal: {e}")
            return {'success': False, 'error': str(e)}

    def get_upcoming_renewals(self, user_id: int, days_ahead: int = 30) -> List[Dict]:
        """
        Get domains expiring within specified days

        Args:
            user_id: User ID
            days_ahead: Look ahead this many days

        Returns:
            List of domains with expiry info
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT domain_name, expires_at, auto_renew, renewal_price,
                           EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
                    FROM user_domains
                    WHERE user_id = %s
                      AND status = 'active'
                      AND expires_at IS NOT NULL
                      AND expires_at <= NOW() + INTERVAL '%s days'
                      AND expires_at > NOW()
                    ORDER BY expires_at ASC
                """, (user_id, days_ahead))

                results = []
                for row in cursor.fetchall():
                    results.append({
                        'domain': row[0],
                        'expires_at': row[1].isoformat() if row[1] else None,
                        'auto_renew': row[2],
                        'renewal_price': float(row[3]) if row[3] else None,
                        'days_until_expiry': int(row[4]) if row[4] else None
                    })

                return results

        finally:
            self.db.return_connection(conn)
