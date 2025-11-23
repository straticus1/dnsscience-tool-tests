#!/usr/bin/env python3
"""
Stripe Payment Integration for DNS Science
Handles subscriptions, checkout, webhooks, and customer portal
"""

import os
import stripe
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('stripe_integration')

# Initialize Stripe
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')


class StripeManager:
    """Manage Stripe subscriptions and payments"""

    # Stripe Price IDs (set these in your Stripe dashboard)
    PRICE_IDS = {
        'starter_monthly': os.getenv('STRIPE_PRICE_STARTER_MONTHLY'),
        'starter_annual': os.getenv('STRIPE_PRICE_STARTER_ANNUAL'),
        'professional_monthly': os.getenv('STRIPE_PRICE_PROFESSIONAL_MONTHLY'),
        'professional_annual': os.getenv('STRIPE_PRICE_PROFESSIONAL_ANNUAL'),
        'business_monthly': os.getenv('STRIPE_PRICE_BUSINESS_MONTHLY'),
        'business_annual': os.getenv('STRIPE_PRICE_BUSINESS_ANNUAL'),
        'enterprise_monthly': os.getenv('STRIPE_PRICE_ENTERPRISE_MONTHLY'),
        'enterprise_annual': os.getenv('STRIPE_PRICE_ENTERPRISE_ANNUAL'),
    }

    # Trial periods (days)
    TRIAL_PERIODS = {
        'starter': 7,
        'professional': 14,
        'business': 14,
        'enterprise': 30
    }

    def __init__(self):
        self.db = Database()

    def create_checkout_session(self, user_id: int, price_id: str,
                               success_url: str, cancel_url: str,
                               trial_days: Optional[int] = None) -> Dict[str, Any]:
        """
        Create a Stripe Checkout session for subscription

        Args:
            user_id: User ID
            price_id: Stripe Price ID
            success_url: URL to redirect after success
            cancel_url: URL to redirect after cancel
            trial_days: Number of trial days (optional)

        Returns:
            {'success': True, 'checkout_url': 'https://...', 'session_id': '...'}
        """
        try:
            # Get or create Stripe customer
            customer_id = self._get_or_create_customer(user_id)

            # Create checkout session
            session_params = {
                'customer': customer_id,
                'payment_method_types': ['card'],
                'line_items': [{
                    'price': price_id,
                    'quantity': 1,
                }],
                'mode': 'subscription',
                'success_url': success_url + '?session_id={CHECKOUT_SESSION_ID}',
                'cancel_url': cancel_url,
                'client_reference_id': str(user_id),
                'metadata': {
                    'user_id': user_id
                }
            }

            # Add trial period if specified
            if trial_days:
                session_params['subscription_data'] = {
                    'trial_period_days': trial_days,
                    'metadata': {
                        'user_id': user_id,
                        'trial_days': trial_days
                    }
                }

            session = stripe.checkout.Session.create(**session_params)

            # Log checkout session
            self._log_checkout_session(user_id, session.id, price_id, trial_days)

            return {
                'success': True,
                'checkout_url': session.url,
                'session_id': session.id
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating checkout: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Error creating checkout: {e}")
            return {'success': False, 'error': str(e)}

    def create_customer_portal_session(self, user_id: int,
                                       return_url: str) -> Dict[str, Any]:
        """
        Create a Stripe Customer Portal session for subscription management

        Args:
            user_id: User ID
            return_url: URL to return to after portal

        Returns:
            {'success': True, 'portal_url': 'https://...'}
        """
        try:
            customer_id = self._get_customer_id(user_id)
            if not customer_id:
                return {'success': False, 'error': 'No Stripe customer found'}

            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url
            )

            return {
                'success': True,
                'portal_url': session.url
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating portal: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Error creating portal: {e}")
            return {'success': False, 'error': str(e)}

    def handle_webhook(self, payload: bytes, sig_header: str) -> Dict[str, Any]:
        """
        Handle Stripe webhook events

        Args:
            payload: Request body
            sig_header: Stripe-Signature header

        Returns:
            {'success': True, 'event_type': '...'}
        """
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )

            event_type = event['type']
            data = event['data']['object']

            logger.info(f"Received Stripe webhook: {event_type}")

            # Handle different event types
            if event_type == 'checkout.session.completed':
                self._handle_checkout_completed(data)

            elif event_type == 'customer.subscription.created':
                self._handle_subscription_created(data)

            elif event_type == 'customer.subscription.updated':
                self._handle_subscription_updated(data)

            elif event_type == 'customer.subscription.deleted':
                self._handle_subscription_deleted(data)

            elif event_type == 'invoice.payment_succeeded':
                self._handle_payment_succeeded(data)

            elif event_type == 'invoice.payment_failed':
                self._handle_payment_failed(data)

            elif event_type == 'customer.subscription.trial_will_end':
                self._handle_trial_ending(data)

            return {'success': True, 'event_type': event_type}

        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid webhook signature: {e}")
            return {'success': False, 'error': 'Invalid signature'}
        except Exception as e:
            logger.error(f"Error handling webhook: {e}")
            return {'success': False, 'error': str(e)}

    def get_subscription_status(self, user_id: int) -> Dict[str, Any]:
        """Get current subscription status for a user"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        stripe_subscription_id,
                        stripe_customer_id,
                        plan_name,
                        billing_cycle,
                        status,
                        current_period_start,
                        current_period_end,
                        trial_end,
                        cancel_at_period_end,
                        created_at
                    FROM stripe_subscriptions
                    WHERE user_id = %s
                    AND status IN ('active', 'trialing')
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))

                result = cursor.fetchone()
                if not result:
                    return {'has_subscription': False}

                return {
                    'has_subscription': True,
                    'subscription_id': result[0],
                    'customer_id': result[1],
                    'plan_name': result[2],
                    'billing_cycle': result[3],
                    'status': result[4],
                    'current_period_start': result[5],
                    'current_period_end': result[6],
                    'trial_end': result[7],
                    'cancel_at_period_end': result[8],
                    'is_trial': result[4] == 'trialing',
                    'days_until_renewal': (result[6] - datetime.now()).days if result[6] else None
                }

        finally:
            self.db.return_connection(conn)

    def cancel_subscription(self, user_id: int,
                           immediate: bool = False) -> Dict[str, Any]:
        """
        Cancel a subscription

        Args:
            user_id: User ID
            immediate: If True, cancel immediately. If False, cancel at period end.

        Returns:
            {'success': True}
        """
        try:
            status = self.get_subscription_status(user_id)
            if not status.get('has_subscription'):
                return {'success': False, 'error': 'No active subscription'}

            subscription_id = status['subscription_id']

            if immediate:
                stripe.Subscription.delete(subscription_id)
            else:
                stripe.Subscription.modify(
                    subscription_id,
                    cancel_at_period_end=True
                )

            # Update database
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    if immediate:
                        cursor.execute("""
                            UPDATE stripe_subscriptions
                            SET status = 'canceled',
                                canceled_at = NOW()
                            WHERE stripe_subscription_id = %s
                        """, (subscription_id,))
                    else:
                        cursor.execute("""
                            UPDATE stripe_subscriptions
                            SET cancel_at_period_end = true
                            WHERE stripe_subscription_id = %s
                        """, (subscription_id,))
                    conn.commit()
            finally:
                self.db.return_connection(conn)

            return {'success': True}

        except Exception as e:
            logger.error(f"Error canceling subscription: {e}")
            return {'success': False, 'error': str(e)}

    def _get_or_create_customer(self, user_id: int) -> str:
        """Get existing Stripe customer ID or create new customer"""
        customer_id = self._get_customer_id(user_id)
        if customer_id:
            return customer_id

        # Get user details
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT email, username
                    FROM users
                    WHERE id = %s
                """, (user_id,))
                user = cursor.fetchone()

                if not user:
                    raise ValueError(f"User {user_id} not found")

                email, username = user

            # Create Stripe customer
            customer = stripe.Customer.create(
                email=email,
                name=username,
                metadata={'user_id': user_id}
            )

            # Save customer ID
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO stripe_customers (user_id, stripe_customer_id, created_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (user_id) DO UPDATE
                    SET stripe_customer_id = EXCLUDED.stripe_customer_id
                """, (user_id, customer.id))
                conn.commit()

            return customer.id

        finally:
            self.db.return_connection(conn)

    def _get_customer_id(self, user_id: int) -> Optional[str]:
        """Get Stripe customer ID for user"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT stripe_customer_id
                    FROM stripe_customers
                    WHERE user_id = %s
                """, (user_id,))
                result = cursor.fetchone()
                return result[0] if result else None
        finally:
            self.db.return_connection(conn)

    def _log_checkout_session(self, user_id: int, session_id: str,
                              price_id: str, trial_days: Optional[int]):
        """Log checkout session creation"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO stripe_checkout_sessions
                    (user_id, session_id, price_id, trial_days, created_at)
                    VALUES (%s, %s, %s, %s, NOW())
                """, (user_id, session_id, price_id, trial_days))
                conn.commit()
        finally:
            self.db.return_connection(conn)

    def _handle_checkout_completed(self, session):
        """Handle checkout.session.completed event"""
        user_id = int(session['metadata']['user_id'])
        customer_id = session['customer']
        subscription_id = session.get('subscription')
        purchase_type = session.get('metadata', {}).get('type')

        logger.info(f"Checkout completed for user {user_id}, type: {purchase_type}")

        # Handle domain purchases
        if purchase_type == 'domain_purchase':
            self._process_domain_purchase(session, user_id)

        # Handle domain renewals
        elif purchase_type == 'domain_renewal':
            self._process_domain_renewal(session, user_id)

        # Subscription will be handled by subscription.created event
        # Just log the checkout completion
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE stripe_checkout_sessions
                    SET completed_at = NOW(),
                        stripe_customer_id = %s,
                        stripe_subscription_id = %s
                    WHERE session_id = %s
                """, (customer_id, subscription_id, session['id']))
                conn.commit()
        finally:
            self.db.return_connection(conn)

    def _process_domain_purchase(self, session, user_id):
        """Process domain purchase after successful payment"""
        import json
        from opensrs_integration import create_opensrs_client
        from config import Config

        logger.info(f"Processing domain purchase for user {user_id}")

        metadata = session.get('metadata', {})
        session_id = session['id']

        # Extract domain lists from metadata
        domains = metadata.get('domains', '').split(',') if metadata.get('domains') else []
        transfers = metadata.get('transfers', '').split(',') if metadata.get('transfers') else []
        ssl_domains = metadata.get('ssl_domains', '').split(',') if metadata.get('ssl_domains') else []

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Update transaction status to completed
                cursor.execute("""
                    UPDATE domain_transactions
                    SET payment_status = 'completed',
                        stripe_charge_id = %s,
                        updated_at = NOW()
                    WHERE user_id = %s AND stripe_payment_intent_id = %s
                """, (session.get('payment_intent'), user_id, session_id))

                # Initialize OpenSRS client
                client, domain_mgr, ssl_mgr, dns_mgr = create_opensrs_client(
                    Config.OPENSRS_USERNAME,
                    Config.OPENSRS_API_KEY,
                    Config.OPENSRS_ENVIRONMENT
                )

                # Register domains
                for domain in domains:
                    if domain:
                        try:
                            # Register domain via OpenSRS
                            result = domain_mgr.register_domain(
                                domain=domain.strip(),
                                years=1  # Default 1 year registration
                            )

                            # Add to user_domains table
                            cursor.execute("""
                                INSERT INTO user_domains (
                                    user_id, domain_name, status, registration_type,
                                    registered_at, expires_at, opensrs_order_id,
                                    purchase_price, currency, auto_renew
                                ) VALUES (%s, %s, %s, %s, NOW(), NOW() + INTERVAL '1 year', %s, %s, %s, %s)
                                ON CONFLICT (user_id, domain_name) DO UPDATE
                                SET status = 'active', updated_at = NOW()
                            """, (
                                user_id, domain.strip(), 'active', 'register',
                                result.get('order_id'), 12.99, 'USD', True
                            ))
                            logger.info(f"Successfully registered {domain} for user {user_id}")

                        except Exception as e:
                            logger.error(f"Failed to register {domain}: {str(e)}")
                            # Mark domain as pending/failed but don't fail entire transaction
                            cursor.execute("""
                                INSERT INTO user_domains (
                                    user_id, domain_name, status, registration_type,
                                    registered_at, purchase_price, currency, notes
                                ) VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s)
                                ON CONFLICT (user_id, domain_name) DO UPDATE
                                SET notes = EXCLUDED.notes, updated_at = NOW()
                            """, (
                                user_id, domain.strip(), 'pending', 'register',
                                12.99, 'USD', f"Registration failed: {str(e)}"
                            ))

                # Process transfers
                for domain in transfers:
                    if domain:
                        try:
                            cursor.execute("""
                                INSERT INTO user_domains (
                                    user_id, domain_name, status, registration_type,
                                    registered_at, purchase_price, currency
                                ) VALUES (%s, %s, %s, %s, NOW(), %s, %s)
                                ON CONFLICT (user_id, domain_name) DO UPDATE
                                SET status = 'pending', registration_type = 'transfer', updated_at = NOW()
                            """, (user_id, domain.strip(), 'pending', 'transfer', 14.99, 'USD'))
                            logger.info(f"Initiated transfer for {domain} for user {user_id}")

                        except Exception as e:
                            logger.error(f"Failed to initiate transfer for {domain}: {str(e)}")

                conn.commit()
                logger.info(f"Domain purchase processing completed for user {user_id}")

        except Exception as e:
            logger.error(f"Error processing domain purchase: {str(e)}")
            conn.rollback()
        finally:
            self.db.return_connection(conn)

    def _process_domain_renewal(self, session, user_id):
        """Process domain renewal after successful payment"""
        from domain_renewal_system import DomainRenewalSystem

        logger.info(f"Processing domain renewal for user {user_id}")

        renewal_system = DomainRenewalSystem(self.db)
        success = renewal_system.process_renewal_webhook(session)

        if success:
            logger.info(f"Domain renewal processed successfully for user {user_id}")
        else:
            logger.error(f"Failed to process domain renewal for user {user_id}")

    def _handle_subscription_created(self, subscription):
        """Handle customer.subscription.created event"""
        customer_id = subscription['customer']
        subscription_id = subscription['id']

        # Get user_id from customer
        user_id = self._get_user_id_from_customer(customer_id)
        if not user_id:
            logger.error(f"Cannot find user for customer {customer_id}")
            return

        # Extract subscription details
        plan_name = self._get_plan_name_from_price(subscription['items']['data'][0]['price']['id'])
        billing_cycle = subscription['items']['data'][0]['price']['recurring']['interval']

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO stripe_subscriptions (
                        user_id,
                        stripe_subscription_id,
                        stripe_customer_id,
                        plan_name,
                        billing_cycle,
                        status,
                        current_period_start,
                        current_period_end,
                        trial_end,
                        created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (stripe_subscription_id) DO UPDATE
                    SET status = EXCLUDED.status,
                        current_period_start = EXCLUDED.current_period_start,
                        current_period_end = EXCLUDED.current_period_end,
                        trial_end = EXCLUDED.trial_end
                """, (
                    user_id,
                    subscription_id,
                    customer_id,
                    plan_name,
                    billing_cycle,
                    subscription['status'],
                    datetime.fromtimestamp(subscription['current_period_start']),
                    datetime.fromtimestamp(subscription['current_period_end']),
                    datetime.fromtimestamp(subscription['trial_end']) if subscription.get('trial_end') else None
                ))
                conn.commit()

            logger.info(f"Subscription created for user {user_id}: {plan_name}")

        finally:
            self.db.return_connection(conn)

    def _handle_subscription_updated(self, subscription):
        """Handle customer.subscription.updated event"""
        subscription_id = subscription['id']

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE stripe_subscriptions
                    SET status = %s,
                        current_period_start = %s,
                        current_period_end = %s,
                        cancel_at_period_end = %s
                    WHERE stripe_subscription_id = %s
                """, (
                    subscription['status'],
                    datetime.fromtimestamp(subscription['current_period_start']),
                    datetime.fromtimestamp(subscription['current_period_end']),
                    subscription.get('cancel_at_period_end', False),
                    subscription_id
                ))
                conn.commit()

            logger.info(f"Subscription updated: {subscription_id}")

        finally:
            self.db.return_connection(conn)

    def _handle_subscription_deleted(self, subscription):
        """Handle customer.subscription.deleted event"""
        subscription_id = subscription['id']

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE stripe_subscriptions
                    SET status = 'canceled',
                        canceled_at = NOW()
                    WHERE stripe_subscription_id = %s
                """, (subscription_id,))
                conn.commit()

            logger.info(f"Subscription canceled: {subscription_id}")

        finally:
            self.db.return_connection(conn)

    def _handle_payment_succeeded(self, invoice):
        """Handle invoice.payment_succeeded event"""
        subscription_id = invoice.get('subscription')
        if not subscription_id:
            return

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO stripe_invoices (
                        stripe_invoice_id,
                        stripe_subscription_id,
                        amount_paid,
                        currency,
                        status,
                        paid_at,
                        created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, (
                    invoice['id'],
                    subscription_id,
                    invoice['amount_paid'],
                    invoice['currency'],
                    'paid',
                    datetime.fromtimestamp(invoice['status_transitions']['paid_at'])
                ))
                conn.commit()

            logger.info(f"Payment succeeded for subscription {subscription_id}")

        finally:
            self.db.return_connection(conn)

    def _handle_payment_failed(self, invoice):
        """Handle invoice.payment_failed event"""
        subscription_id = invoice.get('subscription')
        if not subscription_id:
            return

        logger.warning(f"Payment failed for subscription {subscription_id}")

        # TODO: Send email notification to user
        # TODO: Update subscription status if payment fails repeatedly

    def _handle_trial_ending(self, subscription):
        """Handle customer.subscription.trial_will_end event (3 days before end)"""
        customer_id = subscription['customer']
        user_id = self._get_user_id_from_customer(customer_id)

        if user_id:
            logger.info(f"Trial ending soon for user {user_id}")
            # TODO: Send email reminder about trial ending

    def _get_user_id_from_customer(self, customer_id: str) -> Optional[int]:
        """Get user_id from Stripe customer_id"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT user_id
                    FROM stripe_customers
                    WHERE stripe_customer_id = %s
                """, (customer_id,))
                result = cursor.fetchone()
                return result[0] if result else None
        finally:
            self.db.return_connection(conn)

    def _get_plan_name_from_price(self, price_id: str) -> str:
        """Get plan name from Stripe price ID"""
        for key, value in self.PRICE_IDS.items():
            if value == price_id:
                return key.split('_')[0].capitalize()
        return 'Unknown'


if __name__ == '__main__':
    # Test Stripe integration
    manager = StripeManager()
    print("Stripe Manager initialized")
    print(f"Available plans: {list(manager.PRICE_IDS.keys())}")
