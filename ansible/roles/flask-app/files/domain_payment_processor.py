"""
Domain and SSL Payment Processing Integration

Extends the existing Stripe payment system to handle domain registration
and SSL certificate purchases.

Author: DNS Science Development Team
Version: 1.0.0
Date: 2025-11-13
"""

import stripe
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from database import Database
from opensrs_integration import create_opensrs_client, DomainRegistrationRequest, SSLCertificateOrder
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DomainPaymentProcessor:
    """
    Handle payments for domain registrations and SSL certificates through Stripe.
    """

    def __init__(self, db: Database, stripe_api_key: str):
        """
        Initialize payment processor.

        Args:
            db: Database instance
            stripe_api_key: Stripe secret API key
        """
        self.db = db
        stripe.api_key = stripe_api_key

    def create_domain_checkout_session(self, user_id: int, cart_items: List[Dict[str, Any]],
                                       success_url: str, cancel_url: str) -> Dict[str, Any]:
        """
        Create Stripe checkout session for domain/SSL purchase.

        Args:
            user_id: User ID
            cart_items: List of cart items
                [
                    {
                        'type': 'domain_registration',
                        'domain': 'example.com',
                        'years': 1,
                        'price': 12.99,
                        'config': {...}
                    },
                    {
                        'type': 'ssl_certificate',
                        'domain': 'example.com',
                        'product_code': 'dv_single',
                        'years': 1,
                        'price': 29.99,
                        'config': {...}
                    }
                ]
            success_url: Redirect URL on success
            cancel_url: Redirect URL on cancel

        Returns:
            {
                'session_id': ...,
                'session_url': ...,
                'order_number': ...
            }
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Generate order number
                cursor.execute("SELECT generate_order_number()")
                order_number = cursor.fetchone()[0]

                # Calculate totals
                subtotal = sum(item['price'] for item in cart_items)
                tax = 0  # TODO: Calculate tax based on user location
                total = subtotal + tax

                # Create pending order
                cursor.execute("""
                    INSERT INTO opensrs_orders (
                        user_id, order_type, order_number, domain_name,
                        product_type, subtotal, tax, total, status
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    ) RETURNING id
                """, (
                    user_id,
                    'multi_item' if len(cart_items) > 1 else cart_items[0]['type'],
                    order_number,
                    cart_items[0]['domain'] if cart_items else None,
                    None,
                    subtotal,
                    tax,
                    total,
                    'pending'
                ))

                order_id = cursor.fetchone()[0]

                # Create order line items
                for item in cart_items:
                    cursor.execute("""
                        INSERT INTO opensrs_order_items (
                            order_id, item_type, domain_name, product_code,
                            description, unit_price, quantity, subtotal, config
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        order_id,
                        item['type'],
                        item['domain'],
                        item.get('product_code'),
                        item.get('description', f"{item['type']} - {item['domain']}"),
                        item['price'],
                        1,
                        item['price'],
                        json.dumps(item.get('config', {}))
                    ))

                conn.commit()

                # Create Stripe checkout session
                line_items = []
                for item in cart_items:
                    line_items.append({
                        'price_data': {
                            'currency': 'usd',
                            'unit_amount': int(item['price'] * 100),  # Convert to cents
                            'product_data': {
                                'name': f"{item['domain']} - {item['type'].replace('_', ' ').title()}",
                                'description': f"{item.get('years', 1)} year(s)"
                            }
                        },
                        'quantity': 1
                    })

                # Create Stripe session
                session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=line_items,
                    mode='payment',
                    success_url=f"{success_url}?session_id={{CHECKOUT_SESSION_ID}}",
                    cancel_url=cancel_url,
                    client_reference_id=str(order_id),
                    metadata={
                        'order_number': order_number,
                        'order_id': order_id,
                        'user_id': user_id
                    }
                )

                # Update order with Stripe session ID
                cursor.execute("""
                    UPDATE opensrs_orders
                    SET stripe_payment_intent_id = %s
                    WHERE id = %s
                """, (session.id, order_id))
                conn.commit()

                logger.info(f"Created checkout session for order {order_number}")

                return {
                    'session_id': session.id,
                    'session_url': session.url,
                    'order_number': order_number,
                    'order_id': order_id
                }

        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to create checkout session: {e}")
            raise
        finally:
            self.db.return_connection(conn)

    def handle_payment_success(self, session_id: str) -> Dict[str, Any]:
        """
        Process successful payment and submit to OpenSRS.

        Args:
            session_id: Stripe checkout session ID

        Returns:
            Processing result
        """
        # Retrieve session from Stripe
        session = stripe.checkout.Session.retrieve(session_id)

        order_id = int(session.client_reference_id)
        logger.info(f"Processing successful payment for order ID {order_id}")

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Mark order as paid
                cursor.execute("""
                    UPDATE opensrs_orders
                    SET status = 'processing',
                        paid_at = NOW(),
                        stripe_charge_id = %s
                    WHERE id = %s
                """, (session.payment_intent, order_id))

                # Get order details and items
                cursor.execute("""
                    SELECT o.*, u.email, u.username
                    FROM opensrs_orders o
                    JOIN users u ON o.user_id = u.id
                    WHERE o.id = %s
                """, (order_id,))

                order = cursor.fetchone()

                cursor.execute("""
                    SELECT * FROM opensrs_order_items
                    WHERE order_id = %s
                """, (order_id,))

                items = cursor.fetchall()

                conn.commit()

                # Process each item
                results = []
                for item in items:
                    try:
                        if item[2] == 'domain_registration':  # item_type
                            result = self._process_domain_registration(order, item)
                            results.append(result)
                        elif item[2] == 'ssl_certificate':
                            result = self._process_ssl_order(order, item)
                            results.append(result)
                    except Exception as e:
                        logger.error(f"Failed to process item {item[0]}: {e}")
                        results.append({'success': False, 'error': str(e)})

                # Update final order status
                all_success = all(r.get('success', False) for r in results)
                final_status = 'completed' if all_success else 'failed'

                cursor.execute("""
                    UPDATE opensrs_orders
                    SET status = %s, completed_at = NOW()
                    WHERE id = %s
                """, (final_status, order_id))
                conn.commit()

                # Send confirmation email
                self._send_confirmation_email(order, results)

                return {
                    'success': all_success,
                    'order_id': order_id,
                    'results': results
                }

        except Exception as e:
            conn.rollback()
            logger.error(f"Payment processing failed: {e}")
            raise
        finally:
            self.db.return_connection(conn)

    def _process_domain_registration(self, order: tuple, item: tuple) -> Dict[str, Any]:
        """Process domain registration item."""
        # Get OpenSRS credentials
        opensrs_config = self._get_opensrs_config()

        # Create OpenSRS client
        _, domain_mgr, _, _ = create_opensrs_client(
            opensrs_config['username'],
            opensrs_config['api_key'],
            opensrs_config['environment']
        )

        # Parse item config
        config = json.loads(item[10])  # config column

        # Build registration request
        from opensrs_integration import DomainContact

        contacts = DomainContact(
            first_name=config['contacts']['first_name'],
            last_name=config['contacts']['last_name'],
            email=config['contacts']['email'],
            phone=config['contacts']['phone'],
            address1=config['contacts']['address1'],
            city=config['contacts']['city'],
            state=config['contacts']['state'],
            postal_code=config['contacts']['postal_code'],
            country=config['contacts']['country'],
            org=config['contacts'].get('org')
        )

        request = DomainRegistrationRequest(
            domain=item[3],  # domain_name
            years=config['years'],
            contacts=contacts,
            nameservers=config['nameservers'],
            auto_renew=config.get('auto_renew', True),
            whois_privacy=config.get('whois_privacy', True),
            transfer_lock=config.get('transfer_lock', True)
        )

        # Register domain
        result = domain_mgr.register_domain(request)

        # Save to domains_owned table
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO domains_owned (
                        user_id, domain_name, tld, opensrs_order_id,
                        registered_at, expires_at, auto_renew_enabled,
                        transfer_lock_enabled, registrant_name, registrant_email,
                        nameservers, whois_privacy_enabled, status,
                        purchase_price, cost_price, margin
                    ) VALUES (
                        %s, %s, %s, %s, NOW(), NOW() + INTERVAL '%s years',
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                """, (
                    order[1],  # user_id
                    item[3],  # domain_name
                    item[3].split('.')[-1],  # TLD
                    result['order_id'],
                    config['years'],
                    request.auto_renew,
                    request.transfer_lock,
                    f"{contacts.first_name} {contacts.last_name}",
                    contacts.email,
                    request.nameservers,
                    request.whois_privacy,
                    'active',
                    item[7],  # unit_price
                    item[7] * 0.8,  # Estimate cost (80% of retail)
                    item[7] * 0.2  # 20% margin
                ))
                conn.commit()
        finally:
            self.db.return_connection(conn)

        return result

    def _process_ssl_order(self, order: tuple, item: tuple) -> Dict[str, Any]:
        """Process SSL certificate order item."""
        # Get OpenSRS credentials
        opensrs_config = self._get_opensrs_config()

        # Create OpenSRS client
        _, _, ssl_mgr, _ = create_opensrs_client(
            opensrs_config['username'],
            opensrs_config['api_key'],
            opensrs_config['environment']
        )

        # Parse item config
        config = json.loads(item[10])

        # Build SSL order
        ssl_order = SSLCertificateOrder(
            product_code=item[4],  # product_code
            domain=item[3],  # domain_name
            years=config['years'],
            csr=config['csr'],
            validation_method=config['validation_method'],
            validation_email=config.get('validation_email'),
            san_domains=config.get('san_domains'),
            organization=config.get('organization')
        )

        # Order certificate
        result = ssl_mgr.order_certificate(ssl_order)

        # Save to ssl_certificates_owned table
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO ssl_certificates_owned (
                        user_id, domain_name, certificate_type, product_code,
                        opensrs_product_id, opensrs_order_id, ordered_at,
                        expires_at, auto_renew_enabled, validation_method,
                        validation_status, csr, common_name, status,
                        purchase_price, cost_price, margin
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, NOW(),
                        NOW() + INTERVAL '%s years', %s, %s, %s, %s, %s, %s,
                        %s, %s, %s
                    )
                """, (
                    order[1],  # user_id
                    item[3],  # domain_name
                    config.get('certificate_type', 'dv_single'),
                    item[4],  # product_code
                    result['product_id'],
                    result['order_id'],
                    config['years'],
                    config.get('auto_renew', True),
                    ssl_order.validation_method,
                    'pending',
                    ssl_order.csr,
                    ssl_order.domain,
                    'pending',
                    item[7],  # unit_price
                    item[7] * 0.7,  # Estimate cost (70% of retail)
                    item[7] * 0.3  # 30% margin
                ))
                conn.commit()
        finally:
            self.db.return_connection(conn)

        return result

    def _get_opensrs_config(self) -> Dict[str, str]:
        """Get OpenSRS configuration from database."""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT reseller_username, api_key_encrypted, environment
                    FROM opensrs_config
                    WHERE is_active = true
                    LIMIT 1
                """)
                row = cursor.fetchone()

                if not row:
                    raise Exception("No active OpenSRS configuration found")

                # Decrypt API key
                from opensrs_integration import CredentialEncryption
                encryption_key = os.getenv('OPENSRS_ENCRYPTION_KEY').encode()
                api_key = CredentialEncryption.decrypt(row[1], encryption_key)

                return {
                    'username': row[0],
                    'api_key': api_key,
                    'environment': row[2]
                }
        finally:
            self.db.return_connection(conn)

    def _send_confirmation_email(self, order: tuple, results: List[Dict]):
        """Send order confirmation email."""
        # TODO: Implement email sending using existing email system
        logger.info(f"Would send confirmation email for order {order[3]}")
        pass

    def process_refund(self, order_id: int, reason: str) -> Dict[str, Any]:
        """
        Process refund for domain/SSL order.

        Args:
            order_id: Order ID to refund
            reason: Refund reason

        Returns:
            Refund result
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Get order details
                cursor.execute("""
                    SELECT * FROM opensrs_orders WHERE id = %s
                """, (order_id,))
                order = cursor.fetchone()

                if not order:
                    raise ValueError("Order not found")

                # Check if refund is eligible (within 5 days)
                if order[16]:  # completed_at
                    days_since = (datetime.now() - order[16]).days
                    if days_since > 5:
                        raise ValueError("Refund period expired (> 5 days)")

                # Process Stripe refund
                if order[11]:  # stripe_charge_id
                    refund = stripe.Refund.create(
                        charge=order[11],
                        reason='requested_by_customer'
                    )

                # Update order status
                cursor.execute("""
                    UPDATE opensrs_orders
                    SET status = 'refunded',
                        refunded_at = NOW(),
                        refund_amount = %s,
                        refund_reason = %s
                    WHERE id = %s
                """, (order[8], reason, order_id))  # total amount

                conn.commit()

                logger.info(f"Processed refund for order {order_id}")

                return {
                    'success': True,
                    'order_id': order_id,
                    'refund_amount': order[8]
                }

        except Exception as e:
            conn.rollback()
            logger.error(f"Refund failed: {e}")
            raise
        finally:
            self.db.return_connection(conn)


# Example usage
if __name__ == '__main__':
    from database import Database
    import os

    db = Database()
    stripe_key = os.getenv('STRIPE_SECRET_KEY')

    processor = DomainPaymentProcessor(db, stripe_key)
    print("Domain Payment Processor initialized")
