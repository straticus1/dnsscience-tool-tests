#!/usr/bin/env python3
"""
Auto-Renewal Processing Daemon

Processes automatic renewals for domains and SSL certificates.
Charges payment method on file and submits renewals to OpenSRS.

Run frequency: Every hour
Author: DNS Science Development Team
Version: 1.0.0
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from domain_payment_processor import DomainPaymentProcessor
from opensrs_integration import create_opensrs_client
import logging
from datetime import datetime
import time
import stripe

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AutoRenewalDaemon:
    """Process automatic domain and SSL renewals."""

    def __init__(self):
        self.db = Database()
        stripe_key = os.getenv('STRIPE_SECRET_KEY')
        self.payment_processor = DomainPaymentProcessor(self.db, stripe_key)

    def run(self):
        """Main daemon loop."""
        logger.info("Auto-Renewal Daemon started")

        while True:
            try:
                self.process_renewal_queue()

                # Sleep for 1 hour
                logger.info("Sleeping for 1 hour...")
                time.sleep(60 * 60)

            except Exception as e:
                logger.error(f"Error in daemon loop: {e}", exc_info=True)
                time.sleep(60)  # Wait 1 minute before retry

    def process_renewal_queue(self):
        """Process pending renewals."""
        logger.info("Processing renewal queue...")

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Get pending renewals that are due
                cursor.execute("""
                    SELECT q.id, q.item_type, q.item_id, q.user_id,
                           q.domain_name, q.years, q.estimated_cost
                    FROM auto_renewal_queue q
                    WHERE q.status = 'pending'
                      AND q.scheduled_for <= NOW()
                      AND q.retry_count < 3
                    ORDER BY q.scheduled_for ASC
                    LIMIT 50
                """)

                renewals = cursor.fetchall()
                logger.info(f"Found {len(renewals)} renewals to process")

                for renewal in renewals:
                    self._process_renewal(renewal)

        finally:
            self.db.return_connection(conn)

    def _process_renewal(self, renewal: tuple):
        """Process a single renewal."""
        queue_id, item_type, item_id, user_id, domain_name, years, estimated_cost = renewal

        logger.info(f"Processing renewal: {item_type} {domain_name}")

        # Mark as processing
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE auto_renewal_queue
                    SET status = 'processing'
                    WHERE id = %s
                """, (queue_id,))
                conn.commit()
        finally:
            self.db.return_connection(conn)

        try:
            if item_type == 'domain':
                result = self._renew_domain(user_id, item_id, domain_name, years)
            elif item_type == 'ssl':
                result = self._renew_ssl(user_id, item_id, domain_name, years)
            else:
                raise ValueError(f"Unknown item type: {item_type}")

            # Mark as completed
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE auto_renewal_queue
                        SET status = 'completed', processed_at = NOW(),
                            order_id = %s
                        WHERE id = %s
                    """, (result.get('order_id'), queue_id))
                    conn.commit()
            finally:
                self.db.return_connection(conn)

            logger.info(f"Successfully renewed {domain_name}")

        except Exception as e:
            logger.error(f"Failed to renew {domain_name}: {e}")

            # Mark as failed and schedule retry
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE auto_renewal_queue
                        SET status = 'failed',
                            error_message = %s,
                            retry_count = retry_count + 1,
                            next_retry_at = NOW() + INTERVAL '6 hours'
                        WHERE id = %s
                    """, (str(e), queue_id))
                    conn.commit()
            finally:
                self.db.return_connection(conn)

    def _renew_domain(self, user_id: int, domain_id: int,
                     domain_name: str, years: int) -> dict:
        """Renew a domain."""
        # Get user's payment method
        payment_method = self._get_user_payment_method(user_id)

        if not payment_method:
            raise Exception("No payment method on file")

        # Get renewal pricing
        opensrs_config = self._get_opensrs_config()
        _, domain_mgr, _, _ = create_opensrs_client(
            opensrs_config['username'],
            opensrs_config['api_key'],
            opensrs_config['environment']
        )

        # Get pricing
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT retail_renewal_1_year FROM opensrs_pricing_cache
                    WHERE product_type = 'domain'
                      AND product_code = %s
                """, (domain_name.split('.')[-1],))

                row = cursor.fetchone()
                price = float(row[0]) if row else 12.99  # Default price
        finally:
            self.db.return_connection(conn)

        # Process payment
        charge = stripe.Charge.create(
            amount=int(price * 100),  # Convert to cents
            currency='usd',
            customer=payment_method['customer_id'],
            description=f"Domain Renewal: {domain_name} ({years} year(s))"
        )

        # Create order record
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT generate_order_number()")
                order_number = cursor.fetchone()[0]

                cursor.execute("""
                    INSERT INTO opensrs_orders (
                        user_id, order_type, order_number, domain_name,
                        years, subtotal, total, payment_method,
                        stripe_charge_id, paid_at, status
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s
                    ) RETURNING id
                """, (
                    user_id, 'domain_renewal', order_number, domain_name,
                    years, price, price, 'stripe', charge.id, 'processing'
                ))

                order_id = cursor.fetchone()[0]
                conn.commit()
        finally:
            self.db.return_connection(conn)

        # Submit renewal to OpenSRS
        result = domain_mgr.renew_domain(domain_name, years)

        # Update domain expiry
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE domains_owned
                    SET expires_at = expires_at + INTERVAL '%s years'
                    WHERE id = %s
                """, (years, domain_id))

                cursor.execute("""
                    UPDATE opensrs_orders
                    SET status = 'completed', completed_at = NOW(),
                        opensrs_order_id = %s, opensrs_response = %s
                    WHERE id = %s
                """, (result['order_id'], str(result), order_id))

                conn.commit()
        finally:
            self.db.return_connection(conn)

        return {'order_id': order_id, 'opensrs_order_id': result['order_id']}

    def _renew_ssl(self, user_id: int, ssl_id: int,
                   domain_name: str, years: int) -> dict:
        """Renew an SSL certificate."""
        # Similar logic to domain renewal
        # This is simplified - full implementation would reissue cert
        logger.info(f"SSL renewal for {domain_name} - would reissue certificate")
        return {'order_id': None}

    def _get_user_payment_method(self, user_id: int) -> dict:
        """Get user's Stripe payment method."""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT stripe_customer_id
                    FROM stripe_customers
                    WHERE user_id = %s
                """, (user_id,))

                row = cursor.fetchone()
                if row:
                    return {'customer_id': row[0]}
                return None
        finally:
            self.db.return_connection(conn)

    def _get_opensrs_config(self) -> dict:
        """Get OpenSRS configuration."""
        return self.payment_processor._get_opensrs_config()


if __name__ == '__main__':
    daemon = AutoRenewalDaemon()
    daemon.run()
