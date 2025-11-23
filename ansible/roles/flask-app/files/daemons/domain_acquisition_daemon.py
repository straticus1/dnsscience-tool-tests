#!/usr/bin/env python3
"""
Domain Acquisition Monitoring Daemon

Monitors domains in the priority expiration registration queue and:
1. Checks domain status periodically (WHOIS/RDAP)
2. Tracks expiration timeline through grace/redemption/pending delete
3. Attempts automatic registration when domain becomes available
4. Notifies users of status changes
5. Manages broker requests for manual contact
"""

import os
import sys
import time
import logging
import whois
import re
from datetime import datetime, timedelta
from decimal import Decimal

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from config import Config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('domain_acquisition_daemon')


class DomainAcquisitionMonitor:
    """Monitor and automatically register expired/expiring domains"""

    def __init__(self):
        self.db = Database()
        self.check_interval = 3600  # Check every hour
        self.urgent_check_interval = 300  # Check every 5 minutes if close to available

    def run(self):
        """Main daemon loop"""
        logger.info("Domain Acquisition Monitor started")

        while True:
            try:
                self.process_monitoring_queue()
                time.sleep(self.check_interval)

            except KeyboardInterrupt:
                logger.info("Daemon stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(60)

    def process_monitoring_queue(self):
        """Process all domains in the monitoring queue"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Get domains being monitored, prioritize by proximity to deletion date
                cursor.execute("""
                    SELECT
                        id,
                        user_id,
                        domain_name,
                        status,
                        current_domain_status,
                        domain_deletion_date,
                        last_status_check,
                        registration_attempts,
                        broker_requested,
                        opensrs_order_id
                    FROM domain_acquisition_requests
                    WHERE status IN ('monitoring', 'registration_attempted')
                    AND domain_deletion_date IS NOT NULL
                    ORDER BY domain_deletion_date ASC
                    LIMIT 100
                """)

                requests = cursor.fetchall()

                logger.info(f"Processing {len(requests)} domains in monitoring queue")

                for req in requests:
                    try:
                        self.process_single_request(req)
                    except Exception as e:
                        logger.error(f"Error processing request {req[0]}: {e}")

        finally:
            self.db.return_connection(conn)

    def process_single_request(self, request_data):
        """Process a single domain acquisition request"""
        (request_id, user_id, domain_name, status, current_domain_status,
         domain_deletion_date, last_status_check, registration_attempts,
         broker_requested, opensrs_order_id) = request_data

        logger.info(f"Processing {domain_name} (ID: {request_id}, Status: {status})")

        # Calculate time until estimated deletion
        now = datetime.now()
        days_until_deletion = (domain_deletion_date - now).days if domain_deletion_date else 999

        # Determine check frequency based on urgency
        if days_until_deletion <= 1:
            # Check every 5 minutes if very close
            min_check_interval = timedelta(minutes=5)
        elif days_until_deletion <= 7:
            # Check every hour if within a week
            min_check_interval = timedelta(hours=1)
        elif days_until_deletion <= 30:
            # Check every 6 hours if within a month
            min_check_interval = timedelta(hours=6)
        else:
            # Check daily if further out
            min_check_interval = timedelta(days=1)

        # Skip if checked too recently
        if last_status_check and (now - last_status_check) < min_check_interval:
            logger.debug(f"Skipping {domain_name} - checked recently")
            return

        # Check current domain status
        domain_status_info = self.check_domain_status(domain_name)

        if not domain_status_info:
            logger.warning(f"Could not check status for {domain_name}")
            self.log_attempt(request_id, 'status_check', False,
                           error_message="WHOIS lookup failed")
            return

        # Log the status check
        self.log_attempt(request_id, 'status_check', True,
                       domain_status=domain_status_info.get('status'))

        # Update request with latest status
        self.update_request_status(request_id, domain_status_info)

        # If domain is available, attempt registration
        if domain_status_info.get('status') == 'available':
            logger.info(f"Domain {domain_name} is AVAILABLE! Attempting registration...")
            self.attempt_registration(request_id, user_id, domain_name)

        # If domain is in pending delete and very close, increase monitoring
        elif domain_status_info.get('status') == 'pending_delete' and days_until_deletion <= 5:
            logger.info(f"Domain {domain_name} in pending delete - high priority monitoring")

        # If broker requested and still registered, notify broker queue
        elif broker_requested and domain_status_info.get('status') == 'registered':
            self.handle_broker_request(request_id, domain_name, domain_status_info)

    def check_domain_status(self, domain):
        """
        Check current status of a domain via WHOIS

        Returns:
            {
                'status': 'available' | 'registered' | 'expired' | 'redemption' | 'pending_delete',
                'expiry_date': datetime,
                'registrar': str,
                'whois_status': list
            }
        """
        try:
            w = whois.whois(domain)

            # Check if domain is available
            if w.status is None or not w.expiration_date:
                return {
                    'status': 'available',
                    'expiry_date': None,
                    'registrar': None,
                    'whois_status': []
                }

            # Domain is registered - check expiration date
            expiry_date = w.expiration_date
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]

            # Check status codes
            statuses = w.status if isinstance(w.status, list) else [w.status]
            status_str = ' '.join(statuses).lower() if statuses else ''

            # Determine current lifecycle stage
            current_status = 'registered'

            if 'redemptionperiod' in status_str or 'redemption' in status_str:
                current_status = 'redemption'

            elif 'pendingdelete' in status_str or 'pending delete' in status_str:
                current_status = 'pending_delete'

            elif expiry_date and expiry_date < datetime.now():
                # Expired but not yet in redemption (grace period)
                current_status = 'expired'

            return {
                'status': current_status,
                'expiry_date': expiry_date,
                'registrar': w.registrar,
                'whois_status': statuses
            }

        except whois.parser.PywhoisError as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            # Domain might be available or WHOIS server issue
            return None

        except Exception as e:
            logger.error(f"Error checking domain status for {domain}: {e}")
            return None

    def update_request_status(self, request_id, status_info):
        """Update request with latest domain status information"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Calculate estimated deletion date based on current status
                estimated_deletion = None
                if status_info.get('expiry_date'):
                    expiry = status_info['expiry_date']
                    status = status_info['status']

                    if status == 'redemption':
                        # 30 days redemption + 5 days pending delete remaining
                        estimated_deletion = expiry + timedelta(days=35)
                    elif status == 'pending_delete':
                        # 5 days until available
                        estimated_deletion = expiry + timedelta(days=5)
                    elif status == 'expired':
                        # Could be in grace period (up to 45 days) + redemption (30) + pending (5)
                        estimated_deletion = expiry + timedelta(days=80)

                cursor.execute("""
                    UPDATE domain_acquisition_requests
                    SET
                        current_domain_status = %s,
                        domain_expiry_date = %s,
                        domain_deletion_date = %s,
                        last_status_check = NOW(),
                        check_count = check_count + 1
                    WHERE id = %s
                """, (
                    status_info.get('status'),
                    status_info.get('expiry_date'),
                    estimated_deletion,
                    request_id
                ))

                conn.commit()

        finally:
            self.db.return_connection(conn)

    def attempt_registration(self, request_id, user_id, domain_name):
        """
        Attempt to register a domain that has become available

        This integrates with OpenSRS to actually register the domain
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Update status to registration_attempted
                cursor.execute("""
                    UPDATE domain_acquisition_requests
                    SET
                        status = 'registration_attempted',
                        last_registration_attempt = NOW(),
                        registration_attempts = registration_attempts + 1
                    WHERE id = %s
                """, (request_id,))

                conn.commit()

                logger.info(f"Attempting to register {domain_name} for user {user_id}")

                # Try to register via OpenSRS
                registration_result = self.register_via_opensrs(domain_name, user_id)

                if registration_result.get('success'):
                    # Registration successful!
                    logger.info(f"Successfully registered {domain_name}!")

                    cursor.execute("""
                        UPDATE domain_acquisition_requests
                        SET
                            status = 'registration_successful',
                            registration_success_date = NOW(),
                            opensrs_order_id = %s,
                            opensrs_domain_id = %s,
                            completed_at = NOW()
                        WHERE id = %s
                    """, (
                        registration_result.get('order_id'),
                        registration_result.get('domain_id'),
                        request_id
                    ))

                    # Log successful attempt
                    self.log_attempt(request_id, 'registration_attempt', True,
                                   action_taken='Domain registered successfully via OpenSRS',
                                   domain_status='registered')

                    # TODO: Send success email to user
                    # TODO: Add domain to user_domains table

                else:
                    # Registration failed
                    logger.error(f"Failed to register {domain_name}: {registration_result.get('error')}")

                    cursor.execute("""
                        UPDATE domain_acquisition_requests
                        SET
                            status = 'registration_failed',
                            registration_error = %s
                        WHERE id = %s
                    """, (
                        registration_result.get('error'),
                        request_id
                    ))

                    # Log failed attempt
                    self.log_attempt(request_id, 'registration_attempt', False,
                                   error_message=registration_result.get('error'))

                    # TODO: Send failure notification to user

                conn.commit()

        finally:
            self.db.return_connection(conn)

    def register_via_opensrs(self, domain_name, user_id):
        """
        Register domain via OpenSRS API

        Returns:
            {'success': True, 'order_id': '...', 'domain_id': '...'}
            or
            {'success': False, 'error': 'error message'}
        """
        try:
            from opensrs_integration import create_opensrs_client

            # Initialize OpenSRS client
            client, domain_mgr, ssl_mgr, dns_mgr = create_opensrs_client(
                Config.OPENSRS_USERNAME,
                Config.OPENSRS_API_KEY,
                Config.OPENSRS_ENVIRONMENT
            )

            # Get user contact information
            user_info = self.get_user_contact_info(user_id)

            if not user_info:
                return {'success': False, 'error': 'User contact information not found'}

            # Attempt domain registration
            result = domain_mgr.register_domain(
                domain=domain_name,
                years=1,
                contact_info=user_info
            )

            if result.get('success'):
                return {
                    'success': True,
                    'order_id': result.get('order_id'),
                    'domain_id': result.get('domain_id')
                }
            else:
                return {
                    'success': False,
                    'error': result.get('error', 'Unknown error')
                }

        except Exception as e:
            logger.error(f"OpenSRS registration error: {e}")
            return {'success': False, 'error': str(e)}

    def get_user_contact_info(self, user_id):
        """Get user contact information for domain registration"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT email, username
                    FROM users
                    WHERE id = %s
                """, (user_id,))

                result = cursor.fetchone()

                if result:
                    return {
                        'email': result[0],
                        'name': result[1]
                    }
                return None

        finally:
            self.db.return_connection(conn)

    def handle_broker_request(self, request_id, domain_name, status_info):
        """
        Handle domains where user requested broker service

        This marks them for manual broker contact
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE domain_acquisition_requests
                    SET broker_status = 'pending'
                    WHERE id = %s AND broker_status IS NULL
                """, (request_id,))

                if cursor.rowcount > 0:
                    logger.info(f"Domain {domain_name} marked for broker contact")
                    # TODO: Add to broker queue/notification system

                conn.commit()

        finally:
            self.db.return_connection(conn)

    def log_attempt(self, request_id, attempt_type, success,
                   domain_status=None, error_message=None, action_taken=None):
        """Log an acquisition attempt to the database"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Calculate next check time
                next_check = datetime.now() + timedelta(hours=1)

                cursor.execute("""
                    INSERT INTO domain_acquisition_attempts (
                        request_id,
                        attempt_type,
                        success,
                        domain_status,
                        error_message,
                        action_taken,
                        next_check_scheduled
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    request_id,
                    attempt_type,
                    success,
                    domain_status,
                    error_message,
                    action_taken,
                    next_check
                ))

                conn.commit()

        finally:
            self.db.return_connection(conn)


if __name__ == '__main__':
    monitor = DomainAcquisitionMonitor()
    monitor.run()
