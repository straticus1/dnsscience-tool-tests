#!/usr/bin/env python3
"""
Domain Expiry Monitoring Daemon

Monitors domains for upcoming expiration and sends notifications.
Schedules auto-renewals for domains with auto-renew enabled.

Run frequency: Every 6 hours
Author: DNS Science Development Team
Version: 1.0.0
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from email_system import SESSender
import logging
from datetime import datetime, timedelta
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DomainExpiryDaemon:
    """Monitor and notify about expiring domains."""

    def __init__(self):
        self.db = Database()
        self.email_system = SESSender()

    def run(self):
        """Main daemon loop."""
        logger.info("Domain Expiry Daemon started")

        while True:
            try:
                self.check_expiring_domains()
                self.process_notification_queue()
                self.schedule_auto_renewals()

                # Sleep for 6 hours
                logger.info("Sleeping for 6 hours...")
                time.sleep(6 * 60 * 60)

            except Exception as e:
                logger.error(f"Error in daemon loop: {e}", exc_info=True)
                time.sleep(60)  # Wait 1 minute before retry

    def check_expiring_domains(self):
        """Check for domains expiring soon and create notifications."""
        logger.info("Checking for expiring domains...")

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Get domains expiring in 90, 30, 7, or 1 days
                cursor.execute("""
                    SELECT d.id, d.user_id, d.domain_name, d.expires_at,
                           u.email, u.username,
                           EXTRACT(DAY FROM (d.expires_at - NOW())) as days_remaining
                    FROM domains_owned d
                    JOIN users u ON d.user_id = u.id
                    WHERE d.status = 'active'
                      AND d.expires_at <= NOW() + INTERVAL '90 days'
                      AND d.expires_at > NOW()
                    ORDER BY d.expires_at ASC
                """)

                domains = cursor.fetchall()
                logger.info(f"Found {len(domains)} domains expiring in next 90 days")

                for domain in domains:
                    self._create_notifications_if_needed(domain)

                conn.commit()

        finally:
            self.db.return_connection(conn)

    def _create_notifications_if_needed(self, domain: tuple):
        """Create notification records for a domain if they don't exist."""
        domain_id, user_id, domain_name, expires_at, email, username, days_remaining = domain

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Check which notifications need to be created
                notification_types = []

                if days_remaining <= 1:
                    notification_types.append(('1_day', expires_at - timedelta(days=1)))
                if days_remaining <= 7:
                    notification_types.append(('7_days', expires_at - timedelta(days=7)))
                if days_remaining <= 30:
                    notification_types.append(('30_days', expires_at - timedelta(days=30)))
                if days_remaining <= 90:
                    notification_types.append(('90_days', expires_at - timedelta(days=90)))

                for notif_type, scheduled_for in notification_types:
                    # Check if notification already exists
                    cursor.execute("""
                        SELECT id FROM domain_expiry_notifications
                        WHERE domain_id = %s
                          AND notification_type = %s
                          AND status IN ('pending', 'sent')
                    """, (domain_id, notif_type))

                    if cursor.fetchone() is None:
                        # Create notification
                        cursor.execute("""
                            INSERT INTO domain_expiry_notifications (
                                domain_id, user_id, notification_type,
                                scheduled_for, delivery_method, recipient, status
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """, (
                            domain_id, user_id, notif_type,
                            scheduled_for, 'email', email, 'pending'
                        ))

                        logger.info(f"Created {notif_type} notification for {domain_name}")

                conn.commit()

        finally:
            self.db.return_connection(conn)

    def process_notification_queue(self):
        """Send pending notifications that are due."""
        logger.info("Processing notification queue...")

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Get pending notifications that are due
                cursor.execute("""
                    SELECT n.id, n.domain_id, n.user_id, n.notification_type,
                           n.recipient, d.domain_name, d.expires_at, u.username
                    FROM domain_expiry_notifications n
                    JOIN domains_owned d ON n.domain_id = d.id
                    JOIN users u ON n.user_id = u.id
                    WHERE n.status = 'pending'
                      AND n.scheduled_for <= NOW()
                    ORDER BY n.scheduled_for ASC
                    LIMIT 100
                """)

                notifications = cursor.fetchall()
                logger.info(f"Found {len(notifications)} notifications to send")

                for notif in notifications:
                    self._send_notification(notif)

                conn.commit()

        finally:
            self.db.return_connection(conn)

    def _send_notification(self, notification: tuple):
        """Send a single notification."""
        notif_id, domain_id, user_id, notif_type, recipient, domain_name, expires_at, username = notification

        try:
            # Calculate days remaining
            days_remaining = (expires_at - datetime.now()).days

            # Send email
            subject = f"Domain Expiring: {domain_name} expires in {days_remaining} days"
            body = f"""
Hello {username},

Your domain {domain_name} is expiring soon!

Expiration Date: {expires_at.strftime('%Y-%m-%d')}
Days Remaining: {days_remaining}

To prevent your domain from expiring, please renew it as soon as possible:
https://dnsscience.com/dashboard/domains/{domain_id}

If you have auto-renewal enabled, we will automatically renew your domain 30 days before expiration.

Best regards,
DNS Science Team
            """.strip()

            # Send via email system
            self.email_system.send_email(
                to_email=recipient,
                subject=subject,
                body=body,
                from_name="DNS Science Domains"
            )

            # Mark as sent
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE domain_expiry_notifications
                        SET status = 'sent', sent_at = NOW()
                        WHERE id = %s
                    """, (notif_id,))
                    conn.commit()
            finally:
                self.db.return_connection(conn)

            logger.info(f"Sent {notif_type} notification for {domain_name}")

        except Exception as e:
            logger.error(f"Failed to send notification {notif_id}: {e}")

            # Mark as failed
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE domain_expiry_notifications
                        SET status = 'failed', error_message = %s,
                            retry_count = retry_count + 1
                        WHERE id = %s
                    """, (str(e), notif_id))
                    conn.commit()
            finally:
                self.db.return_connection(conn)

    def schedule_auto_renewals(self):
        """Schedule auto-renewals for domains expiring in 30 days."""
        logger.info("Scheduling auto-renewals...")

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Get domains with auto-renew enabled expiring in 30 days
                cursor.execute("""
                    SELECT d.id, d.user_id, d.domain_name, d.expires_at
                    FROM domains_owned d
                    WHERE d.status = 'active'
                      AND d.auto_renew_enabled = true
                      AND d.expires_at <= NOW() + INTERVAL '30 days'
                      AND d.expires_at > NOW()
                      AND NOT EXISTS (
                          SELECT 1 FROM auto_renewal_queue
                          WHERE item_type = 'domain'
                            AND item_id = d.id
                            AND status IN ('pending', 'processing')
                      )
                """)

                domains = cursor.fetchall()
                logger.info(f"Found {len(domains)} domains to schedule for auto-renewal")

                for domain in domains:
                    domain_id, user_id, domain_name, expires_at = domain

                    # Schedule renewal 30 days before expiry
                    scheduled_for = expires_at - timedelta(days=30)

                    cursor.execute("""
                        INSERT INTO auto_renewal_queue (
                            item_type, item_id, user_id, domain_name,
                            years, scheduled_for, status
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        'domain', domain_id, user_id, domain_name,
                        1,  # Renew for 1 year
                        scheduled_for, 'pending'
                    ))

                    logger.info(f"Scheduled auto-renewal for {domain_name}")

                conn.commit()

        finally:
            self.db.return_connection(conn)


if __name__ == '__main__':
    daemon = DomainExpiryDaemon()
    daemon.run()
