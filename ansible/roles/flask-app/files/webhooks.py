#!/usr/bin/env python3
"""
Webhook System for DNS Science
Allows users to receive real-time notifications via HTTP callbacks
"""

import os
import json
import hmac
import hashlib
import logging
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('webhooks')


class WebhookManager:
    """Manage webhook subscriptions and deliveries"""

    # Supported event types
    EVENTS = [
        'certificate.expiring',
        'certificate.expired',
        'certificate.renewed',
        'domain.scanned',
        'domain.added',
        'threat.detected',
        'anomaly.detected',
        'scan.completed',
        'deliverability.scored'
    ]

    def __init__(self):
        self.db = Database()
        self.timeout = 30  # HTTP timeout in seconds
        self.max_retries = 3

    def create_webhook(self, user_id: int, webhook_url: str,
                      events: List[str], secret_key: Optional[str] = None) -> Dict[str, Any]:
        """Create a new webhook subscription"""

        # Validate events
        invalid_events = [e for e in events if e not in self.EVENTS]
        if invalid_events:
            return {
                'success': False,
                'error': f'Invalid events: {", ".join(invalid_events)}'
            }

        # Generate secret key if not provided
        if not secret_key:
            secret_key = self._generate_secret_key()

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO webhook_subscriptions
                    (user_id, webhook_url, secret_key, events, is_active)
                    VALUES (%s, %s, %s, %s::jsonb, true)
                    ON CONFLICT (user_id, webhook_url)
                    DO UPDATE SET
                        secret_key = EXCLUDED.secret_key,
                        events = EXCLUDED.events,
                        is_active = true,
                        updated_at = NOW()
                    RETURNING id, secret_key
                """, (user_id, webhook_url, secret_key, json.dumps(events)))

                webhook_id, secret = cursor.fetchone()
                conn.commit()

                # Send test/verification webhook
                self._send_verification_webhook(webhook_id, webhook_url, secret)

                return {
                    'success': True,
                    'webhook_id': webhook_id,
                    'webhook_url': webhook_url,
                    'secret_key': secret,
                    'events': events,
                    'message': 'Webhook created. Check your endpoint for verification request.'
                }

        except Exception as e:
            conn.rollback()
            logger.error(f"Error creating webhook: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            self.db.return_connection(conn)

    def delete_webhook(self, user_id: int, webhook_id: int) -> Dict[str, Any]:
        """Delete a webhook subscription"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE webhook_subscriptions
                    SET is_active = false, updated_at = NOW()
                    WHERE id = %s AND user_id = %s
                    RETURNING id
                """, (webhook_id, user_id))

                result = cursor.fetchone()
                conn.commit()

                if result:
                    return {'success': True, 'message': 'Webhook deleted'}
                else:
                    return {'success': False, 'error': 'Webhook not found'}

        except Exception as e:
            conn.rollback()
            logger.error(f"Error deleting webhook: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            self.db.return_connection(conn)

    def get_user_webhooks(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all webhooks for a user"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        id,
                        webhook_url,
                        events,
                        is_active,
                        is_verified,
                        verified_at,
                        total_deliveries,
                        failed_deliveries,
                        last_delivery_at,
                        last_delivery_status,
                        created_at
                    FROM webhook_subscriptions
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))

                webhooks = []
                for row in cursor.fetchall():
                    webhooks.append({
                        'id': row[0],
                        'webhook_url': row[1],
                        'events': row[2],
                        'is_active': row[3],
                        'is_verified': row[4],
                        'verified_at': row[5],
                        'total_deliveries': row[6],
                        'failed_deliveries': row[7],
                        'last_delivery_at': row[8],
                        'last_delivery_status': row[9],
                        'created_at': row[10]
                    })

                return webhooks

        finally:
            self.db.return_connection(conn)

    def trigger_event(self, user_id: int, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger a webhook event for a user"""

        if event_type not in self.EVENTS:
            return {'success': False, 'error': f'Invalid event type: {event_type}'}

        conn = self.db.get_connection()
        deliveries_created = 0

        try:
            with conn.cursor() as cursor:
                # Find all active webhooks for this user/event
                cursor.execute("""
                    SELECT id, webhook_url, secret_key
                    FROM webhook_subscriptions
                    WHERE user_id = %s
                    AND is_active = true
                    AND is_verified = true
                    AND %s = ANY(
                        SELECT jsonb_array_elements_text(events)
                    )
                """, (user_id, event_type))

                webhooks = cursor.fetchall()

                for webhook_id, webhook_url, secret_key in webhooks:
                    # Create delivery record
                    cursor.execute("""
                        INSERT INTO webhook_deliveries
                        (webhook_id, event_type, payload, status, created_at)
                        VALUES (%s, %s, %s::jsonb, 'pending', NOW())
                        RETURNING id
                    """, (webhook_id, event_type, json.dumps(payload)))

                    delivery_id = cursor.fetchone()[0]
                    deliveries_created += 1

                    # Attempt delivery asynchronously (in background)
                    # For now, we'll do it synchronously
                    self._deliver_webhook(delivery_id, webhook_url, secret_key, event_type, payload)

                conn.commit()

                return {
                    'success': True,
                    'event_type': event_type,
                    'deliveries_created': deliveries_created
                }

        except Exception as e:
            conn.rollback()
            logger.error(f"Error triggering webhook event: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            self.db.return_connection(conn)

    def _deliver_webhook(self, delivery_id: int, webhook_url: str,
                        secret_key: str, event_type: str, payload: Dict[str, Any]):
        """Deliver a single webhook"""

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Update delivery status to sent
                cursor.execute("""
                    UPDATE webhook_deliveries
                    SET status = 'sent', sent_at = NOW(), attempts = attempts + 1
                    WHERE id = %s
                """, (delivery_id,))
                conn.commit()

            # Prepare webhook payload
            timestamp = datetime.utcnow().isoformat() + 'Z'
            webhook_payload = {
                'event': event_type,
                'timestamp': timestamp,
                'data': payload
            }

            # Generate signature
            signature = self._generate_signature(webhook_payload, secret_key)

            # Send HTTP POST request
            headers = {
                'Content-Type': 'application/json',
                'X-DNSScience-Event': event_type,
                'X-DNSScience-Signature': signature,
                'X-DNSScience-Timestamp': timestamp,
                'User-Agent': 'DNSScience-Webhook/1.0'
            }

            response = requests.post(
                webhook_url,
                json=webhook_payload,
                headers=headers,
                timeout=self.timeout
            )

            # Update delivery status
            with conn.cursor() as cursor:
                if 200 <= response.status_code < 300:
                    cursor.execute("""
                        UPDATE webhook_deliveries
                        SET
                            status = 'success',
                            http_status_code = %s,
                            response_body = %s,
                            completed_at = NOW()
                        WHERE id = %s
                    """, (response.status_code, response.text[:1000], delivery_id))

                    # Update webhook stats
                    cursor.execute("""
                        UPDATE webhook_subscriptions
                        SET
                            total_deliveries = total_deliveries + 1,
                            last_delivery_at = NOW(),
                            last_delivery_status = 'success'
                        WHERE id = (
                            SELECT webhook_id FROM webhook_deliveries WHERE id = %s
                        )
                    """, (delivery_id,))

                    logger.info(f"Webhook delivery {delivery_id} succeeded: {response.status_code}")
                else:
                    cursor.execute("""
                        UPDATE webhook_deliveries
                        SET
                            status = 'failed',
                            http_status_code = %s,
                            response_body = %s,
                            error_message = %s,
                            completed_at = NOW()
                        WHERE id = %s
                    """, (response.status_code, response.text[:1000],
                         f'HTTP {response.status_code}', delivery_id))

                    # Update webhook stats
                    cursor.execute("""
                        UPDATE webhook_subscriptions
                        SET
                            failed_deliveries = failed_deliveries + 1,
                            last_delivery_at = NOW(),
                            last_delivery_status = 'failed'
                        WHERE id = (
                            SELECT webhook_id FROM webhook_deliveries WHERE id = %s
                        )
                    """, (delivery_id,))

                    logger.warning(f"Webhook delivery {delivery_id} failed: {response.status_code}")

                conn.commit()

        except requests.exceptions.Timeout:
            self._mark_delivery_failed(delivery_id, 'Timeout')
            logger.error(f"Webhook delivery {delivery_id} timed out")

        except requests.exceptions.RequestException as e:
            self._mark_delivery_failed(delivery_id, str(e))
            logger.error(f"Webhook delivery {delivery_id} failed: {e}")

        except Exception as e:
            self._mark_delivery_failed(delivery_id, str(e))
            logger.error(f"Unexpected error delivering webhook {delivery_id}: {e}")

        finally:
            self.db.return_connection(conn)

    def _mark_delivery_failed(self, delivery_id: int, error_message: str):
        """Mark a webhook delivery as failed"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE webhook_deliveries
                    SET
                        status = 'failed',
                        error_message = %s,
                        completed_at = NOW()
                    WHERE id = %s
                """, (error_message, delivery_id))

                cursor.execute("""
                    UPDATE webhook_subscriptions
                    SET
                        failed_deliveries = failed_deliveries + 1,
                        last_delivery_at = NOW(),
                        last_delivery_status = 'failed'
                    WHERE id = (
                        SELECT webhook_id FROM webhook_deliveries WHERE id = %s
                    )
                """, (delivery_id,))

                conn.commit()
        finally:
            self.db.return_connection(conn)

    def _send_verification_webhook(self, webhook_id: int, webhook_url: str, secret_key: str):
        """Send verification webhook"""
        payload = {
            'event': 'webhook.verification',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'data': {
                'webhook_id': webhook_id,
                'message': 'Webhook verification - respond with 200 OK to activate'
            }
        }

        try:
            signature = self._generate_signature(payload, secret_key)
            headers = {
                'Content-Type': 'application/json',
                'X-DNSScience-Event': 'webhook.verification',
                'X-DNSScience-Signature': signature,
                'User-Agent': 'DNSScience-Webhook/1.0'
            }

            response = requests.post(webhook_url, json=payload, headers=headers, timeout=10)

            if 200 <= response.status_code < 300:
                # Mark as verified
                conn = self.db.get_connection()
                try:
                    with conn.cursor() as cursor:
                        cursor.execute("""
                            UPDATE webhook_subscriptions
                            SET is_verified = true, verified_at = NOW()
                            WHERE id = %s
                        """, (webhook_id,))
                        conn.commit()
                    logger.info(f"Webhook {webhook_id} verified successfully")
                finally:
                    self.db.return_connection(conn)
        except Exception as e:
            logger.warning(f"Webhook verification failed for {webhook_id}: {e}")

    def _generate_signature(self, payload: Dict[str, Any], secret_key: str) -> str:
        """Generate HMAC signature for webhook payload"""
        payload_str = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            secret_key.encode('utf-8'),
            payload_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return signature

    def _generate_secret_key(self) -> str:
        """Generate a random secret key for webhook"""
        import secrets
        return secrets.token_urlsafe(32)

    @staticmethod
    def verify_webhook_signature(payload: Dict[str, Any], signature: str, secret_key: str) -> bool:
        """Verify webhook signature (for recipients to use)"""
        payload_str = json.dumps(payload, sort_keys=True)
        expected_signature = hmac.new(
            secret_key.encode('utf-8'),
            payload_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_signature)


if __name__ == '__main__':
    # Test webhook system
    manager = WebhookManager()

    # Example: Trigger a certificate expiration event
    result = manager.trigger_event(
        user_id=1,
        event_type='certificate.expiring',
        payload={
            'domain': 'example.com',
            'days_until_expiration': 7,
            'expiration_date': '2025-11-20T00:00:00Z'
        }
    )
    print(f"Event triggered: {result}")
