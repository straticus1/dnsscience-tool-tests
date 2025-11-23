"""Custom Scanner Module for DNS Science Platform

Provides user-created scan profiles with:
- Scanner CRUD operations
- Target domain management
- Execution engine
- Alert threshold checking
- Notification triggering
- Subscription tier limit enforcement
"""

import psycopg2
import psycopg2.extras
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from database import Database
from checkers import DomainScanner
from email_sender import EmailSender


class CustomScannerManager:
    """Manages custom scanner operations"""

    def __init__(self, db: Database = None):
        """
        Initialize custom scanner manager.

        Args:
            db: Optional Database instance
        """
        self.db = db if db else Database()
        self.scanner = DomainScanner()
        self.email_sender = EmailSender()

    def create_scanner(
        self,
        user_id: int,
        scanner_name: str,
        description: str = None,
        scan_options: Dict = None,
        schedule_type: str = 'manual',
        schedule_cron: str = None,
        alert_thresholds: Dict = None,
        notification_emails: List[str] = None,
        notification_webhooks: List[str] = None
    ) -> Dict:
        """
        Create a new custom scanner.

        Args:
            user_id: User ID
            scanner_name: Scanner name (unique per user)
            description: Optional description
            scan_options: Dict of checks to enable
            schedule_type: manual, hourly, daily, weekly, monthly, custom
            schedule_cron: Cron expression for custom schedules
            alert_thresholds: Dict of alert conditions
            notification_emails: List of email addresses
            notification_webhooks: List of webhook URLs

        Returns:
            Created scanner dict

        Raises:
            ValueError: If quota exceeded or invalid parameters
        """
        # Check quota
        quota_check = self.check_quota(user_id, 'scanner_count')
        if not quota_check['can_create_scanner']:
            raise ValueError(f"Scanner quota exceeded. You have {quota_check['usage']['current_scanners']} "
                           f"of {quota_check['limits']['max_scanners']} scanners.")

        # Validate schedule
        valid_schedules = ['manual', 'hourly', 'daily', 'weekly', 'monthly', 'custom']
        if schedule_type not in valid_schedules:
            raise ValueError(f"Invalid schedule_type. Must be one of: {', '.join(valid_schedules)}")

        if schedule_type == 'custom' and not schedule_cron:
            raise ValueError("schedule_cron required for custom schedule type")

        # Set defaults
        if scan_options is None:
            scan_options = {
                "dnssec": True,
                "spf": True,
                "dkim": True,
                "dmarc": True,
                "ssl": True,
                "caa": True,
                "bimi": False,
                "tlsa": False,
                "mta_sts": True
            }

        if alert_thresholds is None:
            alert_thresholds = {
                "cert_expiry_days": 30,
                "spf_changed": True,
                "dkim_changed": True,
                "dnssec_validation_failed": True,
                "ssl_grade_degraded": True,
                "new_threat_intel_match": True,
                "dmarc_policy_changed": True
            }

        if notification_emails is None:
            notification_emails = []

        if notification_webhooks is None:
            notification_webhooks = []

        # Calculate next run time
        next_run_at = None
        if schedule_type != 'manual':
            next_run_at = self._calculate_next_run(schedule_type, schedule_cron)

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    INSERT INTO custom_scanners (
                        user_id, scanner_name, description, scan_options,
                        schedule_type, schedule_cron, alert_thresholds,
                        notification_emails, notification_webhooks, next_run_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING *
                """, (
                    user_id, scanner_name, description, json.dumps(scan_options),
                    schedule_type, schedule_cron, json.dumps(alert_thresholds),
                    notification_emails, notification_webhooks, next_run_at
                ))

                scanner = dict(cursor.fetchone())
                conn.commit()

                # Parse JSON fields
                scanner['scan_options'] = json.loads(scanner['scan_options'])
                scanner['alert_thresholds'] = json.loads(scanner['alert_thresholds'])

                return scanner
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            raise ValueError(f"Scanner with name '{scanner_name}' already exists")
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.db.return_connection(conn)

    def get_scanner(self, scanner_id: int, user_id: int = None) -> Optional[Dict]:
        """
        Get scanner by ID.

        Args:
            scanner_id: Scanner ID
            user_id: Optional user ID for ownership check

        Returns:
            Scanner dict or None
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                if user_id:
                    cursor.execute("""
                        SELECT * FROM custom_scanners
                        WHERE id = %s AND user_id = %s
                    """, (scanner_id, user_id))
                else:
                    cursor.execute("""
                        SELECT * FROM custom_scanners
                        WHERE id = %s
                    """, (scanner_id,))

                row = cursor.fetchone()
                if not row:
                    return None

                scanner = dict(row)
                scanner['scan_options'] = json.loads(scanner['scan_options'])
                scanner['alert_thresholds'] = json.loads(scanner['alert_thresholds'])

                return scanner
        finally:
            self.db.return_connection(conn)

    def list_scanners(self, user_id: int, include_stats: bool = False) -> List[Dict]:
        """
        List all scanners for a user.

        Args:
            user_id: User ID
            include_stats: Include execution statistics

        Returns:
            List of scanner dicts
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                if include_stats:
                    cursor.execute("""
                        SELECT * FROM scanner_statistics
                        WHERE user_id = %s
                        ORDER BY scanner_name
                    """, (user_id,))
                else:
                    cursor.execute("""
                        SELECT * FROM custom_scanners
                        WHERE user_id = %s
                        ORDER BY scanner_name
                    """, (user_id,))

                scanners = [dict(row) for row in cursor.fetchall()]

                # Parse JSON fields
                for scanner in scanners:
                    if 'scan_options' in scanner:
                        scanner['scan_options'] = json.loads(scanner['scan_options'])
                    if 'alert_thresholds' in scanner:
                        scanner['alert_thresholds'] = json.loads(scanner['alert_thresholds'])

                return scanners
        finally:
            self.db.return_connection(conn)

    def update_scanner(
        self,
        scanner_id: int,
        user_id: int,
        updates: Dict
    ) -> Dict:
        """
        Update scanner settings.

        Args:
            scanner_id: Scanner ID
            user_id: User ID
            updates: Dictionary of fields to update

        Returns:
            Updated scanner dict
        """
        # Only allow certain fields to be updated
        allowed_fields = [
            'scanner_name', 'description', 'is_enabled', 'scan_options',
            'schedule_type', 'schedule_cron', 'alert_thresholds',
            'notification_emails', 'notification_webhooks'
        ]

        update_fields = []
        params = []
        param_counter = 1

        for field, value in updates.items():
            if field in allowed_fields:
                # Convert dicts/lists to JSON for JSONB fields
                if field in ['scan_options', 'alert_thresholds']:
                    value = json.dumps(value)

                update_fields.append(f"{field} = ${param_counter}")
                params.append(value)
                param_counter += 1

        if not update_fields:
            raise ValueError("No valid fields to update")

        # Add scanner_id and user_id
        params.extend([scanner_id, user_id])

        update_sql = f"""
            UPDATE custom_scanners
            SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ${param_counter} AND user_id = ${param_counter + 1}
            RETURNING *
        """

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(update_sql, params)
                row = cursor.fetchone()

                if not row:
                    raise ValueError("Scanner not found or access denied")

                scanner = dict(row)
                conn.commit()

                scanner['scan_options'] = json.loads(scanner['scan_options'])
                scanner['alert_thresholds'] = json.loads(scanner['alert_thresholds'])

                return scanner
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.db.return_connection(conn)

    def delete_scanner(self, scanner_id: int, user_id: int) -> bool:
        """
        Delete a scanner (soft delete).

        Args:
            scanner_id: Scanner ID
            user_id: User ID

        Returns:
            True if deleted
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE custom_scanners
                    SET status = 'deleted', is_enabled = FALSE
                    WHERE id = %s AND user_id = %s
                """, (scanner_id, user_id))

                deleted = cursor.rowcount > 0
                conn.commit()
                return deleted
        finally:
            self.db.return_connection(conn)

    def add_target(
        self,
        scanner_id: int,
        domain_name: str,
        user_id: int = None,
        notes: str = None,
        tags: List[str] = None
    ) -> Dict:
        """
        Add target domain to scanner.

        Args:
            scanner_id: Scanner ID
            domain_name: Domain to scan
            user_id: User ID for ownership check
            notes: Optional notes
            tags: Optional tags

        Returns:
            Target dict
        """
        # Check quota for targets
        if user_id:
            quota_check = self.check_quota(user_id, 'target_count')
            scanner = self.get_scanner(scanner_id, user_id)
            if scanner:
                current_targets = self.get_target_count(scanner_id)
                max_targets = quota_check['limits']['max_targets_per_scanner']

                if current_targets >= max_targets:
                    raise ValueError(f"Target quota exceeded. Maximum {max_targets} targets per scanner.")

        if tags is None:
            tags = []

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    INSERT INTO custom_scanner_targets (
                        scanner_id, domain_name, added_by_user_id, notes, tags
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (scanner_id, domain_name) DO UPDATE
                    SET is_active = TRUE
                    RETURNING *
                """, (scanner_id, domain_name.lower(), user_id, notes, tags))

                target = dict(cursor.fetchone())
                conn.commit()
                return target
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.db.return_connection(conn)

    def remove_target(self, scanner_id: int, domain_name: str) -> bool:
        """
        Remove target from scanner.

        Args:
            scanner_id: Scanner ID
            domain_name: Domain name

        Returns:
            True if removed
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE custom_scanner_targets
                    SET is_active = FALSE
                    WHERE scanner_id = %s AND domain_name = %s
                """, (scanner_id, domain_name.lower()))

                removed = cursor.rowcount > 0
                conn.commit()
                return removed
        finally:
            self.db.return_connection(conn)

    def list_targets(self, scanner_id: int) -> List[Dict]:
        """
        List all targets for a scanner.

        Args:
            scanner_id: Scanner ID

        Returns:
            List of target dicts
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM custom_scanner_targets
                    WHERE scanner_id = %s AND is_active = TRUE
                    ORDER BY domain_name
                """, (scanner_id,))

                return [dict(row) for row in cursor.fetchall()]
        finally:
            self.db.return_connection(conn)

    def get_target_count(self, scanner_id: int) -> int:
        """Get count of active targets for scanner."""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) FROM custom_scanner_targets
                    WHERE scanner_id = %s AND is_active = TRUE
                """, (scanner_id,))
                return cursor.fetchone()[0]
        finally:
            self.db.return_connection(conn)

    def run_scanner(
        self,
        scanner_id: int,
        user_id: int = None,
        trigger_type: str = 'manual'
    ) -> Dict:
        """
        Execute a scanner on all its targets.

        Args:
            scanner_id: Scanner ID
            user_id: User ID for quota check
            trigger_type: manual, scheduled, api, webhook

        Returns:
            Execution result dict
        """
        # Check quota
        if user_id:
            quota_check = self.check_quota(user_id, 'monthly_scans')
            if not quota_check['can_run_scan']:
                raise ValueError(f"Monthly scan quota exceeded. You have used "
                               f"{quota_check['usage']['current_monthly_scans']} "
                               f"of {quota_check['limits']['max_scans_per_month']} scans this month.")

        # Get scanner and targets
        scanner = self.get_scanner(scanner_id)
        if not scanner:
            raise ValueError("Scanner not found")

        if not scanner['is_enabled'] or scanner['status'] != 'active':
            raise ValueError("Scanner is not active")

        targets = self.list_targets(scanner_id)
        if not targets:
            raise ValueError("No targets configured for this scanner")

        # Initialize result
        result = {
            'scanner_id': scanner_id,
            'total_domains': len(targets),
            'successful_scans': 0,
            'failed_scans': 0,
            'skipped_scans': 0,
            'alerts_triggered': 0,
            'critical_alerts': 0,
            'warning_alerts': 0,
            'info_alerts': 0,
            'execution_time_ms': 0,
            'results_summary': {},
            'alerts_data': [],
            'error_log': []
        }

        start_time = datetime.now()

        # Execute scans
        scan_options = scanner['scan_options']
        for target in targets:
            domain_name = target['domain_name']

            try:
                # Perform scan
                scan_result = self.scanner.scan_domain(
                    domain_name,
                    check_ssl=scan_options.get('ssl', True)
                )

                # Save to database
                self.db.save_scan_result(domain_name, scan_result)

                # Check for alerts
                alerts = self._check_alerts(scanner, target, scan_result)
                for alert in alerts:
                    self._create_alert(scanner_id, None, domain_name, alert)
                    result['alerts_triggered'] += 1

                    if alert['severity'] == 'critical':
                        result['critical_alerts'] += 1
                    elif alert['severity'] == 'warning':
                        result['warning_alerts'] += 1
                    else:
                        result['info_alerts'] += 1

                result['alerts_data'].extend(alerts)
                result['successful_scans'] += 1

                # Update target status
                self._update_target_status(target['id'], 'success', None)

            except Exception as e:
                result['failed_scans'] += 1
                error_msg = f"{domain_name}: {str(e)}"
                result['error_log'].append(error_msg)
                self._update_target_status(target['id'], 'failed', str(e))

        # Calculate execution time
        execution_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        result['execution_time_ms'] = execution_time_ms
        result['avg_scan_time_ms'] = execution_time_ms // result['total_domains'] if result['total_domains'] > 0 else 0

        # Save execution result
        result_id = self._save_execution_result(scanner_id, result, trigger_type, user_id)
        result['result_id'] = result_id

        # Send notifications if alerts triggered
        if result['alerts_triggered'] > 0:
            self._send_notifications(scanner, result)

        return result

    def get_scanner_results(
        self,
        scanner_id: int,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get execution history for scanner.

        Args:
            scanner_id: Scanner ID
            limit: Max results

        Returns:
            List of execution result dicts
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM custom_scanner_results
                    WHERE scanner_id = %s
                    ORDER BY scan_timestamp DESC
                    LIMIT %s
                """, (scanner_id, limit))

                results = [dict(row) for row in cursor.fetchall()]

                # Parse JSON fields
                for result in results:
                    if result.get('results_summary'):
                        result['results_summary'] = json.loads(result['results_summary'])
                    if result.get('alerts_data'):
                        result['alerts_data'] = json.loads(result['alerts_data'])

                return results
        finally:
            self.db.return_connection(conn)

    def get_scanner_alerts(
        self,
        scanner_id: int,
        unacknowledged_only: bool = False,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get alerts for scanner.

        Args:
            scanner_id: Scanner ID
            unacknowledged_only: Only return unacknowledged alerts
            limit: Max results

        Returns:
            List of alert dicts
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                if unacknowledged_only:
                    cursor.execute("""
                        SELECT * FROM custom_scanner_alerts
                        WHERE scanner_id = %s AND acknowledged = FALSE
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (scanner_id, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM custom_scanner_alerts
                        WHERE scanner_id = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (scanner_id, limit))

                alerts = [dict(row) for row in cursor.fetchall()]

                # Parse metadata JSON
                for alert in alerts:
                    if alert.get('metadata'):
                        alert['metadata'] = json.loads(alert['metadata'])

                return alerts
        finally:
            self.db.return_connection(conn)

    def check_quota(self, user_id: int, check_type: str = 'scanner_count') -> Dict:
        """
        Check user's scanner quota.

        Args:
            user_id: User ID
            check_type: scanner_count, target_count, monthly_scans

        Returns:
            Quota information dict
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT check_scanner_quota(%s, %s)", (user_id, check_type))
                result = cursor.fetchone()[0]
                return result
        finally:
            self.db.return_connection(conn)

    def _calculate_next_run(self, schedule_type: str, schedule_cron: str = None) -> Optional[datetime]:
        """Calculate next run time based on schedule."""
        now = datetime.now()

        if schedule_type == 'hourly':
            return now + timedelta(hours=1)
        elif schedule_type == 'daily':
            return now + timedelta(days=1)
        elif schedule_type == 'weekly':
            return now + timedelta(weeks=1)
        elif schedule_type == 'monthly':
            return now + timedelta(days=30)
        elif schedule_type == 'custom' and schedule_cron:
            # For cron parsing, would need croniter library
            # For now, return next hour
            return now + timedelta(hours=1)
        else:
            return None

    def _check_alerts(self, scanner: Dict, target: Dict, scan_result: Dict) -> List[Dict]:
        """Check scan result against alert thresholds."""
        alerts = []
        thresholds = scanner['alert_thresholds']

        # Certificate expiry alert
        if thresholds.get('cert_expiry_days') and 'ssl_certificates' in scan_result:
            for cert in scan_result.get('ssl_certificates', []):
                days_until_expiry = cert.get('days_until_expiry')
                if days_until_expiry is not None and days_until_expiry <= thresholds['cert_expiry_days']:
                    alerts.append({
                        'alert_type': 'cert_expiring',
                        'severity': 'critical' if days_until_expiry <= 7 else 'warning',
                        'title': f'Certificate expiring in {days_until_expiry} days',
                        'message': f"SSL certificate for {target['domain_name']} expires in {days_until_expiry} days",
                        'metadata': cert
                    })

        # DNSSEC validation failed
        if thresholds.get('dnssec_validation_failed') and not scan_result.get('dnssec_valid'):
            alerts.append({
                'alert_type': 'dnssec_failed',
                'severity': 'warning',
                'title': 'DNSSEC validation failed',
                'message': f"DNSSEC validation failed for {target['domain_name']}",
                'metadata': {'dnssec_details': scan_result.get('dnssec_details')}
            })

        # SPF validation failed
        if thresholds.get('spf_changed') and not scan_result.get('spf_valid'):
            alerts.append({
                'alert_type': 'spf_invalid',
                'severity': 'warning',
                'title': 'SPF validation failed',
                'message': f"SPF record invalid for {target['domain_name']}",
                'metadata': {'spf_details': scan_result.get('spf_details')}
            })

        # Security score threshold
        if scan_result.get('security_score') is not None:
            if scan_result['security_score'] < 70:
                alerts.append({
                    'alert_type': 'low_security_score',
                    'severity': 'critical' if scan_result['security_score'] < 50 else 'warning',
                    'title': f"Low security score: {scan_result['security_score']}",
                    'message': f"Security score for {target['domain_name']} is {scan_result['security_score']}/100",
                    'metadata': {'score': scan_result['security_score'], 'grade': scan_result.get('security_grade')}
                })

        return alerts

    def _create_alert(self, scanner_id: int, result_id: int, domain_name: str, alert_data: Dict):
        """Create alert record in database."""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO custom_scanner_alerts (
                        scanner_id, result_id, domain_name,
                        alert_type, severity, title, message, metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    scanner_id, result_id, domain_name,
                    alert_data['alert_type'],
                    alert_data['severity'],
                    alert_data['title'],
                    alert_data['message'],
                    json.dumps(alert_data.get('metadata', {}))
                ))
                conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"Error creating alert: {e}")
        finally:
            self.db.return_connection(conn)

    def _save_execution_result(self, scanner_id: int, result: Dict, trigger_type: str, user_id: int) -> int:
        """Save execution result to database."""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO custom_scanner_results (
                        scanner_id, total_domains, successful_scans, failed_scans,
                        skipped_scans, alerts_triggered, critical_alerts,
                        warning_alerts, info_alerts, execution_time_ms,
                        avg_scan_time_ms, results_summary, alerts_data,
                        error_log, execution_status, trigger_type, triggered_by_user_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s
                    ) RETURNING id
                """, (
                    scanner_id,
                    result['total_domains'],
                    result['successful_scans'],
                    result['failed_scans'],
                    result['skipped_scans'],
                    result['alerts_triggered'],
                    result['critical_alerts'],
                    result['warning_alerts'],
                    result['info_alerts'],
                    result['execution_time_ms'],
                    result['avg_scan_time_ms'],
                    json.dumps(result.get('results_summary', {})),
                    json.dumps(result.get('alerts_data', [])),
                    result['error_log'],
                    'completed',
                    trigger_type,
                    user_id
                ))

                result_id = cursor.fetchone()[0]
                conn.commit()
                return result_id
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.db.return_connection(conn)

    def _update_target_status(self, target_id: int, status: str, error: str):
        """Update target scan status."""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE custom_scanner_targets
                    SET last_scanned_at = CURRENT_TIMESTAMP,
                        last_scan_status = %s,
                        last_scan_error = %s
                    WHERE id = %s
                """, (status, error, target_id))
                conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"Error updating target status: {e}")
        finally:
            self.db.return_connection(conn)

    def _send_notifications(self, scanner: Dict, result: Dict):
        """Send email/webhook notifications for alerts."""
        try:
            # Send emails
            if scanner.get('notification_emails'):
                for email in scanner['notification_emails']:
                    self.email_sender.send_scanner_alert(
                        to_email=email,
                        scanner_name=scanner['scanner_name'],
                        result=result
                    )

            # Send webhooks (would need webhook sender implementation)
            # if scanner.get('notification_webhooks'):
            #     for webhook_url in scanner['notification_webhooks']:
            #         self._send_webhook(webhook_url, result)

        except Exception as e:
            print(f"Error sending notifications: {e}")
