#!/usr/bin/env python3
"""
Historical Trending and Analytics for DNS Cache Validator
SQLite-based storage for tracking DNS changes over time
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


class DNSTrendingDatabase:
    """SQLite database for DNS historical tracking"""

    def __init__(self, db_path: str = 'dns_trending.db'):
        """
        Initialize trending database.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row  # Enable column access by name
        self._initialize_schema()

    def _initialize_schema(self):
        """Create database schema if it doesn't exist"""
        cursor = self.conn.cursor()

        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                record_type TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                total_queries INTEGER,
                successful_queries INTEGER,
                failed_queries INTEGER,
                consistency_score REAL,
                avg_response_time REAL,
                median_response_time REAL,
                unique_answers_count INTEGER,
                analysis_json TEXT,
                INDEX idx_domain (domain),
                INDEX idx_timestamp (timestamp)
            )
        ''')

        # Query results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS query_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                resolver_ip TEXT NOT NULL,
                country TEXT,
                provider TEXT,
                success BOOLEAN,
                answer TEXT,
                response_time REAL,
                error TEXT,
                timestamp DATETIME NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scan_history(id),
                INDEX idx_scan_id (scan_id),
                INDEX idx_resolver_ip (resolver_ip)
            )
        ''')

        # Resolver health tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resolver_health (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resolver_ip TEXT NOT NULL,
                provider TEXT,
                country TEXT,
                timestamp DATETIME NOT NULL,
                success_rate REAL,
                avg_response_time REAL,
                total_queries INTEGER,
                successful_queries INTEGER,
                UNIQUE(resolver_ip, timestamp)
            )
        ''')

        # Answer change events
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS answer_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                record_type TEXT NOT NULL,
                old_answer TEXT,
                new_answer TEXT,
                first_seen DATETIME NOT NULL,
                resolver_count INTEGER,
                INDEX idx_domain_changes (domain)
            )
        ''')

        self.conn.commit()

    def record_scan(
        self,
        domain: str,
        record_type: str,
        results: List[Dict],
        analysis: Dict
    ) -> int:
        """
        Record a DNS scan to the database.

        Args:
            domain: Domain that was scanned
            record_type: DNS record type
            results: Query results
            analysis: Analysis data

        Returns:
            Scan ID
        """
        cursor = self.conn.cursor()

        # Insert scan history
        cursor.execute('''
            INSERT INTO scan_history (
                domain, record_type, timestamp,
                total_queries, successful_queries, failed_queries,
                consistency_score, avg_response_time, median_response_time,
                unique_answers_count, analysis_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            domain,
            record_type,
            datetime.utcnow(),
            analysis['total_queries'],
            analysis['successful'],
            analysis['failed'],
            analysis['consistency_score'],
            analysis['avg_response_time'],
            analysis['median_response_time'],
            len(analysis['unique_answers']),
            json.dumps(analysis)
        ))

        scan_id = cursor.lastrowid

        # Insert individual query results
        for result in results:
            cursor.execute('''
                INSERT INTO query_results (
                    scan_id, resolver_ip, country, provider,
                    success, answer, response_time, error, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                result['resolver_ip'],
                result['country'],
                result['provider'],
                result['success'],
                json.dumps(result['answers']) if result['success'] else None,
                result.get('response_time'),
                result.get('error'),
                datetime.utcnow()
            ))

        self.conn.commit()
        return scan_id

    def get_domain_history(
        self,
        domain: str,
        days: int = 30,
        record_type: Optional[str] = None
    ) -> List[Dict]:
        """
        Get scan history for a domain.

        Args:
            domain: Domain to query
            days: Number of days to look back
            record_type: Optional record type filter

        Returns:
            List of scan history records
        """
        cursor = self.conn.cursor()

        since = datetime.utcnow() - timedelta(days=days)

        if record_type:
            cursor.execute('''
                SELECT * FROM scan_history
                WHERE domain = ? AND record_type = ? AND timestamp >= ?
                ORDER BY timestamp DESC
            ''', (domain, record_type, since))
        else:
            cursor.execute('''
                SELECT * FROM scan_history
                WHERE domain = ? AND timestamp >= ?
                ORDER BY timestamp DESC
            ''', (domain, since))

        return [dict(row) for row in cursor.fetchall()]

    def get_consistency_trend(
        self,
        domain: str,
        days: int = 30
    ) -> List[Tuple[datetime, float]]:
        """
        Get consistency score trend for a domain.

        Args:
            domain: Domain to analyze
            days: Number of days to analyze

        Returns:
            List of (timestamp, consistency_score) tuples
        """
        cursor = self.conn.cursor()

        since = datetime.utcnow() - timedelta(days=days)

        cursor.execute('''
            SELECT timestamp, consistency_score
            FROM scan_history
            WHERE domain = ? AND timestamp >= ?
            ORDER BY timestamp ASC
        ''', (domain, since))

        return [(row['timestamp'], row['consistency_score']) for row in cursor.fetchall()]

    def get_response_time_trend(
        self,
        domain: str,
        days: int = 30
    ) -> List[Tuple[datetime, float]]:
        """
        Get response time trend for a domain.

        Args:
            domain: Domain to analyze
            days: Number of days to analyze

        Returns:
            List of (timestamp, avg_response_time) tuples
        """
        cursor = self.conn.cursor()

        since = datetime.utcnow() - timedelta(days=days)

        cursor.execute('''
            SELECT timestamp, avg_response_time
            FROM scan_history
            WHERE domain = ? AND timestamp >= ? AND avg_response_time IS NOT NULL
            ORDER BY timestamp ASC
        ''', (domain, since))

        return [(row['timestamp'], row['avg_response_time']) for row in cursor.fetchall()]

    def track_resolver_health(self, results: List[Dict]):
        """
        Track resolver health metrics.

        Args:
            results: Query results
        """
        cursor = self.conn.cursor()

        # Aggregate by resolver
        resolver_stats = defaultdict(lambda: {
            'total': 0,
            'successful': 0,
            'response_times': []
        })

        for result in results:
            ip = result['resolver_ip']
            resolver_stats[ip]['total'] += 1
            if result['success']:
                resolver_stats[ip]['successful'] += 1
                if result.get('response_time'):
                    resolver_stats[ip]['response_times'].append(result['response_time'])

        # Insert health records
        for ip, stats in resolver_stats.items():
            success_rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
            avg_rt = sum(stats['response_times']) / len(stats['response_times']) \
                     if stats['response_times'] else None

            # Get resolver info from first result
            resolver_info = next((r for r in results if r['resolver_ip'] == ip), {})

            cursor.execute('''
                INSERT OR REPLACE INTO resolver_health (
                    resolver_ip, provider, country, timestamp,
                    success_rate, avg_response_time,
                    total_queries, successful_queries
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip,
                resolver_info.get('provider'),
                resolver_info.get('country'),
                datetime.utcnow(),
                success_rate,
                avg_rt,
                stats['total'],
                stats['successful']
            ))

        self.conn.commit()

    def get_resolver_health_history(
        self,
        resolver_ip: str,
        days: int = 30
    ) -> List[Dict]:
        """
        Get health history for a specific resolver.

        Args:
            resolver_ip: Resolver IP address
            days: Number of days to look back

        Returns:
            List of health records
        """
        cursor = self.conn.cursor()

        since = datetime.utcnow() - timedelta(days=days)

        cursor.execute('''
            SELECT * FROM resolver_health
            WHERE resolver_ip = ? AND timestamp >= ?
            ORDER BY timestamp DESC
        ''', (resolver_ip, since))

        return [dict(row) for row in cursor.fetchall()]

    def detect_answer_changes(
        self,
        domain: str,
        current_answers: Dict,
        threshold: int = 5
    ) -> List[Dict]:
        """
        Detect significant answer changes for a domain.

        Args:
            domain: Domain to check
            current_answers: Current unique answers
            threshold: Minimum resolver count to consider significant

        Returns:
            List of detected changes
        """
        # Get most recent scan
        history = self.get_domain_history(domain, days=1)
        if not history:
            return []

        last_scan = history[0]
        last_analysis = json.loads(last_scan['analysis_json'])
        last_answers = last_analysis.get('unique_answers', {})

        changes = []

        # Check for new answers
        for answer, data in current_answers.items():
            if answer not in last_answers and data['count'] >= threshold:
                changes.append({
                    'type': 'new_answer',
                    'answer': answer,
                    'resolver_count': data['count'],
                    'timestamp': datetime.utcnow()
                })

        # Check for removed answers
        for answer, data in last_answers.items():
            if answer not in current_answers and data['count'] >= threshold:
                changes.append({
                    'type': 'removed_answer',
                    'answer': answer,
                    'resolver_count': data['count'],
                    'timestamp': datetime.utcnow()
                })

        # Record changes to database
        if changes:
            cursor = self.conn.cursor()
            for change in changes:
                cursor.execute('''
                    INSERT INTO answer_changes (
                        domain, record_type, old_answer, new_answer,
                        first_seen, resolver_count
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    domain,
                    last_scan['record_type'],
                    change.get('answer') if change['type'] == 'removed_answer' else None,
                    change.get('answer') if change['type'] == 'new_answer' else None,
                    change['timestamp'],
                    change['resolver_count']
                ))
            self.conn.commit()

        return changes

    def get_top_failing_resolvers(self, days: int = 7, limit: int = 10) -> List[Dict]:
        """
        Get resolvers with worst health scores.

        Args:
            days: Number of days to analyze
            limit: Maximum number of resolvers to return

        Returns:
            List of resolver health summaries
        """
        cursor = self.conn.cursor()

        since = datetime.utcnow() - timedelta(days=days)

        cursor.execute('''
            SELECT
                resolver_ip,
                provider,
                country,
                AVG(success_rate) as avg_success_rate,
                AVG(avg_response_time) as avg_response_time,
                SUM(total_queries) as total_queries
            FROM resolver_health
            WHERE timestamp >= ?
            GROUP BY resolver_ip
            ORDER BY avg_success_rate ASC
            LIMIT ?
        ''', (since, limit))

        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        """Close database connection"""
        self.conn.close()


if __name__ == '__main__':
    # Test the trending database
    db = DNSTrendingDatabase('test_trending.db')

    print("DNS Trending Database initialized")
    print("Schema created successfully")

    # Example: Record a scan
    example_results = [
        {
            'resolver_ip': '8.8.8.8',
            'country': 'United States',
            'provider': 'Google',
            'success': True,
            'answers': ['93.184.216.34'],
            'response_time': 45.2
        }
    ]

    example_analysis = {
        'total_queries': 1,
        'successful': 1,
        'failed': 0,
        'consistency_score': 1.0,
        'avg_response_time': 45.2,
        'median_response_time': 45.2,
        'unique_answers': {'93.184.216.34': {'count': 1}}
    }

    scan_id = db.record_scan('example.com', 'A', example_results, example_analysis)
    print(f"Recorded scan with ID: {scan_id}")

    db.close()
