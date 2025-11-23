"""Advanced Search Module for DNS Science Platform

Provides comprehensive search functionality including:
- Full-text domain search
- Filtering by DNSSEC, SPF, SSL status
- Web3 domain search (ENS/SNS)
- Tag-based search
- Pagination support
"""

import psycopg2
import psycopg2.extras
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from database import Database


class AdvancedSearch:
    """Advanced search functionality for domains and DNS data"""

    def __init__(self, db: Database = None):
        """
        Initialize search module.

        Args:
            db: Optional Database instance. Creates new one if not provided.
        """
        self.db = db if db else Database()

    def search_domains(
        self,
        query: str = "",
        filters: Dict = None,
        page: int = 1,
        per_page: int = 50,
        user_id: int = None
    ) -> Dict:
        """
        Advanced domain search with filtering and pagination.

        Args:
            query: Text search query for domain names
            filters: Dictionary of filter criteria:
                - dnssec_enabled: bool
                - spf_valid: bool
                - dkim_valid: bool
                - dmarc_enabled: bool
                - ssl_grade: str (A+, A, B, C, D, F)
                - security_score_min: int (0-100)
                - security_score_max: int (0-100)
                - cert_expiring_days: int
                - has_threats: bool
                - blacklisted: bool
                - tags: List[str] (requires user_id)
            page: Page number (1-based)
            per_page: Results per page (max 200)
            user_id: User ID for tag filtering

        Returns:
            Dictionary containing:
                - domains: List of matching domains
                - total: Total count
                - page: Current page
                - per_page: Results per page
                - total_pages: Total pages
        """
        if filters is None:
            filters = {}

        # Enforce per_page limit
        per_page = min(per_page, 200)
        offset = (page - 1) * per_page

        # Build WHERE clause
        where_clauses = []
        params = []
        param_counter = 1

        # Text search
        if query:
            where_clauses.append(f"d.domain_name ILIKE ${param_counter}")
            params.append(f"%{query}%")
            param_counter += 1

        # DNSSEC filter
        if 'dnssec_enabled' in filters:
            where_clauses.append(f"ls.dnssec_enabled = ${param_counter}")
            params.append(filters['dnssec_enabled'])
            param_counter += 1

        # SPF filter
        if 'spf_valid' in filters:
            where_clauses.append(f"ls.spf_valid = ${param_counter}")
            params.append(filters['spf_valid'])
            param_counter += 1

        # DKIM filter
        if 'dkim_valid' in filters:
            where_clauses.append(f"ls.dkim_valid = ${param_counter}")
            params.append(filters['dkim_valid'])
            param_counter += 1

        # DMARC filter
        if 'dmarc_enabled' in filters:
            where_clauses.append(f"ls.dmarc_enabled = ${param_counter}")
            params.append(filters['dmarc_enabled'])
            param_counter += 1

        # SSL grade filter
        if 'ssl_grade' in filters:
            where_clauses.append(f"d.ssl_grade = ${param_counter}")
            params.append(filters['ssl_grade'])
            param_counter += 1

        # Security score filters
        if 'security_score_min' in filters:
            where_clauses.append(f"ls.security_score >= ${param_counter}")
            params.append(filters['security_score_min'])
            param_counter += 1

        if 'security_score_max' in filters:
            where_clauses.append(f"ls.security_score <= ${param_counter}")
            params.append(filters['security_score_max'])
            param_counter += 1

        # Certificate expiration filter
        if 'cert_expiring_days' in filters:
            where_clauses.append(f"""
                EXISTS (
                    SELECT 1 FROM certificate_history ch
                    WHERE ch.domain_id = d.id
                    AND ch.days_until_expiry IS NOT NULL
                    AND ch.days_until_expiry <= ${param_counter}
                    AND ch.id = (
                        SELECT id FROM certificate_history
                        WHERE domain_id = d.id
                        ORDER BY scan_timestamp DESC
                        LIMIT 1
                    )
                )
            """)
            params.append(filters['cert_expiring_days'])
            param_counter += 1

        # Threat intelligence filter
        if filters.get('has_threats'):
            where_clauses.append("""
                EXISTS (
                    SELECT 1 FROM threat_indicators ti
                    WHERE ti.domain_id = d.id
                    AND ti.is_active = TRUE
                )
            """)

        # Blacklist filter
        if filters.get('blacklisted'):
            where_clauses.append("""
                EXISTS (
                    SELECT 1 FROM domain_blacklists db
                    WHERE db.domain_id = d.id
                    AND db.is_active = TRUE
                )
            """)

        # Tag filter (requires user_id)
        if 'tags' in filters and filters['tags'] and user_id:
            tag_placeholders = ','.join([f"${i}" for i in range(param_counter, param_counter + len(filters['tags']))])
            where_clauses.append(f"""
                EXISTS (
                    SELECT 1 FROM domain_tags dt
                    WHERE dt.domain_id = d.id
                    AND dt.user_id = ${param_counter}
                    AND dt.tag_name IN ({tag_placeholders})
                )
            """)
            params.append(user_id)
            param_counter += 1
            params.extend(filters['tags'])
            param_counter += len(filters['tags'])

        # Build final query
        where_sql = " AND ".join(where_clauses) if where_clauses else "TRUE"

        # Get total count
        count_query = f"""
            SELECT COUNT(DISTINCT d.id)
            FROM domains d
            LEFT JOIN latest_scans ls ON d.domain_name = ls.domain_name
            WHERE {where_sql}
        """

        # Get results
        results_query = f"""
            SELECT DISTINCT
                d.id,
                d.domain_name,
                d.first_checked,
                d.last_checked,
                d.ssl_grade,
                ls.dnssec_enabled,
                ls.dnssec_valid,
                ls.spf_valid,
                ls.dkim_valid,
                ls.dmarc_enabled,
                ls.dmarc_policy,
                ls.security_score,
                ls.security_grade,
                ls.scan_timestamp
            FROM domains d
            LEFT JOIN latest_scans ls ON d.domain_name = ls.domain_name
            WHERE {where_sql}
            ORDER BY d.last_checked DESC NULLS LAST
            LIMIT ${param_counter} OFFSET ${param_counter + 1}
        """

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Get total
                cursor.execute(count_query, params)
                total = cursor.fetchone()[0]

                # Get results
                result_params = params + [per_page, offset]
                cursor.execute(results_query, result_params)
                domains = [dict(row) for row in cursor.fetchall()]

                # Calculate pagination
                total_pages = (total + per_page - 1) // per_page if total > 0 else 0

                return {
                    'domains': domains,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
        finally:
            self.db.return_connection(conn)

    def search_web3_domains(
        self,
        query: str = "",
        blockchain: str = None,
        page: int = 1,
        per_page: int = 50
    ) -> Dict:
        """
        Search Web3 domains (ENS, SNS, etc.).

        Args:
            query: Search query for domain/wallet
            blockchain: Filter by blockchain (ethereum, solana, etc.)
            page: Page number
            per_page: Results per page

        Returns:
            Dictionary with results and pagination info
        """
        per_page = min(per_page, 200)
        offset = (page - 1) * per_page

        where_clauses = []
        params = []
        param_counter = 1

        if query:
            where_clauses.append(f"(w3d.domain_name ILIKE ${param_counter} OR w3d.wallet_address ILIKE ${param_counter})")
            params.append(f"%{query}%")
            param_counter += 1

        if blockchain:
            where_clauses.append(f"w3n.blockchain = ${param_counter}")
            params.append(blockchain)
            param_counter += 1

        where_sql = " AND ".join(where_clauses) if where_clauses else "TRUE"

        count_query = f"""
            SELECT COUNT(*)
            FROM web3_domains w3d
            JOIN web3_networks w3n ON w3d.network_id = w3n.id
            WHERE {where_sql}
        """

        results_query = f"""
            SELECT
                w3d.id,
                w3d.domain_name,
                w3d.wallet_address,
                w3d.resolved_address,
                w3d.token_id,
                w3d.owner_address,
                w3d.registration_date,
                w3d.expiration_date,
                w3d.last_updated,
                w3n.network_name,
                w3n.blockchain,
                w3n.token_standard
            FROM web3_domains w3d
            JOIN web3_networks w3n ON w3d.network_id = w3n.id
            WHERE {where_sql}
            ORDER BY w3d.last_updated DESC
            LIMIT ${param_counter} OFFSET ${param_counter + 1}
        """

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(count_query, params)
                total = cursor.fetchone()[0]

                result_params = params + [per_page, offset]
                cursor.execute(results_query, result_params)
                domains = [dict(row) for row in cursor.fetchall()]

                total_pages = (total + per_page - 1) // per_page if total > 0 else 0

                return {
                    'domains': domains,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
        finally:
            self.db.return_connection(conn)

    def search_by_tags(
        self,
        user_id: int,
        tags: List[str],
        match_all: bool = False,
        page: int = 1,
        per_page: int = 50
    ) -> Dict:
        """
        Search domains by tags.

        Args:
            user_id: User ID
            tags: List of tag names
            match_all: If True, domain must have all tags. If False, any tag matches.
            page: Page number
            per_page: Results per page

        Returns:
            Dictionary with results and pagination info
        """
        if not tags:
            return {
                'domains': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 0
            }

        per_page = min(per_page, 200)
        offset = (page - 1) * per_page

        tag_placeholders = ','.join([f"${i}" for i in range(2, 2 + len(tags))])

        if match_all:
            # Domain must have ALL specified tags
            query = f"""
                SELECT
                    d.id,
                    d.domain_name,
                    d.first_checked,
                    d.last_checked,
                    d.ssl_grade,
                    ARRAY_AGG(DISTINCT dt.tag_name) as tags,
                    COUNT(DISTINCT dt.tag_name) as matching_tags
                FROM domains d
                JOIN domain_tags dt ON d.id = dt.domain_id
                WHERE dt.user_id = $1
                AND dt.tag_name IN ({tag_placeholders})
                GROUP BY d.id, d.domain_name, d.first_checked, d.last_checked, d.ssl_grade
                HAVING COUNT(DISTINCT dt.tag_name) = ${2 + len(tags)}
            """
        else:
            # Domain must have ANY of the specified tags
            query = f"""
                SELECT DISTINCT
                    d.id,
                    d.domain_name,
                    d.first_checked,
                    d.last_checked,
                    d.ssl_grade,
                    ARRAY_AGG(DISTINCT dt.tag_name) as tags
                FROM domains d
                JOIN domain_tags dt ON d.id = dt.domain_id
                WHERE dt.user_id = $1
                AND dt.tag_name IN ({tag_placeholders})
                GROUP BY d.id, d.domain_name, d.first_checked, d.last_checked, d.ssl_grade
            """

        count_query = f"SELECT COUNT(*) FROM ({query}) subq"
        results_query = f"{query} ORDER BY d.last_checked DESC LIMIT ${2 + len(tags) + 1} OFFSET ${2 + len(tags) + 2}"

        params = [user_id] + tags
        if match_all:
            params.append(len(tags))

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(count_query, params)
                total = cursor.fetchone()[0]

                result_params = params + [per_page, offset]
                cursor.execute(results_query, result_params)
                domains = [dict(row) for row in cursor.fetchall()]

                total_pages = (total + per_page - 1) // per_page if total > 0 else 0

                return {
                    'domains': domains,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
        finally:
            self.db.return_connection(conn)

    def autocomplete_domains(
        self,
        query: str,
        limit: int = 10
    ) -> List[str]:
        """
        Autocomplete domain names for search.

        Args:
            query: Partial domain name
            limit: Max suggestions

        Returns:
            List of domain name suggestions
        """
        if not query or len(query) < 2:
            return []

        limit = min(limit, 50)

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT domain_name
                    FROM domains
                    WHERE domain_name ILIKE %s
                    ORDER BY
                        CASE
                            WHEN domain_name ILIKE %s THEN 1
                            ELSE 2
                        END,
                        last_checked DESC NULLS LAST
                    LIMIT %s
                """, (f"%{query}%", f"{query}%", limit))

                return [row[0] for row in cursor.fetchall()]
        finally:
            self.db.return_connection(conn)

    def get_search_suggestions(
        self,
        user_id: int = None,
        limit: int = 10
    ) -> Dict:
        """
        Get search suggestions based on recent activity.

        Args:
            user_id: Optional user ID for personalized suggestions
            limit: Max suggestions per category

        Returns:
            Dictionary with suggestion categories
        """
        suggestions = {
            'recent_domains': [],
            'popular_tags': [],
            'saved_searches': []
        }

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Recent domains
                cursor.execute("""
                    SELECT domain_name, last_checked
                    FROM domains
                    WHERE last_checked IS NOT NULL
                    ORDER BY last_checked DESC
                    LIMIT %s
                """, (limit,))
                suggestions['recent_domains'] = [dict(row) for row in cursor.fetchall()]

                # Popular tags (if user_id provided)
                if user_id:
                    cursor.execute("""
                        SELECT tag_name, tag_color, COUNT(*) as count
                        FROM domain_tags
                        WHERE user_id = %s
                        GROUP BY tag_name, tag_color
                        ORDER BY count DESC
                        LIMIT %s
                    """, (user_id, limit))
                    suggestions['popular_tags'] = [dict(row) for row in cursor.fetchall()]

                    # Saved searches
                    cursor.execute("""
                        SELECT id, search_name, query_params
                        FROM saved_searches
                        WHERE user_id = %s
                        ORDER BY last_used_at DESC NULLS LAST, created_at DESC
                        LIMIT %s
                    """, (user_id, limit))
                    suggestions['saved_searches'] = [dict(row) for row in cursor.fetchall()]
        finally:
            self.db.return_connection(conn)

        return suggestions
