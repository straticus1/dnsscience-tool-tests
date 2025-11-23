#!/usr/bin/env python3
"""
Comprehensive TLD Pricing Manager
Fetches ALL available TLDs from OpenSRS and applies competitive profit margins
Supports 800+ TLDs with dynamic pricing updates
"""

import os
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from database import Database
from opensrs_integration import create_opensrs_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tld_pricing')


class TLDPricingManager:
    """Manage pricing for all available TLDs with competitive margins"""

    # Profit margin tiers based on TLD popularity/competition
    MARGIN_TIERS = {
        'premium': 0.20,      # 20% for ultra-competitive (.com, .net, .org)
        'popular': 0.25,      # 25% for popular TLDs (.io, .ai, .app, .dev)
        'standard': 0.30,     # 30% for standard TLDs (most gTLDs)
        'specialty': 0.35,    # 35% for specialty/niche TLDs
    }

    # Categorize TLDs by competition level
    PREMIUM_TLDS = ['com', 'net', 'org']  # Keep razor-thin margins to compete
    POPULAR_TLDS = ['io', 'ai', 'app', 'dev', 'co', 'me', 'tv', 'cc', 'bz']

    # Minimum prices to ensure we're never losing money
    MINIMUM_MARKUP = 1.00  # Always add at least $1

    def __init__(self, db: Database):
        self.db = db
        # Get OpenSRS credentials from environment
        username = os.getenv('OPENSRS_USERNAME', 'dnsscience')
        api_key = os.getenv('OPENSRS_API_KEY', '')

        if not api_key:
            logger.warning("No OpenSRS API key found, using fallback pricing")
            self.opensrs_client = None
            self.domain_mgr = None
        else:
            self.opensrs_client, self.domain_mgr, _, _ = create_opensrs_client(username, api_key)

    def get_margin_tier(self, tld: str) -> float:
        """
        Determine profit margin for a TLD based on competition

        Args:
            tld: TLD without dot (e.g., 'com')

        Returns:
            Margin percentage (0.20 - 0.35)
        """
        tld_lower = tld.lower()

        if tld_lower in self.PREMIUM_TLDS:
            return self.MARGIN_TIERS['premium']  # 20% - stay competitive
        elif tld_lower in self.POPULAR_TLDS:
            return self.MARGIN_TIERS['popular']   # 25%
        else:
            return self.MARGIN_TIERS['standard']  # 30%

    def calculate_retail_price(self, wholesale_price: float, tld: str) -> float:
        """
        Calculate retail price with appropriate margin

        Args:
            wholesale_price: OpenSRS wholesale cost
            tld: TLD name

        Returns:
            Retail price with margin applied
        """
        margin = self.get_margin_tier(tld)
        retail = wholesale_price * (1 + margin)

        # Ensure minimum markup
        if retail - wholesale_price < self.MINIMUM_MARKUP:
            retail = wholesale_price + self.MINIMUM_MARKUP

        # Round to .99 for psychological pricing
        retail = round(retail, 2)
        if retail % 1 >= 0.50:
            retail = int(retail) + 0.99
        else:
            retail = int(retail) - 0.01

        return max(retail, wholesale_price + 1.00)

    def fetch_all_tld_pricing(self) -> Dict[str, Dict]:
        """
        Fetch all available TLDs and their pricing from OpenSRS

        Returns:
            Dict of {tld: {wholesale, retail, margin, currency}}
        """
        # If OpenSRS not configured, use fallback pricing
        if not self.domain_mgr:
            logger.info("OpenSRS not configured, using fallback pricing")
            return self._get_fallback_pricing()

        try:
            logger.info("Fetching all TLD pricing from OpenSRS...")

            # Get all available TLDs from OpenSRS
            result = self.domain_mgr.get_tld_list()

            if not result or not result.get('is_success'):
                logger.error("Failed to fetch TLD list from OpenSRS")
                return self._get_fallback_pricing()

            tld_pricing = {}
            tld_data = result.get('attributes', {}).get('tlds', [])

            logger.info(f"Retrieved {len(tld_data)} TLDs from OpenSRS")

            for tld_info in tld_data:
                tld = tld_info.get('tld', '').replace('.', '')

                # Get pricing for this TLD
                try:
                    price_result = self.domain_mgr.get_tld_pricing(tld)

                    if price_result and price_result.get('is_success'):
                        pricing_data = price_result.get('attributes', {})
                        wholesale = float(pricing_data.get('registration', {}).get('price', 0))

                        if wholesale > 0:
                            retail = self.calculate_retail_price(wholesale, tld)
                            margin_pct = ((retail - wholesale) / wholesale) * 100

                            tld_pricing[tld] = {
                                'wholesale': round(wholesale, 2),
                                'retail': round(retail, 2),
                                'margin_percent': round(margin_pct, 1),
                                'margin_amount': round(retail - wholesale, 2),
                                'currency': 'USD',
                                'available': True,
                                'last_updated': datetime.now().isoformat()
                            }

                except Exception as e:
                    logger.warning(f"Could not get pricing for {tld}: {e}")
                    continue

            logger.info(f"Successfully priced {len(tld_pricing)} TLDs")
            return tld_pricing

        except Exception as e:
            logger.error(f"Error fetching TLD pricing: {e}")
            return self._get_fallback_pricing()

    def _get_fallback_pricing(self) -> Dict[str, Dict]:
        """
        Fallback pricing based on market research
        Used when OpenSRS API is unavailable
        """
        logger.info("Using fallback pricing based on market research")

        # Based on current market prices from GoDaddy, Namecheap, etc.
        # These are retail prices - we'll reverse-engineer wholesale
        market_prices = {
            # Premium TLDs (20% margin)
            'com': 8.99,    # Wholesale ~$7.50
            'net': 11.99,   # Wholesale ~$10.00
            'org': 12.99,   # Wholesale ~$10.80

            # Popular TLDs (25% margin)
            'io': 32.99,    # Wholesale ~$26.40
            'ai': 79.99,    # Wholesale ~$64.00
            'app': 14.99,   # Wholesale ~$12.00
            'dev': 12.99,   # Wholesale ~$10.40
            'co': 24.99,    # Wholesale ~$20.00
            'me': 19.99,    # Wholesale ~$16.00
            'tv': 29.99,    # Wholesale ~$24.00

            # Standard TLDs (30% margin)
            'info': 14.99,
            'biz': 14.99,
            'name': 9.99,
            'online': 3.99,
            'site': 3.99,
            'website': 4.99,
            'store': 4.99,
            'tech': 19.99,
            'space': 9.99,
            'cloud': 9.99,
            'blog': 24.99,
            'shop': 34.99,
            'uk': 8.99,
            'us': 8.99,
            'ca': 14.99,
            'au': 12.99,
            'de': 8.99,
            'fr': 12.99,
            'it': 12.99,
            'es': 12.99,
            'nl': 12.99,
            'be': 9.99,
            'ch': 14.99,
            'at': 14.99,
            'pl': 24.99,
            'cz': 19.99,
            'se': 19.99,
            'no': 19.99,
            'dk': 19.99,
            'fi': 19.99,
            'ie': 19.99,
            'nz': 19.99,
            'in': 9.99,
            'cn': 39.99,
            'jp': 39.99,
            'kr': 34.99,
            'sg': 39.99,
            'hk': 39.99,
            'tw': 34.99,
            'br': 14.99,
            'mx': 49.99,
            'ru': 9.99,
        }

        pricing = {}
        for tld, retail in market_prices.items():
            margin = self.get_margin_tier(tld)
            wholesale = retail / (1 + margin)

            pricing[tld] = {
                'wholesale': round(wholesale, 2),
                'retail': round(retail, 2),
                'margin_percent': round(margin * 100, 1),
                'margin_amount': round(retail - wholesale, 2),
                'currency': 'USD',
                'available': True,
                'last_updated': datetime.now().isoformat(),
                'source': 'fallback'
            }

        return pricing

    def update_database_pricing(self, tld_pricing: Dict[str, Dict]) -> int:
        """
        Store/update TLD pricing in database

        Args:
            tld_pricing: Pricing data from fetch_all_tld_pricing()

        Returns:
            Number of TLDs updated
        """
        conn = self.db.get_connection()
        updated = 0

        try:
            with conn.cursor() as cursor:
                # Create pricing table if it doesn't exist
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS tld_pricing (
                        id SERIAL PRIMARY KEY,
                        tld VARCHAR(50) UNIQUE NOT NULL,
                        wholesale_price DECIMAL(10, 2) NOT NULL,
                        retail_price DECIMAL(10, 2) NOT NULL,
                        margin_percent DECIMAL(5, 2),
                        margin_amount DECIMAL(10, 2),
                        currency VARCHAR(3) DEFAULT 'USD',
                        available BOOLEAN DEFAULT TRUE,
                        last_updated TIMESTAMP DEFAULT NOW(),
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """)

                # Upsert pricing data
                for tld, pricing in tld_pricing.items():
                    cursor.execute("""
                        INSERT INTO tld_pricing
                        (tld, wholesale_price, retail_price, margin_percent,
                         margin_amount, currency, available, last_updated)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                        ON CONFLICT (tld) DO UPDATE SET
                            wholesale_price = EXCLUDED.wholesale_price,
                            retail_price = EXCLUDED.retail_price,
                            margin_percent = EXCLUDED.margin_percent,
                            margin_amount = EXCLUDED.margin_amount,
                            available = EXCLUDED.available,
                            last_updated = NOW()
                    """, (
                        tld,
                        pricing['wholesale'],
                        pricing['retail'],
                        pricing['margin_percent'],
                        pricing['margin_amount'],
                        pricing['currency'],
                        pricing['available']
                    ))
                    updated += 1

                conn.commit()
                logger.info(f"Updated {updated} TLD prices in database")

        except Exception as e:
            logger.error(f"Error updating database pricing: {e}")
            conn.rollback()
            raise
        finally:
            self.db.return_connection(conn)

        return updated

    def get_price(self, tld: str, years: int = 1) -> float:
        """
        Get retail price for a TLD

        Args:
            tld: TLD without dot
            years: Number of years (applies small bulk discount)

        Returns:
            Total price for registration period
        """
        tld = tld.replace('.', '').lower()

        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT retail_price FROM tld_pricing
                    WHERE tld = %s AND available = TRUE
                """, (tld,))

                result = cursor.fetchone()
                if result:
                    annual_price = float(result[0])
                else:
                    # Fallback to default pricing
                    annual_price = 19.99

                # Apply small multi-year discount
                total = annual_price * years
                if years >= 3:
                    total *= 0.97  # 3% discount for 3+ years
                elif years >= 5:
                    total *= 0.95  # 5% discount for 5+ years

                return round(total, 2)

        finally:
            self.db.return_connection(conn)

    def get_all_prices(self) -> Dict[str, float]:
        """
        Get all TLD retail prices from database

        Returns:
            Dict of {tld: retail_price}
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT tld, retail_price
                    FROM tld_pricing
                    WHERE available = TRUE
                    ORDER BY tld
                """)

                return {row[0]: float(row[1]) for row in cursor.fetchall()}

        finally:
            self.db.return_connection(conn)

    def refresh_pricing(self) -> Dict[str, any]:
        """
        Refresh all TLD pricing from OpenSRS
        Run this weekly via cron

        Returns:
            Status dict with counts
        """
        logger.info("Starting TLD pricing refresh...")

        # Fetch current pricing
        tld_pricing = self.fetch_all_tld_pricing()

        # Update database
        updated = self.update_database_pricing(tld_pricing)

        return {
            'success': True,
            'tlds_fetched': len(tld_pricing),
            'tlds_updated': updated,
            'timestamp': datetime.now().isoformat()
        }


if __name__ == '__main__':
    # Run pricing refresh
    db = Database()
    pricing_mgr = TLDPricingManager(db)
    result = pricing_mgr.refresh_pricing()
    print(json.dumps(result, indent=2))
