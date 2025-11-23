"""
Domain Marketplace API
Peer-to-peer marketplace for buying and selling domains
"""

from flask import Blueprint, request, jsonify, session, current_app
from functools import wraps
import os
import logging
from datetime import datetime, timedelta
from decimal import Decimal
import stripe
import psycopg2
import psycopg2.extras
import re

logger = logging.getLogger(__name__)

# Create Blueprint
marketplace_bp = Blueprint('marketplace', __name__, url_prefix='/api/marketplace')

def get_db_connection():
    """Get database connection"""
    from database import Database
    db = Database()
    return db.get_connection()

def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


# ============================================
# MARKETPLACE LISTING ENDPOINTS
# ============================================

@marketplace_bp.route('/list', methods=['POST'])
@login_required
def create_listing():
    """
    Create a marketplace listing

    POST /api/marketplace/list
    {
        "domain": "example.com",
        "price": 1500.00,
        "description": "Premium brandable domain",
        "category": "business",
        "min_offer": 1200.00
    }
    """
    try:
        data = request.get_json()

        # Validate input
        domain = data.get('domain', '').strip().lower()
        price = float(data.get('price', 0))
        description = data.get('description', '').strip()
        category = data.get('category', 'general')
        min_offer = float(data.get('min_offer', price * 0.8))
        accepts_offers = data.get('accepts_offers', True)

        if not domain:
            return jsonify({'error': 'Domain name is required'}), 400

        if price < 10:
            return jsonify({'error': 'Listing price must be at least $10'}), 400

        if len(description) < 10:
            return jsonify({'error': 'Please provide a description (minimum 10 characters)'}), 400

        # Validate domain format
        domain_pattern = r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$'
        if not re.match(domain_pattern, domain):
            return jsonify({'error': 'Invalid domain format'}), 400

        # Check if user owns this domain (optional - could integrate with domains_owned table)
        # For MVP, we'll allow any listing but mark as unverified

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check for existing active listing
        cursor.execute("""
            SELECT id FROM domain_marketplace_listings
            WHERE domain_name = %s AND status = 'active'
            LIMIT 1;
        """, (domain,))

        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'This domain is already listed in the marketplace'}), 409

        # Calculate commission
        commission_pct = 10.00  # 10% commission

        # Create listing
        cursor.execute("""
            INSERT INTO domain_marketplace_listings
            (seller_id, domain_name, asking_price, description, category,
             minimum_offer, accepts_offers, commission_percentage, status, published_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active', NOW())
            RETURNING id;
        """, (session['user_id'], domain, price, description, category,
              min_offer, accepts_offers, commission_pct))

        listing_id = cursor.fetchone()[0]

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Created marketplace listing {listing_id} for {domain} by user {session['user_id']}")

        return jsonify({
            'success': True,
            'listing_id': listing_id,
            'domain': domain,
            'price': price,
            'commission_percentage': commission_pct,
            'message': f'{domain} is now listed for ${price:,.2f}'
        }), 200

    except Exception as e:
        logger.error(f"Error creating listing: {str(e)}")
        return jsonify({'error': str(e)}), 500


@marketplace_bp.route('/browse', methods=['GET'])
def browse_listings():
    """
    Browse marketplace listings

    GET /api/marketplace/browse?category=tech&min_price=100&max_price=5000&sort=price_low&limit=50
    """
    try:
        # Get filter parameters
        category = request.args.get('category', 'all')
        min_price = float(request.args.get('min_price', 0))
        max_price = float(request.args.get('max_price', 999999))
        sort_by = request.args.get('sort', 'newest')  # newest, price_low, price_high, popular
        search_query = request.args.get('q', '').strip()
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = int(request.args.get('offset', 0))

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Build query
        query = """
            SELECT
                l.id,
                l.domain_name,
                l.asking_price,
                l.description,
                l.category,
                l.domain_age_years,
                l.featured,
                l.views_count,
                l.inquiries_count,
                l.offers_count,
                l.created_at,
                l.includes_website,
                l.revenue_generating,
                l.monthly_revenue,
                u.email as seller_email
            FROM domain_marketplace_listings l
            JOIN users u ON l.seller_id = u.id
            WHERE l.status = 'active'
            AND l.asking_price BETWEEN %s AND %s
        """

        params = [min_price, max_price]

        # Category filter
        if category != 'all':
            query += " AND l.category = %s"
            params.append(category)

        # Search query
        if search_query:
            query += " AND (l.domain_name ILIKE %s OR l.description ILIKE %s)"
            params.extend([f'%{search_query}%', f'%{search_query}%'])

        # Sort order
        if sort_by == 'price_low':
            query += " ORDER BY l.asking_price ASC"
        elif sort_by == 'price_high':
            query += " ORDER BY l.asking_price DESC"
        elif sort_by == 'popular':
            query += " ORDER BY l.views_count DESC, l.inquiries_count DESC"
        elif sort_by == 'featured':
            query += " ORDER BY l.featured DESC, l.created_at DESC"
        else:  # newest
            query += " ORDER BY l.created_at DESC"

        query += " LIMIT %s OFFSET %s;"
        params.extend([limit, offset])

        cursor.execute(query, params)
        listings = cursor.fetchall()

        # Get total count for pagination
        count_query = """
            SELECT COUNT(*) as total
            FROM domain_marketplace_listings l
            WHERE l.status = 'active'
            AND l.asking_price BETWEEN %s AND %s
        """
        count_params = [min_price, max_price]

        if category != 'all':
            count_query += " AND l.category = %s"
            count_params.append(category)

        if search_query:
            count_query += " AND (l.domain_name ILIKE %s OR l.description ILIKE %s)"
            count_params.extend([f'%{search_query}%', f'%{search_query}%'])

        cursor.execute(count_query, count_params)
        total = cursor.fetchone()['total']

        cursor.close()
        conn.close()

        # Format listings
        listings_formatted = []
        for listing in listings:
            listing_dict = dict(listing)
            # Convert Decimal to float
            for key in ['asking_price', 'monthly_revenue']:
                if listing_dict.get(key):
                    listing_dict[key] = float(listing_dict[key])
            # Mask seller email for privacy
            listing_dict['seller_email'] = _mask_email(listing_dict['seller_email'])
            listings_formatted.append(listing_dict)

        return jsonify({
            'success': True,
            'listings': listings_formatted,
            'total': total,
            'limit': limit,
            'offset': offset,
            'filters': {
                'category': category,
                'min_price': min_price,
                'max_price': max_price,
                'sort': sort_by
            }
        }), 200

    except Exception as e:
        logger.error(f"Error browsing marketplace: {str(e)}")
        return jsonify({'error': str(e)}), 500


@marketplace_bp.route('/listing/<int:listing_id>', methods=['GET'])
def get_listing(listing_id):
    """
    Get detailed information about a specific listing

    GET /api/marketplace/listing/123
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Increment view count
        cursor.execute("""
            UPDATE domain_marketplace_listings
            SET views_count = views_count + 1
            WHERE id = %s AND status = 'active';
        """, (listing_id,))

        # Get listing details
        cursor.execute("""
            SELECT
                l.*,
                u.email as seller_email,
                u.id as seller_id
            FROM domain_marketplace_listings l
            JOIN users u ON l.seller_id = u.id
            WHERE l.id = %s AND l.status = 'active';
        """, (listing_id,))

        listing = cursor.fetchone()

        if not listing:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Listing not found'}), 404

        conn.commit()
        cursor.close()
        conn.close()

        # Format response
        listing_dict = dict(listing)

        # Convert Decimals
        for key in ['asking_price', 'minimum_offer', 'commission_percentage',
                    'monthly_revenue', 'moz_rank']:
            if listing_dict.get(key):
                listing_dict[key] = float(listing_dict[key])

        # Mask seller email unless viewer is the seller
        is_owner = session.get('user_id') == listing_dict['seller_id']
        if not is_owner:
            listing_dict['seller_email'] = _mask_email(listing_dict['seller_email'])
        listing_dict['is_owner'] = is_owner

        return jsonify({
            'success': True,
            'listing': listing_dict
        }), 200

    except Exception as e:
        logger.error(f"Error fetching listing: {str(e)}")
        return jsonify({'error': str(e)}), 500


@marketplace_bp.route('/listing/<int:listing_id>', methods=['PUT'])
@login_required
def update_listing(listing_id):
    """
    Update a marketplace listing (seller only)

    PUT /api/marketplace/listing/123
    {
        "price": 2000.00,
        "description": "Updated description"
    }
    """
    try:
        data = request.get_json()

        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership
        cursor.execute("""
            SELECT seller_id FROM domain_marketplace_listings
            WHERE id = %s;
        """, (listing_id,))

        result = cursor.fetchone()
        if not result:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Listing not found'}), 404

        if result[0] != session['user_id']:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Not authorized to update this listing'}), 403

        # Build update query
        updates = []
        params = []

        if 'price' in data:
            updates.append("asking_price = %s")
            params.append(float(data['price']))

        if 'description' in data:
            updates.append("description = %s")
            params.append(data['description'])

        if 'category' in data:
            updates.append("category = %s")
            params.append(data['category'])

        if 'min_offer' in data:
            updates.append("minimum_offer = %s")
            params.append(float(data['min_offer']))

        if 'accepts_offers' in data:
            updates.append("accepts_offers = %s")
            params.append(data['accepts_offers'])

        if not updates:
            cursor.close()
            conn.close()
            return jsonify({'error': 'No fields to update'}), 400

        # Perform update
        update_query = f"""
            UPDATE domain_marketplace_listings
            SET {', '.join(updates)}, updated_at = NOW()
            WHERE id = %s;
        """
        params.append(listing_id)

        cursor.execute(update_query, params)
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Updated listing {listing_id} by user {session['user_id']}")

        return jsonify({
            'success': True,
            'message': 'Listing updated successfully'
        }), 200

    except Exception as e:
        logger.error(f"Error updating listing: {str(e)}")
        return jsonify({'error': str(e)}), 500


@marketplace_bp.route('/listing/<int:listing_id>', methods=['DELETE'])
@login_required
def delete_listing(listing_id):
    """
    Delete/remove a marketplace listing

    DELETE /api/marketplace/listing/123
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership
        cursor.execute("""
            SELECT seller_id, status FROM domain_marketplace_listings
            WHERE id = %s;
        """, (listing_id,))

        result = cursor.fetchone()
        if not result:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Listing not found'}), 404

        seller_id, status = result

        if seller_id != session['user_id']:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Not authorized to delete this listing'}), 403

        if status == 'sold':
            cursor.close()
            conn.close()
            return jsonify({'error': 'Cannot delete sold listing'}), 400

        # Update status to removed
        cursor.execute("""
            UPDATE domain_marketplace_listings
            SET status = 'removed', updated_at = NOW()
            WHERE id = %s;
        """, (listing_id,))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Deleted listing {listing_id} by user {session['user_id']}")

        return jsonify({
            'success': True,
            'message': 'Listing removed successfully'
        }), 200

    except Exception as e:
        logger.error(f"Error deleting listing: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# INQUIRY AND OFFER ENDPOINTS
# ============================================

@marketplace_bp.route('/listing/<int:listing_id>/inquire', methods=['POST'])
@login_required
def create_inquiry(listing_id):
    """
    Send inquiry or make offer on a listing

    POST /api/marketplace/listing/123/inquire
    {
        "type": "offer",
        "message": "Interested in purchasing",
        "offer_amount": 1200.00
    }
    """
    try:
        data = request.get_json()

        inquiry_type = data.get('type', 'question')  # question, offer, request_info
        message = data.get('message', '').strip()
        offer_amount = data.get('offer_amount')

        if not message:
            return jsonify({'error': 'Message is required'}), 400

        if inquiry_type == 'offer' and not offer_amount:
            return jsonify({'error': 'Offer amount is required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get listing details
        cursor.execute("""
            SELECT seller_id, asking_price, minimum_offer, accepts_offers
            FROM domain_marketplace_listings
            WHERE id = %s AND status = 'active';
        """, (listing_id,))

        listing = cursor.fetchone()

        if not listing:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Listing not found'}), 404

        # Can't inquire on own listing
        if listing['seller_id'] == session['user_id']:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Cannot inquire on your own listing'}), 400

        # Validate offer
        if inquiry_type == 'offer':
            offer_amount_float = float(offer_amount)

            if not listing['accepts_offers']:
                cursor.close()
                conn.close()
                return jsonify({'error': 'This listing does not accept offers'}), 400

            min_offer = float(listing['minimum_offer']) if listing['minimum_offer'] else float(listing['asking_price']) * 0.5
            if offer_amount_float < min_offer:
                cursor.close()
                conn.close()
                return jsonify({'error': f'Offer must be at least ${min_offer:,.2f}'}), 400

        # Create inquiry
        cursor.execute("""
            INSERT INTO marketplace_inquiries
            (listing_id, buyer_id, inquiry_type, message, offer_amount, status)
            VALUES (%s, %s, %s, %s, %s, 'pending')
            RETURNING id;
        """, (listing_id, session['user_id'], inquiry_type, message, offer_amount))

        inquiry_id = cursor.fetchone()['id']

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Created inquiry {inquiry_id} on listing {listing_id} by user {session['user_id']}")

        # TODO: Send email notification to seller

        return jsonify({
            'success': True,
            'inquiry_id': inquiry_id,
            'message': 'Your inquiry has been sent to the seller'
        }), 200

    except Exception as e:
        logger.error(f"Error creating inquiry: {str(e)}")
        return jsonify({'error': str(e)}), 500


@marketplace_bp.route('/listing/<int:listing_id>/buy', methods=['POST'])
@login_required
def buy_domain(listing_id):
    """
    Purchase a domain at asking price

    POST /api/marketplace/listing/123/buy

    Returns Stripe checkout URL
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get listing
        cursor.execute("""
            SELECT * FROM domain_marketplace_listings
            WHERE id = %s AND status = 'active';
        """, (listing_id,))

        listing = cursor.fetchone()

        if not listing:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Listing not found or no longer available'}), 404

        # Can't buy own listing
        if listing['seller_id'] == session['user_id']:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Cannot purchase your own domain'}), 400

        # Calculate fees
        sale_price = float(listing['asking_price'])
        commission_pct = float(listing['commission_percentage'])
        commission = sale_price * (commission_pct / 100)
        seller_payout = sale_price - commission

        cursor.close()
        conn.close()

        # Create Stripe checkout session
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'Domain: {listing["domain_name"]}',
                        'description': listing['description'],
                    },
                    'unit_amount': int(sale_price * 100),  # Convert to cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=f'{request.host_url}marketplace/purchase/success?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=f'{request.host_url}marketplace/listing/{listing_id}',
            client_reference_id=str(session['user_id']),
            metadata={
                'type': 'marketplace_purchase',
                'listing_id': listing_id,
                'buyer_id': session['user_id'],
                'seller_id': listing['seller_id'],
                'commission': commission,
                'seller_payout': seller_payout
            }
        )

        logger.info(f"Created checkout session for listing {listing_id}, buyer {session['user_id']}")

        return jsonify({
            'success': True,
            'checkout_url': checkout_session.url,
            'sale_price': sale_price,
            'commission': commission
        }), 200

    except Exception as e:
        logger.error(f"Error initiating purchase: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# MY LISTINGS (SELLER DASHBOARD)
# ============================================

@marketplace_bp.route('/my-listings', methods=['GET'])
@login_required
def get_my_listings():
    """
    Get all listings for current user

    GET /api/marketplace/my-listings?status=active
    """
    try:
        status_filter = request.args.get('status', 'all')  # all, active, sold, removed

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        query = """
            SELECT
                id, domain_name, asking_price, status, featured,
                views_count, inquiries_count, offers_count,
                created_at, sold_at, sold_price
            FROM domain_marketplace_listings
            WHERE seller_id = %s
        """

        params = [session['user_id']]

        if status_filter != 'all':
            query += " AND status = %s"
            params.append(status_filter)

        query += " ORDER BY created_at DESC;"

        cursor.execute(query, params)
        listings = cursor.fetchall()

        cursor.close()
        conn.close()

        # Format response
        listings_formatted = []
        for listing in listings:
            listing_dict = dict(listing)
            for key in ['asking_price', 'sold_price']:
                if listing_dict.get(key):
                    listing_dict[key] = float(listing_dict[key])
            listings_formatted.append(listing_dict)

        return jsonify({
            'success': True,
            'listings': listings_formatted,
            'total': len(listings_formatted)
        }), 200

    except Exception as e:
        logger.error(f"Error fetching my listings: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# HELPER FUNCTIONS
# ============================================

def _mask_email(email):
    """Mask email address for privacy"""
    if '@' not in email:
        return '***@***'

    parts = email.split('@')
    username = parts[0]
    domain = parts[1]

    if len(username) <= 2:
        masked_username = '*' * len(username)
    else:
        masked_username = username[0] + '*' * (len(username) - 2) + username[-1]

    return f"{masked_username}@{domain}"


# Export blueprint
__all__ = ['marketplace_bp']
