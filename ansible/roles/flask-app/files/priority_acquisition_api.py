"""
Priority Expiration Registration API
Automated service for acquiring expired/expiring domains
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
import whois
import re

logger = logging.getLogger(__name__)

# Create Blueprint
priority_acquisition_bp = Blueprint('priority_acquisition', __name__, url_prefix='/api/domain/acquisition')

def get_db_connection():
    """Get database connection from config"""
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
# TLD PRICING CONFIGURATION
# ============================================

def get_tld_pricing(tld):
    """Get pricing for a specific TLD"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("""
                SELECT
                    tld,
                    priority_fee_min,
                    priority_fee_max,
                    registration_fee,
                    broker_fee,
                    premium_multiplier,
                    enabled
                FROM domain_acquisition_pricing
                WHERE tld = %s AND enabled = TRUE
            """, (tld,))

            result = cursor.fetchone()

            if result:
                return {
                    'tld': result['tld'],
                    'priority_fee': float(result['priority_fee_min']),  # Use min for now
                    'registration_fee': float(result['registration_fee']),
                    'broker_fee': float(result['broker_fee']),
                    'enabled': result['enabled']
                }
            else:
                # Default to .com pricing if TLD not found
                return {
                    'tld': tld,
                    'priority_fee': 85.00,
                    'registration_fee': 12.99,
                    'broker_fee': 500.00,
                    'enabled': True
                }
    finally:
        from database import Database
        Database().return_connection(conn)


def extract_tld(domain):
    """Extract TLD from domain name"""
    match = re.search(r'(\.[a-z]{2,})$', domain.lower())
    return match.group(1) if match else '.com'


# ============================================
# DOMAIN STATUS CHECK
# ============================================

@priority_acquisition_bp.route('/check-availability', methods=['GET'])
def check_domain_availability():
    """
    Check if a domain is available for registration or in expired status

    GET /api/domain/acquisition/check-availability?domain=example.com

    Returns:
    {
        "domain": "example.com",
        "status": "available" | "registered" | "expired" | "redemption" | "pending_delete",
        "expiry_date": "2025-12-31",
        "estimated_deletion_date": "2026-03-15"
    }
    """
    try:
        domain = request.args.get('domain', '').strip().lower()

        if not domain:
            return jsonify({'error': 'Domain parameter is required'}), 400

        # Validate domain format
        if not re.match(r'^[a-z0-9-]+\.[a-z]{2,}$', domain):
            return jsonify({'error': 'Invalid domain format'}), 400

        # Try WHOIS lookup
        try:
            w = whois.whois(domain)

            # Check if domain is registered
            if w.status is None or not w.expiration_date:
                return jsonify({
                    'domain': domain,
                    'status': 'available',
                    'message': 'Domain appears to be available for standard registration'
                }), 200

            # Domain is registered - check expiration date
            expiry_date = w.expiration_date
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]

            # Check status
            statuses = w.status if isinstance(w.status, list) else [w.status]
            status_str = ' '.join(statuses).lower() if statuses else ''

            current_status = 'registered'
            estimated_deletion = None

            if 'redemptionperiod' in status_str or 'redemption' in status_str:
                current_status = 'redemption'
                # Estimate: 30 days redemption + 5 days pending delete
                estimated_deletion = expiry_date + timedelta(days=35)

            elif 'pendingdelete' in status_str or 'pending delete' in status_str:
                current_status = 'pending_delete'
                # Estimate: 5 days until available
                estimated_deletion = expiry_date + timedelta(days=5)

            elif expiry_date and expiry_date < datetime.now():
                # Expired but not yet in redemption
                current_status = 'expired'
                # Estimate: Could be in grace period (up to 45 days) then redemption (30 days) + pending delete (5 days)
                estimated_deletion = expiry_date + timedelta(days=80)

            return jsonify({
                'domain': domain,
                'status': current_status,
                'expiry_date': expiry_date.isoformat() if expiry_date else None,
                'estimated_deletion_date': estimated_deletion.isoformat() if estimated_deletion else None,
                'registrar': w.registrar,
                'whois_status': statuses
            }), 200

        except whois.parser.PywhoisError as e:
            # Domain might be available or WHOIS failed
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return jsonify({
                'domain': domain,
                'status': 'unknown',
                'message': 'Unable to determine domain status via WHOIS'
            }), 200

    except Exception as e:
        logger.error(f"Error checking domain availability: {e}")
        return jsonify({'error': 'Failed to check domain availability'}), 500


# ============================================
# CREATE ACQUISITION REQUEST
# ============================================

@priority_acquisition_bp.route('/create-intent', methods=['POST'])
@login_required
def create_acquisition_intent():
    """
    Create a priority expiration registration request and Stripe payment intent

    POST /api/domain/acquisition/create-intent
    {
        "domain": "example.com",
        "broker_requested": false,
        "notes": "I need this domain for my business"
    }

    Returns Stripe checkout URL
    """
    try:
        data = request.get_json()

        # Validate input
        domain = data.get('domain', '').strip().lower()
        broker_requested = data.get('broker_requested', False)
        user_notes = data.get('notes', '').strip()

        if not domain:
            return jsonify({'error': 'Domain name is required'}), 400

        # Validate domain format
        if not re.match(r'^[a-z0-9-]+\.[a-z]{2,}$', domain):
            return jsonify({'error': 'Invalid domain format'}), 400

        # Get pricing for TLD
        tld = extract_tld(domain)
        pricing = get_tld_pricing(tld)

        if not pricing['enabled']:
            return jsonify({'error': f'Priority registration not available for {tld} domains'}), 400

        # Calculate total cost
        priority_fee = Decimal(str(pricing['priority_fee']))
        registration_fee = Decimal(str(pricing['registration_fee']))
        broker_fee = Decimal(str(pricing['broker_fee'])) if broker_requested else Decimal('0')
        total_paid = priority_fee + registration_fee + broker_fee

        # Check for existing active request
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id, status
                    FROM domain_acquisition_requests
                    WHERE user_id = %s
                    AND domain_name = %s
                    AND status NOT IN ('registration_successful', 'registration_failed', 'cancelled', 'completed')
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (session['user_id'], domain))

                existing = cursor.fetchone()
                if existing:
                    return jsonify({
                        'error': 'You already have an active request for this domain',
                        'existing_request_id': existing[0],
                        'status': existing[1]
                    }), 409

                # Configure Stripe
                stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

                # Create Stripe checkout session
                line_items = [
                    {
                        'price_data': {
                            'currency': 'usd',
                            'product_data': {
                                'name': f'Priority Registration Fee - {domain}',
                                'description': 'Non-refundable priority monitoring and registration service',
                            },
                            'unit_amount': int(priority_fee * 100),  # Convert to cents
                        },
                        'quantity': 1,
                    },
                    {
                        'price_data': {
                            'currency': 'usd',
                            'product_data': {
                                'name': f'Domain Registration (1 year) - {domain}',
                                'description': f'{tld} domain registration for 1 year',
                            },
                            'unit_amount': int(registration_fee * 100),
                        },
                        'quantity': 1,
                    }
                ]

                # Add broker service line item if requested
                if broker_requested:
                    line_items.append({
                        'price_data': {
                            'currency': 'usd',
                            'product_data': {
                                'name': f'Domain Broker Service - {domain}',
                                'description': 'Professional broker to contact current owner',
                            },
                            'unit_amount': int(broker_fee * 100),
                        },
                        'quantity': 1,
                    })

                checkout_session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=line_items,
                    mode='payment',
                    success_url=f'{request.host_url}acquisition/success?session_id={{CHECKOUT_SESSION_ID}}',
                    cancel_url=f'{request.host_url}acquisition/priority?domain={domain}',
                    client_reference_id=str(session['user_id']),
                    metadata={
                        'type': 'priority_expiration_registration',
                        'domain': domain,
                        'user_id': session['user_id'],
                        'broker_requested': str(broker_requested)
                    }
                )

                # Create acquisition request in database
                cursor.execute("""
                    INSERT INTO domain_acquisition_requests (
                        user_id,
                        domain_name,
                        status,
                        priority_fee,
                        registration_fee,
                        total_paid,
                        stripe_payment_intent_id,
                        payment_status,
                        broker_requested,
                        user_notes,
                        created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    RETURNING id
                """, (
                    session['user_id'],
                    domain,
                    'pending_payment',
                    priority_fee,
                    registration_fee,
                    total_paid,
                    checkout_session.id,
                    'pending',
                    broker_requested,
                    user_notes
                ))

                request_id = cursor.fetchone()[0]

                conn.commit()

                logger.info(f"Created priority acquisition request {request_id} for {domain} by user {session['user_id']}")

                return jsonify({
                    'success': True,
                    'request_id': request_id,
                    'checkout_url': checkout_session.url,
                    'checkout_session_id': checkout_session.id,
                    'total_amount': float(total_paid),
                    'message': 'Please complete payment to start domain monitoring'
                }), 200

        finally:
            from database import Database
            Database().return_connection(conn)

    except Exception as e:
        logger.error(f"Error creating acquisition intent: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================
# WEBHOOK HANDLER
# ============================================

@priority_acquisition_bp.route('/webhook', methods=['POST'])
def priority_acquisition_webhook():
    """
    Handle Stripe webhook events for priority acquisition payments

    This should be called by Stripe when payment events occur
    """
    try:
        payload = request.data
        sig_header = request.headers.get('Stripe-Signature')

        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
        endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
        except ValueError:
            return jsonify({'error': 'Invalid payload'}), 400
        except stripe.error.SignatureVerificationError:
            return jsonify({'error': 'Invalid signature'}), 400

        # Handle checkout session completed
        if event['type'] == 'checkout.session.completed':
            session_data = event['data']['object']

            # Check if this is a priority expiration registration payment
            if session_data.get('metadata', {}).get('type') == 'priority_expiration_registration':
                _handle_priority_payment_success(session_data)

        return jsonify({'success': True}), 200

    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({'error': str(e)}), 500


def _handle_priority_payment_success(session_data):
    """Handle successful priority registration payment"""
    try:
        session_id = session_data['id']
        metadata = session_data.get('metadata', {})
        domain = metadata.get('domain')
        user_id = int(metadata.get('user_id'))

        logger.info(f"Processing priority registration payment for {domain}, user {user_id}")

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # Update request status to monitoring
                cursor.execute("""
                    UPDATE domain_acquisition_requests
                    SET
                        payment_status = 'paid',
                        payment_date = NOW(),
                        status = 'monitoring',
                        stripe_charge_id = %s,
                        updated_at = NOW()
                    WHERE stripe_payment_intent_id = %s
                    RETURNING id
                """, (session_data.get('payment_intent'), session_id))

                result = cursor.fetchone()
                if not result:
                    logger.error(f"Could not find acquisition request for session {session_id}")
                    return

                request_id = result[0]

                # Check domain status and set estimated deletion date
                try:
                    # This would normally call check_domain_availability internally
                    # For now, estimate 80 days from now
                    estimated_deletion = datetime.now() + timedelta(days=80)

                    cursor.execute("""
                        UPDATE domain_acquisition_requests
                        SET
                            domain_deletion_date = %s,
                            last_status_check = NOW()
                        WHERE id = %s
                    """, (estimated_deletion, request_id))

                except Exception as e:
                    logger.error(f"Failed to check domain status: {e}")

                # Log the attempt
                cursor.execute("""
                    INSERT INTO domain_acquisition_attempts (
                        request_id,
                        attempt_type,
                        success,
                        action_taken,
                        next_check_scheduled
                    ) VALUES (%s, %s, %s, %s, %s)
                """, (
                    request_id,
                    'status_check',
                    True,
                    'Payment received, monitoring started',
                    datetime.now() + timedelta(hours=24)
                ))

                conn.commit()

                logger.info(f"Priority acquisition request {request_id} activated for monitoring")

                # TODO: Send confirmation email to user
                # TODO: Notify monitoring daemon of new request

        finally:
            from database import Database
            Database().return_connection(conn)

    except Exception as e:
        logger.error(f"Error handling priority payment: {e}")


# ============================================
# USER DASHBOARD ENDPOINTS
# ============================================

@priority_acquisition_bp.route('/my-requests', methods=['GET'])
@login_required
def get_my_requests():
    """
    Get all priority acquisition requests for current user

    GET /api/domain/acquisition/my-requests?status=all
    """
    try:
        status_filter = request.args.get('status', 'all')

        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                query = """
                    SELECT
                        id,
                        domain_name,
                        status,
                        priority_fee,
                        registration_fee,
                        total_paid,
                        payment_status,
                        broker_requested,
                        current_domain_status,
                        domain_deletion_date,
                        registration_attempts,
                        registration_success_date,
                        created_at,
                        updated_at
                    FROM domain_acquisition_requests
                    WHERE user_id = %s
                """

                params = [session['user_id']]

                if status_filter != 'all':
                    query += " AND status = %s"
                    params.append(status_filter)

                query += " ORDER BY created_at DESC LIMIT 50"

                cursor.execute(query, params)
                requests = cursor.fetchall()

                # Convert Decimal to float for JSON
                formatted_requests = []
                for req in requests:
                    req_dict = dict(req)
                    for key in ['priority_fee', 'registration_fee', 'total_paid']:
                        if req_dict.get(key):
                            req_dict[key] = float(req_dict[key])
                    formatted_requests.append(req_dict)

                return jsonify({
                    'success': True,
                    'requests': formatted_requests,
                    'count': len(formatted_requests)
                }), 200

        finally:
            from database import Database
            Database().return_connection(conn)

    except Exception as e:
        logger.error(f"Error fetching user requests: {e}")
        return jsonify({'error': str(e)}), 500


@priority_acquisition_bp.route('/<int:request_id>', methods=['GET'])
@login_required
def get_request_details(request_id):
    """
    Get detailed information about a specific acquisition request

    GET /api/domain/acquisition/123
    """
    try:
        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Get request details
                cursor.execute("""
                    SELECT *
                    FROM domain_acquisition_requests
                    WHERE id = %s AND user_id = %s
                """, (request_id, session['user_id']))

                request_data = cursor.fetchone()

                if not request_data:
                    return jsonify({'error': 'Request not found'}), 404

                # Get attempt history
                cursor.execute("""
                    SELECT *
                    FROM domain_acquisition_attempts
                    WHERE request_id = %s
                    ORDER BY attempt_time DESC
                    LIMIT 20
                """, (request_id,))

                attempts = cursor.fetchall()

                # Convert Decimal to float
                request_dict = dict(request_data)
                for key in ['priority_fee', 'registration_fee', 'total_paid']:
                    if request_dict.get(key):
                        request_dict[key] = float(request_dict[key])

                return jsonify({
                    'success': True,
                    'request': request_dict,
                    'attempts': [dict(a) for a in attempts]
                }), 200

        finally:
            from database import Database
            Database().return_connection(conn)

    except Exception as e:
        logger.error(f"Error fetching request details: {e}")
        return jsonify({'error': str(e)}), 500


# Export blueprint
__all__ = ['priority_acquisition_bp']
