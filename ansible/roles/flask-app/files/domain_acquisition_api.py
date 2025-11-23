"""
Domain Acquisition Service API
Handles requests for acquiring taken domains on behalf of users
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

logger = logging.getLogger(__name__)

# Create Blueprint
acquisition_bp = Blueprint('acquisition', __name__, url_prefix='/api/acquisition')

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
# DOMAIN ACQUISITION ENDPOINTS
# ============================================

@acquisition_bp.route('/request', methods=['POST'])
@login_required
def create_acquisition_request():
    """
    Create a domain acquisition request

    POST /api/acquisition/request
    {
        "domain": "example.com",
        "max_budget": 5000.00,
        "notes": "Need this for my business"
    }

    Returns Stripe checkout URL for $75 investigation fee
    """
    try:
        data = request.get_json()

        # Validate input
        domain = data.get('domain', '').strip().lower()
        max_budget = float(data.get('max_budget', 0))
        user_notes = data.get('notes', '').strip()

        if not domain:
            return jsonify({'error': 'Domain name is required'}), 400

        if max_budget < 100:
            return jsonify({'error': 'Maximum budget must be at least $100'}), 400

        # Check if domain is actually taken
        # TODO: Add WHOIS check here

        # Check for existing request
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, status FROM domain_acquisition_requests
            WHERE user_id = %s AND domain_name = %s
            AND status NOT IN ('completed', 'failed')
            ORDER BY created_at DESC LIMIT 1;
        """, (session['user_id'], domain))

        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            return jsonify({
                'error': 'You already have an active acquisition request for this domain',
                'existing_request_id': existing[0],
                'status': existing[1]
            }), 409

        # Configure Stripe
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

        # Create Stripe checkout session for investigation fee
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'Domain Acquisition Investigation: {domain}',
                        'description': 'Investigation fee (non-refundable) - We will research current owner and attempt contact',
                        'images': ['https://www.dnsscience.io/static/images/acquisition-service.png'],
                    },
                    'unit_amount': 7500,  # $75.00 in cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=f'{request.host_url}acquisition/success?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=f'{request.host_url}acquisition?domain={domain}',
            client_reference_id=str(session['user_id']),
            metadata={
                'type': 'domain_acquisition_investigation',
                'domain': domain,
                'user_id': session['user_id'],
                'max_budget': max_budget
            }
        )

        # Create acquisition request in database
        cursor.execute("""
            INSERT INTO domain_acquisition_requests
            (user_id, domain_name, max_budget, user_notes, investigation_payment_id,
             status, investigation_payment_status)
            VALUES (%s, %s, %s, %s, %s, 'payment_pending', 'pending')
            RETURNING id;
        """, (session['user_id'], domain, max_budget, user_notes, checkout_session.id))

        acquisition_id = cursor.fetchone()[0]

        # Log initial update
        cursor.execute("""
            INSERT INTO domain_acquisition_updates
            (acquisition_id, update_type, message, created_by)
            VALUES (%s, 'note_added', %s, 'system');
        """, (acquisition_id, f'Acquisition request created. Awaiting payment of $75 investigation fee.'))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Created acquisition request {acquisition_id} for {domain} by user {session['user_id']}")

        return jsonify({
            'success': True,
            'acquisition_id': acquisition_id,
            'checkout_url': checkout_session.url,
            'checkout_session_id': checkout_session.id,
            'message': 'Please complete payment to start investigation'
        }), 200

    except Exception as e:
        logger.error(f"Error creating acquisition request: {str(e)}")
        return jsonify({'error': str(e)}), 500


@acquisition_bp.route('/<int:acquisition_id>', methods=['GET'])
@login_required
def get_acquisition_request(acquisition_id):
    """
    Get details of a specific acquisition request

    GET /api/acquisition/123
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get acquisition request
        cursor.execute("""
            SELECT
                dar.*,
                u.email as user_email
            FROM domain_acquisition_requests dar
            JOIN users u ON dar.user_id = u.id
            WHERE dar.id = %s AND dar.user_id = %s;
        """, (acquisition_id, session['user_id']))

        acquisition = cursor.fetchone()

        if not acquisition:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Acquisition request not found'}), 404

        # Get updates (filter out internal-only updates for non-admin users)
        cursor.execute("""
            SELECT
                id, update_type, message, created_by, created_at
            FROM domain_acquisition_updates
            WHERE acquisition_id = %s AND internal_only = false
            ORDER BY created_at DESC;
        """, (acquisition_id,))

        updates = cursor.fetchall()

        cursor.close()
        conn.close()

        # Convert Decimal to float for JSON
        acquisition_dict = dict(acquisition)
        for key in ['investigation_fee', 'max_budget', 'seller_asking_price',
                    'our_offer_price', 'final_acquisition_cost', 'total_user_cost']:
            if acquisition_dict.get(key):
                acquisition_dict[key] = float(acquisition_dict[key])

        return jsonify({
            'success': True,
            'acquisition': acquisition_dict,
            'updates': [dict(u) for u in updates],
            'timeline': _generate_timeline(acquisition_dict, updates)
        }), 200

    except Exception as e:
        logger.error(f"Error fetching acquisition request: {str(e)}")
        return jsonify({'error': str(e)}), 500


@acquisition_bp.route('/list', methods=['GET'])
@login_required
def list_acquisition_requests():
    """
    List all acquisition requests for current user

    GET /api/acquisition/list?status=active&limit=20
    """
    try:
        status_filter = request.args.get('status', 'all')  # all, active, completed, failed
        limit = min(int(request.args.get('limit', 20)), 100)
        offset = int(request.args.get('offset', 0))

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Build query
        query = """
            SELECT
                dar.id,
                dar.domain_name,
                dar.status,
                dar.investigation_fee,
                dar.max_budget,
                dar.total_user_cost,
                dar.requested_at,
                dar.completed_at,
                COUNT(dau.id) as update_count
            FROM domain_acquisition_requests dar
            LEFT JOIN domain_acquisition_updates dau ON dar.id = dau.acquisition_id
            WHERE dar.user_id = %s
        """

        params = [session['user_id']]

        if status_filter == 'active':
            query += " AND dar.status NOT IN ('completed', 'failed')"
        elif status_filter == 'completed':
            query += " AND dar.status = 'completed'"
        elif status_filter == 'failed':
            query += " AND dar.status = 'failed'"

        query += """
            GROUP BY dar.id
            ORDER BY dar.created_at DESC
            LIMIT %s OFFSET %s;
        """

        params.extend([limit, offset])

        cursor.execute(query, params)
        requests_list = cursor.fetchall()

        # Get total count
        count_query = """
            SELECT COUNT(*) FROM domain_acquisition_requests
            WHERE user_id = %s
        """
        count_params = [session['user_id']]

        if status_filter == 'active':
            count_query += " AND status NOT IN ('completed', 'failed')"
        elif status_filter == 'completed':
            count_query += " AND status = 'completed'"
        elif status_filter == 'failed':
            count_query += " AND status = 'failed'"

        cursor.execute(count_query, count_params)
        total_count = cursor.fetchone()['count']

        cursor.close()
        conn.close()

        # Convert Decimals to floats
        requests_list_formatted = []
        for req in requests_list:
            req_dict = dict(req)
            for key in ['investigation_fee', 'max_budget', 'total_user_cost']:
                if req_dict.get(key):
                    req_dict[key] = float(req_dict[key])
            requests_list_formatted.append(req_dict)

        return jsonify({
            'success': True,
            'requests': requests_list_formatted,
            'total': total_count,
            'limit': limit,
            'offset': offset
        }), 200

    except Exception as e:
        logger.error(f"Error listing acquisition requests: {str(e)}")
        return jsonify({'error': str(e)}), 500


@acquisition_bp.route('/<int:acquisition_id>/cancel', methods=['POST'])
@login_required
def cancel_acquisition_request(acquisition_id):
    """
    Cancel an acquisition request (only if not yet completed)

    POST /api/acquisition/123/cancel
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if request exists and belongs to user
        cursor.execute("""
            SELECT status, investigation_payment_status
            FROM domain_acquisition_requests
            WHERE id = %s AND user_id = %s;
        """, (acquisition_id, session['user_id']))

        result = cursor.fetchone()

        if not result:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Acquisition request not found'}), 404

        status, payment_status = result

        if status in ('completed', 'failed'):
            cursor.close()
            conn.close()
            return jsonify({'error': f'Cannot cancel request with status: {status}'}), 400

        # Update status to failed
        cursor.execute("""
            UPDATE domain_acquisition_requests
            SET status = 'failed',
                failure_reason = 'Cancelled by user',
                failed_at = NOW()
            WHERE id = %s;
        """, (acquisition_id,))

        # Add update log
        cursor.execute("""
            INSERT INTO domain_acquisition_updates
            (acquisition_id, update_type, message, created_by)
            VALUES (%s, 'failed', 'Request cancelled by user', 'customer');
        """, (acquisition_id,))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Acquisition request {acquisition_id} cancelled by user {session['user_id']}")

        return jsonify({
            'success': True,
            'message': 'Acquisition request cancelled'
        }), 200

    except Exception as e:
        logger.error(f"Error cancelling acquisition request: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# WEBHOOK HANDLER (for Stripe payments)
# ============================================

@acquisition_bp.route('/webhook', methods=['POST'])
def acquisition_webhook():
    """
    Handle Stripe webhook events for acquisition payments

    This should be called by Stripe when payment events occur
    """
    try:
        payload = request.data
        sig_header = request.headers.get('Stripe-Signature')

        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
        endpoint_secret = os.getenv('STRIPE_ACQUISITION_WEBHOOK_SECRET')

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
        except ValueError:
            return jsonify({'error': 'Invalid payload'}), 400
        except stripe.error.SignatureVerificationError:
            return jsonify({'error': 'Invalid signature'}), 400

        # Handle specific events
        if event['type'] == 'checkout.session.completed':
            session_data = event['data']['object']

            # Check if this is an acquisition investigation payment
            if session_data.get('metadata', {}).get('type') == 'domain_acquisition_investigation':
                _handle_investigation_payment_success(session_data)

        elif event['type'] == 'payment_intent.succeeded':
            payment_intent = event['data']['object']
            # Handle final acquisition payment
            _handle_final_payment_success(payment_intent)

        return jsonify({'success': True}), 200

    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return jsonify({'error': str(e)}), 500


def _handle_investigation_payment_success(session_data):
    """Handle successful investigation fee payment"""
    try:
        session_id = session_data['id']
        metadata = session_data.get('metadata', {})
        domain = metadata.get('domain')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update request status
        cursor.execute("""
            UPDATE domain_acquisition_requests
            SET investigation_payment_status = 'paid',
                status = 'investigating',
                investigation_started_at = NOW()
            WHERE investigation_payment_id = %s;
        """, (session_id,))

        # Get the acquisition ID
        cursor.execute("""
            SELECT id FROM domain_acquisition_requests
            WHERE investigation_payment_id = %s;
        """, (session_id,))

        acq_id = cursor.fetchone()[0]

        # Add update
        cursor.execute("""
            INSERT INTO domain_acquisition_updates
            (acquisition_id, update_type, message, created_by)
            VALUES (%s, 'investigation_started',
                    'Payment received. Investigation started. We will research the current owner and attempt to make contact.',
                    'system');
        """, (acq_id,))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Investigation payment received for domain {domain}, acquisition {acq_id}")

        # TODO: Trigger investigation workflow (send to admin dashboard, run WHOIS, etc.)

    except Exception as e:
        logger.error(f"Error handling investigation payment: {str(e)}")


def _handle_final_payment_success(payment_intent):
    """Handle successful final acquisition payment"""
    try:
        # Extract acquisition ID from metadata
        metadata = payment_intent.get('metadata', {})
        acquisition_id = metadata.get('acquisition_id')

        if not acquisition_id:
            return

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update request
        cursor.execute("""
            UPDATE domain_acquisition_requests
            SET final_payment_id = %s,
                final_payment_status = 'paid',
                status = 'transfer_initiated'
            WHERE id = %s;
        """, (payment_intent['id'], acquisition_id))

        # Add update
        cursor.execute("""
            INSERT INTO domain_acquisition_updates
            (acquisition_id, update_type, message, created_by)
            VALUES (%s, 'payment_received',
                    'Final payment received. Initiating domain transfer process.',
                    'system');
        """, (acquisition_id,))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Final payment received for acquisition {acquisition_id}")

    except Exception as e:
        logger.error(f"Error handling final payment: {str(e)}")


def _generate_timeline(acquisition, updates):
    """Generate user-friendly timeline from acquisition data"""
    timeline = []

    if acquisition.get('requested_at'):
        timeline.append({
            'date': acquisition['requested_at'],
            'event': 'Request Created',
            'description': f"Requested acquisition of {acquisition['domain_name']}"
        })

    if acquisition.get('investigation_started_at'):
        timeline.append({
            'date': acquisition['investigation_started_at'],
            'event': 'Investigation Started',
            'description': 'Payment received, investigation in progress'
        })

    # Add update timeline events
    for update in updates:
        event_name = update['update_type'].replace('_', ' ').title()
        timeline.append({
            'date': update['created_at'],
            'event': event_name,
            'description': update['message']
        })

    return sorted(timeline, key=lambda x: x['date'], reverse=True)


# Export blueprint
__all__ = ['acquisition_bp']
