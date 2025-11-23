"""
OpenSRS API Routes for DNS Science Platform
Add these routes to app.py

These endpoints provide domain registration, SSL certificate ordering,
and portfolio management functionality integrated with OpenSRS.
"""

# ============================================================================
# OPENSRS DOMAIN & SSL CERTIFICATE API ENDPOINTS
# ============================================================================

@app.route('/api/domains/search', methods=['POST'])
@login_required
def search_domains():
    """
    Search domain availability via OpenSRS

    POST /api/domains/search
    Body: {
        "domains": ["example.com", "example.net", "example.org"]
    }

    Returns: {
        "results": [
            {
                "domain": "example.com",
                "available": true,
                "is_premium": false,
                "price_1_year": 12.99,
                "price_2_years": 24.99,
                "price_3_years": 35.99
            }
        ],
        "search_time": 0.234
    }
    """
    try:
        from opensrs_integration import OpenSRSIntegration
        import time

        data = request.get_json()
        if not data or 'domains' not in data:
            return jsonify({'error': 'Missing domains array'}), 400

        domains = data['domains']
        if not isinstance(domains, list) or len(domains) == 0:
            return jsonify({'error': 'Domains must be a non-empty array'}), 400

        if len(domains) > 20:
            return jsonify({'error': 'Maximum 20 domains per search'}), 400

        start_time = time.time()

        # Initialize OpenSRS integration
        opensrs = OpenSRSIntegration()

        # Check each domain
        results = []
        for domain in domains:
            domain = domain.strip().lower()
            availability = opensrs.check_domain_availability(domain)
            results.append({
                'domain': availability['domain'],
                'available': availability['available'],
                'is_premium': availability.get('is_premium', False),
                'price_1_year': availability.get('price_1_year'),
                'price_2_years': availability.get('price_2_years'),
                'price_3_years': availability.get('price_3_years'),
                'error': availability.get('error')
            })

        search_time = time.time() - start_time

        # Log search
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO opensrs_audit_log (
                user_id, action, resource_type, request_data,
                response_data, status, duration_ms, ip_address
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """, (
            session['user_id'],
            'search_domains',
            'domain',
            json.dumps({'domains': domains}),
            json.dumps({'results': results}),
            'success',
            int(search_time * 1000),
            request.remote_addr
        ))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'results': results,
            'search_time': round(search_time, 3),
            'count': len(results)
        })

    except Exception as e:
        logger.error(f"Domain search error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/register', methods=['POST'])
@login_required
def register_domain():
    """
    Register a new domain via OpenSRS

    POST /api/domains/register
    Body: {
        "domain": "example.com",
        "years": 1,
        "contacts": {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john@example.com",
            "phone": "+1.2125551234",
            "address1": "123 Main St",
            "city": "New York",
            "state": "NY",
            "postal_code": "10001",
            "country": "US"
        },
        "nameservers": ["ns1.dnsscience.io", "ns2.dnsscience.io"],
        "auto_renew": true,
        "whois_privacy": true,
        "payment_method": "stripe",
        "stripe_payment_method_id": "pm_xxx"
    }

    Returns: {
        "success": true,
        "order_id": 123,
        "order_number": "ORD-20251113-000001",
        "domain_id": 456,
        "domain": "example.com",
        "status": "processing",
        "message": "Domain registration initiated"
    }
    """
    try:
        from domain_payment_processor import DomainPaymentProcessor

        data = request.get_json()
        required = ['domain', 'years', 'contacts', 'payment_method']
        for field in required:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Validate contact information
        contact_required = ['first_name', 'last_name', 'email', 'phone',
                           'address1', 'city', 'state', 'postal_code', 'country']
        for field in contact_required:
            if field not in data['contacts']:
                return jsonify({'error': f'Missing contact field: {field}'}), 400

        # Initialize payment processor
        processor = DomainPaymentProcessor()

        # Process domain registration with payment
        result = processor.process_domain_registration(
            user_id=session['user_id'],
            domain=data['domain'],
            years=data['years'],
            contacts=data['contacts'],
            nameservers=data.get('nameservers', ['ns1.opensrs.net', 'ns2.opensrs.net']),
            auto_renew=data.get('auto_renew', True),
            whois_privacy=data.get('whois_privacy', True),
            payment_method=data['payment_method'],
            stripe_payment_method_id=data.get('stripe_payment_method_id')
        )

        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400

    except Exception as e:
        logger.error(f"Domain registration error: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/domains/list', methods=['GET'])
@login_required
def list_user_domains():
    """
    Get user's domain portfolio

    GET /api/domains/list?status=active

    Returns: {
        "domains": [
            {
                "id": 123,
                "domain_name": "example.com",
                "tld": ".com",
                "registered_at": "2025-01-01T00:00:00Z",
                "expires_at": "2026-01-01T00:00:00Z",
                "days_until_expiry": 365,
                "auto_renew_enabled": true,
                "whois_privacy_enabled": true,
                "status": "active",
                "nameservers": ["ns1.example.com", "ns2.example.com"]
            }
        ],
        "total": 1
    }
    """
    try:
        user_id = session['user_id']
        status_filter = request.args.get('status', 'active')

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        if status_filter == 'all':
            cursor.execute("""
                SELECT
                    id, domain_name, tld, registered_at, expires_at,
                    auto_renew_enabled, whois_privacy_enabled, status,
                    nameservers, purchase_price,
                    EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
                FROM domains_owned
                WHERE user_id = %s
                ORDER BY expires_at ASC;
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT
                    id, domain_name, tld, registered_at, expires_at,
                    auto_renew_enabled, whois_privacy_enabled, status,
                    nameservers, purchase_price,
                    EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
                FROM domains_owned
                WHERE user_id = %s AND status = %s
                ORDER BY expires_at ASC;
            """, (user_id, status_filter))

        domains = cursor.fetchall()
        cursor.close()
        conn.close()

        # Convert to JSON-serializable format
        domains_list = []
        for domain in domains:
            domain_dict = dict(domain)
            # Convert datetime objects to ISO format strings
            if domain_dict.get('registered_at'):
                domain_dict['registered_at'] = domain_dict['registered_at'].isoformat()
            if domain_dict.get('expires_at'):
                domain_dict['expires_at'] = domain_dict['expires_at'].isoformat()
            # Convert Decimal to float
            if domain_dict.get('purchase_price'):
                domain_dict['purchase_price'] = float(domain_dict['purchase_price'])
            domains_list.append(domain_dict)

        return jsonify({
            'success': True,
            'domains': domains_list,
            'total': len(domains_list)
        })

    except Exception as e:
        logger.error(f"List domains error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/<int:domain_id>/manage', methods=['POST'])
@login_required
def manage_domain(domain_id):
    """
    Update domain settings

    POST /api/domains/123/manage
    Body: {
        "action": "update_nameservers",
        "nameservers": ["ns1.example.com", "ns2.example.com"]
    }
    OR
    Body: {
        "action": "toggle_auto_renew",
        "auto_renew": true
    }
    OR
    Body: {
        "action": "toggle_whois_privacy",
        "whois_privacy": false
    }

    Returns: {
        "success": true,
        "message": "Domain settings updated"
    }
    """
    try:
        from opensrs_integration import OpenSRSIntegration

        data = request.get_json()
        user_id = session['user_id']

        if not data or 'action' not in data:
            return jsonify({'error': 'Missing action parameter'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Verify domain ownership
        cursor.execute("""
            SELECT * FROM domains_owned
            WHERE id = %s AND user_id = %s;
        """, (domain_id, user_id))
        domain = cursor.fetchone()

        if not domain:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Domain not found or access denied'}), 404

        action = data['action']
        opensrs = OpenSRSIntegration()

        if action == 'update_nameservers':
            nameservers = data.get('nameservers')
            if not nameservers or len(nameservers) < 2:
                return jsonify({'error': 'At least 2 nameservers required'}), 400

            # Update via OpenSRS
            result = opensrs.update_nameservers(domain['domain_name'], nameservers)

            if result['success']:
                # Update database
                cursor.execute("""
                    UPDATE domains_owned
                    SET nameservers = %s, updated_at = NOW()
                    WHERE id = %s;
                """, (nameservers, domain_id))
                conn.commit()

                message = f"Nameservers updated for {domain['domain_name']}"
            else:
                cursor.close()
                conn.close()
                return jsonify({'error': result.get('error')}), 400

        elif action == 'toggle_auto_renew':
            auto_renew = data.get('auto_renew', True)

            cursor.execute("""
                UPDATE domains_owned
                SET auto_renew_enabled = %s, updated_at = NOW()
                WHERE id = %s;
            """, (auto_renew, domain_id))
            conn.commit()

            message = f"Auto-renewal {'enabled' if auto_renew else 'disabled'} for {domain['domain_name']}"

        elif action == 'toggle_whois_privacy':
            whois_privacy = data.get('whois_privacy', True)

            # Update via OpenSRS
            result = opensrs.update_whois_privacy(domain['domain_name'], whois_privacy)

            if result['success']:
                cursor.execute("""
                    UPDATE domains_owned
                    SET whois_privacy_enabled = %s, updated_at = NOW()
                    WHERE id = %s;
                """, (whois_privacy, domain_id))
                conn.commit()

                message = f"WHOIS privacy {'enabled' if whois_privacy else 'disabled'} for {domain['domain_name']}"
            else:
                cursor.close()
                conn.close()
                return jsonify({'error': result.get('error')}), 400

        else:
            cursor.close()
            conn.close()
            return jsonify({'error': f'Unknown action: {action}'}), 400

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': message
        })

    except Exception as e:
        logger.error(f"Domain management error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ssl/products', methods=['GET'])
def list_ssl_products():
    """
    List available SSL certificate products

    GET /api/ssl/products

    Returns: {
        "products": [
            {
                "product_code": "dv_single",
                "name": "Domain Validated SSL",
                "type": "DV Single Domain",
                "price_1_year": 29.99,
                "price_2_years": 54.99,
                "validation_methods": ["email", "dns", "http"],
                "features": ["99.9% browser recognition", "2048-bit encryption"]
            }
        ]
    }
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT
                product_code, product_name, product_type,
                retail_1_year as price_1_year,
                retail_2_years as price_2_years,
                retail_3_years as price_3_years,
                is_available
            FROM opensrs_pricing_cache
            WHERE product_type = 'ssl' AND is_available = true
            ORDER BY retail_1_year ASC;
        """)

        products = cursor.fetchall()
        cursor.close()
        conn.close()

        # Convert to JSON-serializable
        products_list = []
        for product in products:
            product_dict = dict(product)
            # Convert Decimal to float
            for key in ['price_1_year', 'price_2_years', 'price_3_years']:
                if product_dict.get(key):
                    product_dict[key] = float(product_dict[key])
            products_list.append(product_dict)

        return jsonify({
            'success': True,
            'products': products_list,
            'total': len(products_list)
        })

    except Exception as e:
        logger.error(f"List SSL products error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ssl/list', methods=['GET'])
@login_required
def list_user_ssl_certificates():
    """
    Get user's SSL certificate inventory

    GET /api/ssl/list?status=active

    Returns: {
        "certificates": [
            {
                "id": 123,
                "domain_name": "example.com",
                "certificate_type": "dv_single",
                "ordered_at": "2025-01-01T00:00:00Z",
                "issued_at": "2025-01-02T00:00:00Z",
                "expires_at": "2026-01-02T00:00:00Z",
                "days_until_expiry": 365,
                "auto_renew_enabled": true,
                "status": "active",
                "validation_status": "completed"
            }
        ],
        "total": 1
    }
    """
    try:
        user_id = session['user_id']
        status_filter = request.args.get('status', 'active')

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        if status_filter == 'all':
            cursor.execute("""
                SELECT
                    id, domain_name, certificate_type, product_code,
                    ordered_at, issued_at, expires_at, auto_renew_enabled,
                    validation_method, validation_status, status, purchase_price,
                    EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
                FROM ssl_certificates_owned
                WHERE user_id = %s
                ORDER BY expires_at ASC;
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT
                    id, domain_name, certificate_type, product_code,
                    ordered_at, issued_at, expires_at, auto_renew_enabled,
                    validation_method, validation_status, status, purchase_price,
                    EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
                FROM ssl_certificates_owned
                WHERE user_id = %s AND status = %s
                ORDER BY expires_at ASC;
            """, (user_id, status_filter))

        certificates = cursor.fetchall()
        cursor.close()
        conn.close()

        # Convert to JSON-serializable
        certificates_list = []
        for cert in certificates:
            cert_dict = dict(cert)
            # Convert datetime objects
            for key in ['ordered_at', 'issued_at', 'expires_at']:
                if cert_dict.get(key):
                    cert_dict[key] = cert_dict[key].isoformat()
            # Convert Decimal
            if cert_dict.get('purchase_price'):
                cert_dict['purchase_price'] = float(cert_dict['purchase_price'])
            certificates_list.append(cert_dict)

        return jsonify({
            'success': True,
            'certificates': certificates_list,
            'total': len(certificates_list)
        })

    except Exception as e:
        logger.error(f"List SSL certificates error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/orders/history', methods=['GET'])
@login_required
def get_order_history():
    """
    Get user's complete order history

    GET /api/orders/history?limit=20&offset=0

    Returns: {
        "orders": [
            {
                "id": 123,
                "order_number": "ORD-20251113-000001",
                "order_type": "domain_registration",
                "domain_name": "example.com",
                "product_type": ".com",
                "years": 1,
                "total": 12.99,
                "status": "completed",
                "created_at": "2025-01-01T00:00:00Z",
                "completed_at": "2025-01-01T00:05:00Z"
            }
        ],
        "total": 1,
        "limit": 20,
        "offset": 0
    }
    """
    try:
        user_id = session['user_id']
        limit = int(request.args.get('limit', 20))
        offset = int(request.args.get('offset', 0))

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Get total count
        cursor.execute("""
            SELECT COUNT(*) as total
            FROM opensrs_orders
            WHERE user_id = %s;
        """, (user_id,))
        total = cursor.fetchone()['total']

        # Get orders with pagination
        cursor.execute("""
            SELECT
                id, order_number, order_type, domain_name, product_type,
                years, subtotal, tax, discount, total, payment_method,
                status, error_message, created_at, completed_at
            FROM opensrs_orders
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s;
        """, (user_id, limit, offset))

        orders = cursor.fetchall()
        cursor.close()
        conn.close()

        # Convert to JSON-serializable
        orders_list = []
        for order in orders:
            order_dict = dict(order)
            # Convert datetime objects
            for key in ['created_at', 'completed_at']:
                if order_dict.get(key):
                    order_dict[key] = order_dict[key].isoformat()
            # Convert Decimal
            for key in ['subtotal', 'tax', 'discount', 'total']:
                if order_dict.get(key):
                    order_dict[key] = float(order_dict[key])
            orders_list.append(order_dict)

        return jsonify({
            'success': True,
            'orders': orders_list,
            'total': total,
            'limit': limit,
            'offset': offset
        })

    except Exception as e:
        logger.error(f"Order history error: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# OPENSRS WEBHOOK HANDLER
# ============================================================================

@app.route('/api/webhooks/opensrs', methods=['POST'])
def opensrs_webhook():
    """
    Handle OpenSRS webhooks for domain/SSL status updates

    POST /api/webhooks/opensrs
    Headers:
        X-OpenSRS-Signature: <hmac_signature>
    Body: {
        "event": "domain.registered",
        "domain": "example.com",
        "order_id": "123456",
        "status": "active",
        "timestamp": "2025-01-01T00:00:00Z"
    }

    Returns: {
        "success": true,
        "message": "Webhook processed"
    }
    """
    try:
        import hmac
        import hashlib

        # Verify webhook signature
        signature = request.headers.get('X-OpenSRS-Signature')
        webhook_secret = os.getenv('OPENSRS_WEBHOOK_SECRET')

        if not signature or not webhook_secret:
            logger.warning("OpenSRS webhook received without proper signature")
            return jsonify({'error': 'Invalid signature'}), 401

        # Calculate expected signature
        payload = request.get_data()
        expected_signature = hmac.new(
            webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("OpenSRS webhook signature mismatch")
            return jsonify({'error': 'Invalid signature'}), 401

        data = request.get_json()
        event = data.get('event')

        logger.info(f"OpenSRS webhook received: {event}")

        # Process different event types
        if event == 'domain.registered':
            # Update domain status in database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE domains_owned
                SET status = 'active', last_synced_at = NOW()
                WHERE opensrs_order_id = %s;
            """, (data.get('order_id'),))
            conn.commit()
            cursor.close()
            conn.close()

        elif event == 'domain.expired':
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE domains_owned
                SET status = 'expired', last_synced_at = NOW()
                WHERE domain_name = %s;
            """, (data.get('domain'),))
            conn.commit()
            cursor.close()
            conn.close()

        elif event == 'ssl.issued':
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE ssl_certificates_owned
                SET status = 'active',
                    issued_at = NOW(),
                    validation_status = 'completed',
                    last_synced_at = NOW()
                WHERE opensrs_order_id = %s;
            """, (data.get('order_id'),))
            conn.commit()
            cursor.close()
            conn.close()

        # Log webhook receipt
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO opensrs_audit_log (
                action, resource_type, resource_id,
                request_data, status, created_at
            ) VALUES (%s, %s, %s, %s, %s, NOW());
        """, (
            f'webhook_{event}',
            'webhook',
            data.get('order_id'),
            json.dumps(data),
            'success'
        ))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Webhook processed'
        }), 200

    except Exception as e:
        logger.error(f"OpenSRS webhook error: {str(e)}")
        return jsonify({'error': str(e)}), 500
