#!/usr/bin/env python3
"""
RESTful API Server for DNS Cache Validator
Provides HTTP API for programmatic access to DNS validation
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import sys
import os
from datetime import datetime
from typing import Dict, List

# Import main validator
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dns_cache_validator import DNSCacheValidator

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global validator instance
validator = None


def init_validator(config_file='dns_resolvers.json'):
    """Initialize global validator instance"""
    global validator
    validator = DNSCacheValidator(
        config_file=config_file,
        timeout=5,
        max_workers=50,
        retry_count=2
    )


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'resolvers_loaded': len(validator.resolvers) if validator else 0
    })


@app.route('/api/v1/resolvers', methods=['GET'])
def list_resolvers():
    """
    List all available DNS resolvers.

    Query parameters:
    - country: Filter by country code (e.g., US,CA)
    - region: Filter by region (e.g., europe,asia)
    - tier: Filter by tier (e.g., tier1,tier2)
    - tags: Filter by tags (e.g., public,security)
    """
    try:
        countries = request.args.get('country', '').split(',') if request.args.get('country') else None
        regions = request.args.get('region', '').split(',') if request.args.get('region') else None
        tiers = request.args.get('tier', '').split(',') if request.args.get('tier') else None
        tags = request.args.get('tags', '').split(',') if request.args.get('tags') else None

        filtered = validator.filter_resolvers(
            countries=countries,
            regions=regions,
            tiers=tiers,
            tags=tags
        )

        return jsonify({
            'total': len(filtered),
            'resolvers': filtered
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/validate', methods=['POST'])
def validate_domain():
    """
    Validate DNS propagation for a domain.

    Request body (JSON):
    {
        "domain": "example.com",
        "record_type": "A",  # optional, default: A
        "type_id": 1,  # optional, custom record type ID
        "countries": ["US", "CA"],  # optional
        "regions": ["europe", "asia"],  # optional
        "tiers": ["tier1"],  # optional
        "tags": ["public"],  # optional
        "limit": 50  # optional, limit number of resolvers
    }

    Response:
    {
        "results": [...],
        "analysis": {...}
    }
    """
    try:
        data = request.get_json()

        if not data or 'domain' not in data:
            return jsonify({'error': 'domain is required'}), 400

        domain = data['domain']
        record_type = data.get('record_type', 'A')
        type_id = data.get('type_id')

        # Validate domain and record type
        if not validator.validate_domain(domain):
            return jsonify({'error': 'Invalid domain name'}), 400

        if not validator.validate_record_type(record_type, type_id):
            return jsonify({'error': 'Invalid record type'}), 400

        # Filter resolvers
        filtered = validator.filter_resolvers(
            countries=data.get('countries'),
            regions=data.get('regions'),
            tiers=data.get('tiers'),
            tags=data.get('tags')
        )

        if data.get('limit'):
            filtered = filtered[:data['limit']]

        # Perform scan
        results = validator.validate_domain_scan(
            domain,
            record_type,
            filtered,
            type_id=type_id
        )

        # Analyze results
        analysis = validator.analyze_results(results)

        # Detect stale resolvers
        stale_resolvers = validator.detect_stale_resolvers(results, analysis)

        return jsonify({
            'domain': domain,
            'record_type': record_type,
            'timestamp': datetime.utcnow().isoformat(),
            'total_resolvers': len(filtered),
            'results': results,
            'analysis': analysis,
            'stale_resolvers': stale_resolvers
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/bulk-validate', methods=['POST'])
def bulk_validate():
    """
    Validate multiple domains.

    Request body (JSON):
    {
        "domains": ["example.com", "example.org"],
        "record_type": "A",  # optional
        "countries": ["US"],  # optional
        ...
    }
    """
    try:
        data = request.get_json()

        if not data or 'domains' not in data:
            return jsonify({'error': 'domains is required'}), 400

        domains = data['domains']
        if not isinstance(domains, list):
            return jsonify({'error': 'domains must be a list'}), 400

        record_type = data.get('record_type', 'A')
        type_id = data.get('type_id')

        # Filter resolvers once
        filtered = validator.filter_resolvers(
            countries=data.get('countries'),
            regions=data.get('regions'),
            tiers=data.get('tiers'),
            tags=data.get('tags')
        )

        if data.get('limit'):
            filtered = filtered[:data['limit']]

        # Validate each domain
        all_results = []
        for domain in domains:
            if not validator.validate_domain(domain):
                all_results.append({
                    'domain': domain,
                    'error': 'Invalid domain name'
                })
                continue

            results = validator.validate_domain_scan(
                domain,
                record_type,
                filtered,
                type_id=type_id
            )

            analysis = validator.analyze_results(results)

            all_results.append({
                'domain': domain,
                'results': results,
                'analysis': analysis
            })

        return jsonify({
            'timestamp': datetime.utcnow().isoformat(),
            'total_domains': len(domains),
            'domain_results': all_results
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/stats', methods=['GET'])
def get_stats():
    """Get statistics about loaded resolvers"""
    try:
        from collections import defaultdict

        by_country = defaultdict(int)
        by_region = defaultdict(int)
        by_tier = defaultdict(int)

        for resolver in validator.resolvers:
            by_country[resolver.get('country', 'Unknown')] += 1
            by_region[resolver.get('region', 'Unknown')] += 1
            by_tier[resolver.get('tier', 'Unknown')] += 1

        return jsonify({
            'total_resolvers': len(validator.resolvers),
            'by_country': dict(by_country),
            'by_region': dict(by_region),
            'by_tier': dict(by_tier)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


def run_server(host='0.0.0.0', port=5000, config_file='dns_resolvers.json', debug=False):
    """
    Run the API server.

    Args:
        host: Host to bind to
        port: Port to listen on
        config_file: DNS resolvers config file
        debug: Enable debug mode
    """
    init_validator(config_file)
    print(f"DNS Cache Validator API Server")
    print(f"Loaded {len(validator.resolvers)} DNS resolvers")
    print(f"Starting server on http://{host}:{port}")
    print(f"\nAPI Endpoints:")
    print(f"  GET  /api/v1/health         - Health check")
    print(f"  GET  /api/v1/resolvers      - List resolvers")
    print(f"  GET  /api/v1/stats          - Resolver statistics")
    print(f"  POST /api/v1/validate       - Validate single domain")
    print(f"  POST /api/v1/bulk-validate  - Validate multiple domains")
    print(f"\nPress Ctrl+C to stop\n")

    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='DNS Cache Validator API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--config', default='dns_resolvers.json', help='DNS resolvers config file')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    run_server(
        host=args.host,
        port=args.port,
        config_file=args.config,
        debug=args.debug
    )
