#!/usr/bin/env python3
"""
Update OpenSRS Configuration with Encrypted API Credentials

This script updates the opensrs_config table with properly encrypted
API credentials using Fernet symmetric encryption.
"""

import os
import sys
import psycopg2
from cryptography.fernet import Fernet
import base64
import hashlib

# Database credentials
DB_HOST = 'dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com'
DB_PORT = 5432
DB_NAME = 'dnsscience'
DB_USER = 'dnsscience'
DB_PASS = 'lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK'

# OpenSRS Credentials
OPENSRS_USERNAME = 'dnsscience'
OPENSRS_API_KEY = '00dd197645dd6620493dd3ba110b53ac9cecea48fece9d6058b980d55df89a774fdf52350e8f968d7374a551b8ef902dde6083985ce99184'

# Generate or use existing encryption key
# In production, this should be stored in a secure location (AWS Secrets Manager, etc.)
ENCRYPTION_KEY_SOURCE = f"{DB_NAME}-opensrs-encryption-key-v1"
# Create a deterministic key from a hash (in production, use a proper secret management system)
key_material = hashlib.sha256(ENCRYPTION_KEY_SOURCE.encode()).digest()
ENCRYPTION_KEY = base64.urlsafe_b64encode(key_material)


def encrypt_api_key(api_key: str, encryption_key: bytes) -> tuple:
    """
    Encrypt the API key using Fernet symmetric encryption

    Returns:
        tuple: (encrypted_data, initialization_vector)
    """
    fernet = Fernet(encryption_key)
    encrypted = fernet.encrypt(api_key.encode())

    # Extract IV from the encrypted data
    # Fernet format: Version (1 byte) | Timestamp (8 bytes) | IV (16 bytes) | Ciphertext | HMAC (32 bytes)
    iv = base64.urlsafe_b64encode(encrypted[9:25]).decode()  # Extract the 16-byte IV
    encrypted_b64 = base64.urlsafe_b64encode(encrypted).decode()

    return encrypted_b64, iv


def update_opensrs_config():
    """Update the opensrs_config table with encrypted credentials"""

    print("=" * 70)
    print("OpenSRS Configuration Update")
    print("=" * 70)

    try:
        # Connect to database
        print(f"\nConnecting to database: {DB_HOST}")
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        cursor = conn.cursor()
        print("✓ Database connection established")

        # Encrypt API key
        print(f"\nEncrypting API key...")
        encrypted_key, iv = encrypt_api_key(OPENSRS_API_KEY, ENCRYPTION_KEY)
        print(f"✓ API key encrypted (length: {len(encrypted_key)})")
        print(f"✓ IV generated (length: {len(iv)})")

        # Update or insert configuration
        print(f"\nUpdating opensrs_config table...")

        # Check if placeholder config exists
        cursor.execute("SELECT id FROM opensrs_config WHERE reseller_username = 'PLACEHOLDER_USERNAME';")
        placeholder = cursor.fetchone()

        if placeholder:
            # Update existing placeholder
            print("Found placeholder config, updating...")
            cursor.execute("""
                UPDATE opensrs_config
                SET reseller_username = %s,
                    api_key_encrypted = %s,
                    encryption_iv = %s,
                    environment = %s,
                    api_endpoint = %s,
                    is_active = %s,
                    updated_at = CURRENT_TIMESTAMP,
                    last_key_rotation = CURRENT_TIMESTAMP
                WHERE reseller_username = 'PLACEHOLDER_USERNAME';
            """, (
                OPENSRS_USERNAME,
                encrypted_key,
                iv,
                'test',  # Start with test/horizon environment
                'https://horizon.opensrs.net:55443',
                True
            ))
        else:
            # Insert new config
            print("No placeholder found, inserting new config...")
            cursor.execute("""
                INSERT INTO opensrs_config (
                    reseller_username,
                    api_key_encrypted,
                    encryption_iv,
                    environment,
                    api_endpoint,
                    api_port,
                    is_active,
                    domain_margin_percent,
                    ssl_margin_percent,
                    transfer_margin_percent,
                    last_key_rotation
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT DO NOTHING;
            """, (
                OPENSRS_USERNAME,
                encrypted_key,
                iv,
                'test',  # Start with test/horizon environment
                'https://horizon.opensrs.net:55443',
                55443,
                True,
                20.00,  # 20% domain markup
                30.00,  # 30% SSL markup
                15.00   # 15% transfer markup
            ))

        conn.commit()
        print("✓ Configuration updated successfully")

        # Verify configuration
        print("\n" + "=" * 70)
        print("Verifying Configuration")
        print("=" * 70)
        cursor.execute("""
            SELECT id, reseller_username, environment, api_endpoint,
                   is_active, domain_margin_percent, ssl_margin_percent,
                   LENGTH(api_key_encrypted) as key_length
            FROM opensrs_config
            WHERE reseller_username = %s;
        """, (OPENSRS_USERNAME,))

        config = cursor.fetchone()
        if config:
            print(f"\n✓ Configuration found:")
            print(f"  ID: {config[0]}")
            print(f"  Username: {config[1]}")
            print(f"  Environment: {config[2]}")
            print(f"  API Endpoint: {config[3]}")
            print(f"  Active: {config[4]}")
            print(f"  Domain Margin: {config[5]}%")
            print(f"  SSL Margin: {config[6]}%")
            print(f"  Encrypted Key Length: {config[7]} bytes")
        else:
            print("✗ Configuration verification failed!")
            sys.exit(1)

        # Test decryption
        print("\nTesting decryption...")
        fernet = Fernet(ENCRYPTION_KEY)
        cursor.execute("SELECT api_key_encrypted FROM opensrs_config WHERE reseller_username = %s;", (OPENSRS_USERNAME,))
        stored_encrypted = cursor.fetchone()[0]

        # Decode from base64
        encrypted_bytes = base64.urlsafe_b64decode(stored_encrypted.encode())
        decrypted = fernet.decrypt(encrypted_bytes).decode()

        if decrypted == OPENSRS_API_KEY:
            print("✓ Decryption test passed - API key matches")
        else:
            print("✗ Decryption test failed - API key mismatch!")
            sys.exit(1)

        cursor.close()
        conn.close()

        print("\n" + "=" * 70)
        print("SUCCESS: OpenSRS configuration updated successfully")
        print("=" * 70)
        print("\nNext steps:")
        print("1. Deploy opensrs_integration.py to production")
        print("2. Deploy domain_payment_processor.py")
        print("3. Update app.py with OpenSRS API endpoints")
        print("4. Test domain search functionality")

    except Exception as e:
        print(f"\n✗ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    update_opensrs_config()
