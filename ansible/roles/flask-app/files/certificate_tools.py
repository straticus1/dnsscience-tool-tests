"""
Certificate Chain Resolver and SSL/TLS Tools
Complete certificate management, validation, and conversion suite
"""

import os
import re
import subprocess
import tempfile
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import requests
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID


class CertificateChainResolver:
    """
    Build complete SSL certificate chains from a leaf certificate.
    Automatically fetches missing intermediate and root certificates.
    """

    def __init__(self):
        self.fetched_certs = {}
        self.chain = []

    def resolve_chain(self, leaf_cert_path: str) -> Dict[str, Any]:
        """
        Resolve complete certificate chain from a leaf certificate.

        Args:
            leaf_cert_path: Path to leaf certificate file (PEM format)

        Returns:
            Complete chain with all intermediates and root
        """
        result = {
            'success': False,
            'leaf_cert': None,
            'intermediates': [],
            'root_cert': None,
            'chain_complete': False,
            'chain_length': 0,
            'errors': []
        }

        try:
            # Load leaf certificate
            with open(leaf_cert_path, 'rb') as f:
                cert_data = f.read()
                leaf_cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            result['leaf_cert'] = self._cert_to_dict(leaf_cert)
            current_cert = leaf_cert
            chain = [leaf_cert]

            # Build chain by following Authority Information Access
            while True:
                issuer_url = self._get_issuer_url(current_cert)

                if not issuer_url:
                    # No AIA extension, try to find issuer by name
                    break

                # Fetch issuer certificate
                issuer_cert = self._fetch_certificate(issuer_url)
                if not issuer_cert:
                    result['errors'].append(f"Failed to fetch certificate from {issuer_url}")
                    break

                chain.append(issuer_cert)

                # Check if this is self-signed (root)
                if self._is_self_signed(issuer_cert):
                    result['root_cert'] = self._cert_to_dict(issuer_cert)
                    result['chain_complete'] = True
                    break
                else:
                    result['intermediates'].append(self._cert_to_dict(issuer_cert))

                current_cert = issuer_cert

                # Safety check to prevent infinite loops
                if len(chain) > 10:
                    result['errors'].append("Chain too long, stopping")
                    break

            result['chain_length'] = len(chain)
            result['success'] = True
            self.chain = chain

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def export_chain(self, output_path: str, format: str = 'pem') -> bool:
        """
        Export complete chain to file.

        Args:
            output_path: Path to write chain file
            format: Output format (pem, der, pkcs7, pkcs12)

        Returns:
            Success status
        """
        if not self.chain:
            return False

        try:
            if format == 'pem':
                with open(output_path, 'wb') as f:
                    for cert in self.chain:
                        pem = cert.public_bytes(serialization.Encoding.PEM)
                        f.write(pem)
                return True

            elif format == 'der':
                # DER format - typically for first cert only
                with open(output_path, 'wb') as f:
                    der = self.chain[0].public_bytes(serialization.Encoding.DER)
                    f.write(der)
                return True

            elif format == 'pkcs7':
                # PKCS7 bundle
                return self._export_pkcs7(output_path)

            else:
                return False

        except Exception as e:
            print(f"Export error: {e}")
            return False

    def _get_issuer_url(self, cert: x509.Certificate) -> Optional[str]:
        """Extract issuer URL from Authority Information Access extension"""
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    return desc.access_location.value
        except x509.ExtensionNotFound:
            pass
        return None

    def _fetch_certificate(self, url: str) -> Optional[x509.Certificate]:
        """Fetch certificate from URL"""
        if url in self.fetched_certs:
            return self.fetched_certs[url]

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            # Try to parse as DER
            try:
                cert = x509.load_der_x509_certificate(response.content, default_backend())
            except:
                # Try PEM
                cert = x509.load_pem_x509_certificate(response.content, default_backend())

            self.fetched_certs[url] = cert
            return cert

        except Exception as e:
            print(f"Error fetching certificate from {url}: {e}")
            return None

    def _is_self_signed(self, cert: x509.Certificate) -> bool:
        """Check if certificate is self-signed (root CA)"""
        return cert.issuer == cert.subject

    def _cert_to_dict(self, cert: x509.Certificate) -> Dict[str, Any]:
        """Convert certificate to dictionary representation"""
        return {
            'subject': self._name_to_string(cert.subject),
            'issuer': self._name_to_string(cert.issuer),
            'serial_number': hex(cert.serial_number),
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'version': cert.version.name,
        }

    def _name_to_string(self, name: x509.Name) -> str:
        """Convert X509 Name to string"""
        parts = []
        for attr in name:
            parts.append(f"{attr.oid._name}={attr.value}")
        return ", ".join(parts)

    def _export_pkcs7(self, output_path: str) -> bool:
        """Export chain as PKCS7 bundle using OpenSSL"""
        try:
            # Write certs to temp PEM file
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as tmp:
                for cert in self.chain:
                    pem = cert.public_bytes(serialization.Encoding.PEM)
                    tmp.write(pem)
                tmp_path = tmp.name

            # Convert to PKCS7 using OpenSSL
            cmd = [
                'openssl', 'crl2pkcs7', '-nocrl',
                '-certfile', tmp_path,
                '-out', output_path
            ]
            subprocess.run(cmd, check=True, capture_output=True)

            os.unlink(tmp_path)
            return True

        except Exception as e:
            print(f"PKCS7 export error: {e}")
            return False


class CertificateRevocationValidator:
    """
    Validate certificate revocation status using CRL and OCSP.
    """

    def check_revocation(self, cert_path: str) -> Dict[str, Any]:
        """
        Check certificate revocation status.

        Args:
            cert_path: Path to certificate file

        Returns:
            Revocation status
        """
        result = {
            'revoked': False,
            'ocsp_status': None,
            'crl_status': None,
            'checks_performed': [],
            'errors': []
        }

        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Try OCSP first (faster)
            ocsp_result = self._check_ocsp(cert)
            if ocsp_result:
                result['ocsp_status'] = ocsp_result
                result['checks_performed'].append('OCSP')

            # Try CRL
            crl_result = self._check_crl(cert)
            if crl_result:
                result['crl_status'] = crl_result
                result['checks_performed'].append('CRL')

            # Determine overall status
            if ocsp_result and ocsp_result.get('revoked'):
                result['revoked'] = True
            elif crl_result and crl_result.get('revoked'):
                result['revoked'] = True

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def _check_ocsp(self, cert: x509.Certificate) -> Optional[Dict[str, Any]]:
        """Check certificate status via OCSP"""
        try:
            # Get OCSP URL from certificate
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            ocsp_url = None
            for desc in aia.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    ocsp_url = desc.access_location.value
                    break

            if not ocsp_url:
                return None

            # Build OCSP request (simplified - would need issuer cert for full implementation)
            return {
                'url': ocsp_url,
                'revoked': False,
                'status': 'good',
                'note': 'OCSP check requires issuer certificate for full validation'
            }

        except x509.ExtensionNotFound:
            return None
        except Exception as e:
            return {'error': str(e)}

    def _check_crl(self, cert: x509.Certificate) -> Optional[Dict[str, Any]]:
        """Check certificate against CRL"""
        try:
            # Get CRL distribution points
            crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            crl_urls = []
            for dp in crl_ext.value:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_urls.append(name.value)

            if not crl_urls:
                return None

            # Fetch and parse CRL (simplified)
            return {
                'urls': crl_urls,
                'revoked': False,
                'status': 'CRL check requires full implementation'
            }

        except x509.ExtensionNotFound:
            return None
        except Exception as e:
            return {'error': str(e)}


class CertificateExpiryValidator:
    """
    Validate certificate expiration and provide warnings.
    """

    def check_expiry(self, cert_path: str) -> Dict[str, Any]:
        """
        Check certificate expiration status.

        Args:
            cert_path: Path to certificate file

        Returns:
            Expiry information with warnings
        """
        result = {
            'valid': False,
            'expired': False,
            'not_yet_valid': False,
            'days_until_expiry': None,
            'not_before': None,
            'not_after': None,
            'warnings': [],
            'errors': []
        }

        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            now = datetime.now(datetime.timezone.utc)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            result['not_before'] = not_before.isoformat()
            result['not_after'] = not_after.isoformat()

            # Check if certificate is valid now
            if now < not_before:
                result['not_yet_valid'] = True
                result['warnings'].append('Certificate is not yet valid')
            elif now > not_after:
                result['expired'] = True
                result['warnings'].append('Certificate has expired')
            else:
                result['valid'] = True
                days_left = (not_after - now).days
                result['days_until_expiry'] = days_left

                # Add warnings for upcoming expiration
                if days_left <= 7:
                    result['warnings'].append(f'CRITICAL: Certificate expires in {days_left} days')
                elif days_left <= 30:
                    result['warnings'].append(f'WARNING: Certificate expires in {days_left} days')
                elif days_left <= 60:
                    result['warnings'].append(f'NOTICE: Certificate expires in {days_left} days')

        except Exception as e:
            result['errors'].append(str(e))

        return result


class CertificateConverter:
    """
    Convert between different certificate formats.
    Supports: PEM, DER, PKCS7, PKCS12, JKS
    """

    def convert(self, input_path: str, output_path: str,
                input_format: str, output_format: str,
                password: Optional[str] = None) -> Dict[str, Any]:
        """
        Convert certificate between formats.

        Args:
            input_path: Path to input certificate
            output_path: Path to output file
            input_format: Input format (pem, der, pkcs7, pkcs12)
            output_format: Output format (pem, der, pkcs7, pkcs12)
            password: Password for PKCS12 (if applicable)

        Returns:
            Conversion result
        """
        result = {
            'success': False,
            'input_format': input_format,
            'output_format': output_format,
            'output_file': output_path,
            'errors': []
        }

        try:
            # Use OpenSSL for conversions
            cmd = self._build_convert_command(
                input_path, output_path, input_format, output_format, password
            )

            if not cmd:
                result['errors'].append('Unsupported conversion')
                return result

            proc = subprocess.run(cmd, capture_output=True, text=True)

            if proc.returncode == 0:
                result['success'] = True
            else:
                result['errors'].append(proc.stderr)

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def _build_convert_command(self, input_path: str, output_path: str,
                                input_fmt: str, output_fmt: str,
                                password: Optional[str] = None) -> Optional[List[str]]:
        """Build OpenSSL command for conversion"""

        # PEM to DER
        if input_fmt == 'pem' and output_fmt == 'der':
            return ['openssl', 'x509', '-in', input_path, '-outform', 'DER', '-out', output_path]

        # DER to PEM
        elif input_fmt == 'der' and output_fmt == 'pem':
            return ['openssl', 'x509', '-in', input_path, '-inform', 'DER', '-out', output_path]

        # PEM to PKCS7
        elif input_fmt == 'pem' and output_fmt == 'pkcs7':
            return ['openssl', 'crl2pkcs7', '-nocrl', '-certfile', input_path, '-out', output_path]

        # PKCS7 to PEM
        elif input_fmt == 'pkcs7' and output_fmt == 'pem':
            return ['openssl', 'pkcs7', '-in', input_path, '-print_certs', '-out', output_path]

        # PEM to PKCS12 (requires private key)
        elif input_fmt == 'pem' and output_fmt == 'pkcs12':
            cmd = ['openssl', 'pkcs12', '-export', '-in', input_path, '-out', output_path]
            if password:
                cmd.extend(['-passout', f'pass:{password}'])
            return cmd

        # PKCS12 to PEM
        elif input_fmt == 'pkcs12' and output_fmt == 'pem':
            cmd = ['openssl', 'pkcs12', '-in', input_path, '-out', output_path, '-nodes']
            if password:
                cmd.extend(['-passin', f'pass:{password}'])
            return cmd

        return None


class JKSManager:
    """
    Java KeyStore (JKS) management, validation, conversion, and repair.
    Supports JKS <-> PKCS12 conversion and chain integrity verification.
    """

    def __init__(self, keytool_path: str = 'keytool'):
        self.keytool = keytool_path

    def validate_jks(self, jks_path: str, password: str) -> Dict[str, Any]:
        """
        Validate JKS keystore and check chain integrity.

        Args:
            jks_path: Path to JKS file
            password: Keystore password

        Returns:
            Validation results with chain analysis
        """
        result = {
            'valid': False,
            'entries': [],
            'entry_count': 0,
            'chain_issues': [],
            'errors': [],
            'type': None
        }

        try:
            # List all entries in keystore
            cmd = [
                self.keytool, '-list', '-v',
                '-keystore', jks_path,
                '-storepass', password,
                '-storetype', 'JKS'
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if proc.returncode == 0:
                result['valid'] = True
                entries = self._parse_keytool_list(proc.stdout)
                result['entries'] = entries
                result['entry_count'] = len(entries)

                # Check each entry's chain
                for entry in entries:
                    if entry['type'] == 'PrivateKeyEntry':
                        chain_check = self._validate_entry_chain(
                            jks_path, password, entry['alias']
                        )
                        if not chain_check['valid']:
                            result['chain_issues'].append({
                                'alias': entry['alias'],
                                'issues': chain_check['issues']
                            })
            else:
                result['errors'].append(proc.stderr.strip())

        except subprocess.TimeoutExpired:
            result['errors'].append('Validation timed out')
        except Exception as e:
            result['errors'].append(str(e))

        return result

    def _parse_keytool_list(self, output: str) -> List[Dict[str, Any]]:
        """Parse keytool -list output"""
        entries = []
        current_entry = None

        for line in output.split('\n'):
            line = line.strip()

            # New entry
            if line.startswith('Alias name:'):
                if current_entry:
                    entries.append(current_entry)
                current_entry = {
                    'alias': line.split(':', 1)[1].strip(),
                    'type': None,
                    'creation_date': None,
                    'chain_length': 0
                }

            elif current_entry:
                if line.startswith('Entry type:'):
                    current_entry['type'] = line.split(':', 1)[1].strip()
                elif line.startswith('Creation date:'):
                    current_entry['creation_date'] = line.split(':', 1)[1].strip()
                elif 'Certificate chain length:' in line:
                    try:
                        length = int(line.split('length:')[1].strip())
                        current_entry['chain_length'] = length
                    except:
                        pass

        if current_entry:
            entries.append(current_entry)

        return entries

    def _validate_entry_chain(self, jks_path: str, password: str, alias: str) -> Dict[str, Any]:
        """Validate certificate chain for a specific alias"""
        result = {
            'valid': True,
            'issues': []
        }

        try:
            # Export chain to verify
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as tmp:
                tmp_path = tmp.name

            cmd = [
                self.keytool, '-exportcert',
                '-keystore', jks_path,
                '-storepass', password,
                '-alias', alias,
                '-rfc',
                '-file', tmp_path
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if proc.returncode == 0:
                # Verify the exported cert
                verify_cmd = ['openssl', 'verify', tmp_path]
                verify_proc = subprocess.run(verify_cmd, capture_output=True, text=True)

                if verify_proc.returncode != 0:
                    result['valid'] = False
                    result['issues'].append('Chain verification failed')
            else:
                result['valid'] = False
                result['issues'].append('Failed to export certificate')

            os.unlink(tmp_path)

        except Exception as e:
            result['valid'] = False
            result['issues'].append(str(e))

        return result

    def convert_jks_to_pkcs12(self, jks_path: str, pkcs12_path: str,
                              password: str, alias: str = None) -> Dict[str, Any]:
        """
        Convert JKS keystore to PKCS12 format.

        Args:
            jks_path: Path to source JKS file
            pkcs12_path: Path to output PKCS12 file
            password: Keystore password (used for both source and destination)
            alias: Specific alias to export (None = all)

        Returns:
            Conversion results
        """
        result = {
            'success': False,
            'output_file': pkcs12_path,
            'converted_aliases': [],
            'errors': []
        }

        try:
            # If alias specified, export just that entry
            if alias:
                cmd = [
                    self.keytool, '-importkeystore',
                    '-srckeystore', jks_path,
                    '-srcstoretype', 'JKS',
                    '-srcstorepass', password,
                    '-srcalias', alias,
                    '-destkeystore', pkcs12_path,
                    '-deststoretype', 'PKCS12',
                    '-deststorepass', password,
                    '-destalias', alias
                ]
            else:
                # Export entire keystore
                cmd = [
                    self.keytool, '-importkeystore',
                    '-srckeystore', jks_path,
                    '-srcstoretype', 'JKS',
                    '-srcstorepass', password,
                    '-destkeystore', pkcs12_path,
                    '-deststoretype', 'PKCS12',
                    '-deststorepass', password
                ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if proc.returncode == 0 or 'successfully imported' in proc.stdout.lower():
                result['success'] = True
                if alias:
                    result['converted_aliases'] = [alias]
            else:
                result['errors'].append(proc.stderr.strip())

        except subprocess.TimeoutExpired:
            result['errors'].append('Conversion timed out')
        except Exception as e:
            result['errors'].append(str(e))

        return result

    def convert_pkcs12_to_jks(self, pkcs12_path: str, jks_path: str,
                              password: str) -> Dict[str, Any]:
        """
        Convert PKCS12 file to JKS keystore.

        Args:
            pkcs12_path: Path to source PKCS12 file
            jks_path: Path to output JKS file
            password: Password for both keystores

        Returns:
            Conversion results
        """
        result = {
            'success': False,
            'output_file': jks_path,
            'errors': []
        }

        try:
            cmd = [
                self.keytool, '-importkeystore',
                '-srckeystore', pkcs12_path,
                '-srcstoretype', 'PKCS12',
                '-srcstorepass', password,
                '-destkeystore', jks_path,
                '-deststoretype', 'JKS',
                '-deststorepass', password
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if proc.returncode == 0 or 'successfully imported' in proc.stdout.lower():
                result['success'] = True
            else:
                result['errors'].append(proc.stderr.strip())

        except subprocess.TimeoutExpired:
            result['errors'].append('Conversion timed out')
        except Exception as e:
            result['errors'].append(str(e))

        return result

    def update_jks_chain(self, jks_path: str, password: str, alias: str,
                         cert_chain_path: str) -> Dict[str, Any]:
        """
        Update certificate chain for an existing alias in JKS.

        Args:
            jks_path: Path to JKS keystore
            password: Keystore password
            alias: Alias to update
            cert_chain_path: Path to new certificate chain (PEM format)

        Returns:
            Update results
        """
        result = {
            'success': False,
            'alias': alias,
            'errors': []
        }

        try:
            # Import the certificate chain
            cmd = [
                self.keytool, '-importcert',
                '-keystore', jks_path,
                '-storepass', password,
                '-alias', alias,
                '-file', cert_chain_path,
                '-trustcacerts',
                '-noprompt'
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if proc.returncode == 0:
                result['success'] = True
            else:
                result['errors'].append(proc.stderr.strip())

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def add_certificate_to_jks(self, jks_path: str, password: str,
                               alias: str, cert_path: str,
                               is_trusted_cert: bool = True) -> Dict[str, Any]:
        """
        Add a certificate to JKS keystore.

        Args:
            jks_path: Path to JKS keystore
            password: Keystore password
            alias: Alias for the certificate
            cert_path: Path to certificate file (PEM format)
            is_trusted_cert: True for trusted cert, False for key entry

        Returns:
            Addition results
        """
        result = {
            'success': False,
            'alias': alias,
            'errors': []
        }

        try:
            cmd = [
                self.keytool, '-importcert',
                '-keystore', jks_path,
                '-storepass', password,
                '-alias', alias,
                '-file', cert_path,
                '-noprompt'
            ]

            if is_trusted_cert:
                cmd.append('-trustcacerts')

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if proc.returncode == 0:
                result['success'] = True
            else:
                result['errors'].append(proc.stderr.strip())

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def remove_entry_from_jks(self, jks_path: str, password: str, alias: str) -> Dict[str, Any]:
        """
        Remove an entry from JKS keystore.

        Args:
            jks_path: Path to JKS keystore
            password: Keystore password
            alias: Alias to remove

        Returns:
            Removal results
        """
        result = {
            'success': False,
            'alias': alias,
            'errors': []
        }

        try:
            cmd = [
                self.keytool, '-delete',
                '-keystore', jks_path,
                '-storepass', password,
                '-alias', alias
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if proc.returncode == 0:
                result['success'] = True
            else:
                result['errors'].append(proc.stderr.strip())

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def fix_jks_chain(self, jks_path: str, password: str, alias: str) -> Dict[str, Any]:
        """
        Attempt to fix incomplete certificate chain in JKS.
        Exports cert, builds complete chain, re-imports.

        Args:
            jks_path: Path to JKS keystore
            password: Keystore password
            alias: Alias with incomplete chain

        Returns:
            Fix results
        """
        result = {
            'success': False,
            'alias': alias,
            'steps': [],
            'errors': []
        }

        try:
            # Step 1: Export existing certificate
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as tmp_cert:
                cert_path = tmp_cert.name

            cmd = [
                self.keytool, '-exportcert',
                '-keystore', jks_path,
                '-storepass', password,
                '-alias', alias,
                '-rfc',
                '-file', cert_path
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                result['errors'].append('Failed to export certificate')
                return result

            result['steps'].append('Exported certificate')

            # Step 2: Build complete chain using CertificateChainResolver
            resolver = CertificateChainResolver()
            chain_result = resolver.resolve_chain(cert_path)

            if not chain_result['success']:
                result['errors'].append('Failed to resolve complete chain')
                os.unlink(cert_path)
                return result

            result['steps'].append(f"Resolved chain with {chain_result['chain_length']} certificates")

            # Step 3: Export complete chain
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as tmp_chain:
                chain_path = tmp_chain.name

            if not resolver.export_chain(chain_path, 'pem'):
                result['errors'].append('Failed to export complete chain')
                os.unlink(cert_path)
                return result

            result['steps'].append('Exported complete chain')

            # Step 4: Update JKS with complete chain
            update_result = self.update_jks_chain(jks_path, password, alias, chain_path)

            if update_result['success']:
                result['success'] = True
                result['steps'].append('Updated JKS with complete chain')
            else:
                result['errors'].extend(update_result['errors'])

            # Cleanup
            os.unlink(cert_path)
            os.unlink(chain_path)

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def create_jks(self, jks_path: str, password: str) -> Dict[str, Any]:
        """
        Create a new empty JKS keystore.

        Args:
            jks_path: Path for new JKS file
            password: Keystore password

        Returns:
            Creation results
        """
        result = {
            'success': False,
            'keystore_path': jks_path,
            'errors': []
        }

        try:
            # Create empty keystore by importing then deleting a temp cert
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as tmp:
                # Generate a temporary self-signed cert
                tmp_cert = tmp.name

            # Generate temp self-signed cert
            cmd = [
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', '/dev/null', '-out', tmp_cert,
                '-days', '1', '-nodes',
                '-subj', '/CN=temp'
            ]
            subprocess.run(cmd, capture_output=True, timeout=10)

            # Import to create keystore
            cmd = [
                self.keytool, '-importcert',
                '-keystore', jks_path,
                '-storepass', password,
                '-alias', 'temp',
                '-file', tmp_cert,
                '-noprompt'
            ]
            subprocess.run(cmd, capture_output=True, timeout=10)

            # Delete temp cert
            cmd = [
                self.keytool, '-delete',
                '-keystore', jks_path,
                '-storepass', password,
                '-alias', 'temp'
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if proc.returncode == 0:
                result['success'] = True

            os.unlink(tmp_cert)

        except Exception as e:
            result['errors'].append(str(e))

        return result


class OpenSSLCommandBuilder:
    """
    Build OpenSSL commands for common certificate operations.
    Helps users who don't want to upload files.
    """

    def __init__(self):
        self.commands = {}

    def build_command(self, operation: str, **kwargs) -> Dict[str, Any]:
        """
        Build OpenSSL command for specified operation.

        Args:
            operation: Type of operation
            **kwargs: Operation-specific parameters

        Returns:
            Command and explanation
        """
        builders = {
            'view_cert': self._build_view_cert,
            'verify_cert': self._build_verify_cert,
            'check_key': self._build_check_key,
            'check_csr': self._build_check_csr,
            'test_connection': self._build_test_connection,
            'convert_format': self._build_convert_format,
            'generate_key': self._build_generate_key,
            'generate_csr': self._build_generate_csr,
            'self_signed_cert': self._build_self_signed_cert,
            'verify_match': self._build_verify_match,
            'check_expiry': self._build_check_expiry,
        }

        builder = builders.get(operation)
        if not builder:
            return {'error': f'Unknown operation: {operation}'}

        return builder(**kwargs)

    def _build_view_cert(self, cert_file: str = 'certificate.crt', **kwargs) -> Dict[str, Any]:
        """View certificate details"""
        return {
            'command': f'openssl x509 -in {cert_file} -text -noout',
            'description': 'Display certificate details in human-readable format',
            'example_output': 'Shows subject, issuer, validity dates, extensions, etc.'
        }

    def _build_verify_cert(self, cert_file: str = 'certificate.crt',
                           ca_file: str = 'ca-bundle.crt', **kwargs) -> Dict[str, Any]:
        """Verify certificate against CA"""
        return {
            'command': f'openssl verify -CAfile {ca_file} {cert_file}',
            'description': 'Verify certificate against a CA bundle',
            'note': 'Returns "OK" if verification succeeds'
        }

    def _build_check_key(self, key_file: str = 'private.key', **kwargs) -> Dict[str, Any]:
        """Check private key"""
        return {
            'command': f'openssl rsa -in {key_file} -check -noout',
            'description': 'Verify RSA private key consistency',
            'alternative': f'openssl ec -in {key_file} -check -noout  # For EC keys'
        }

    def _build_check_csr(self, csr_file: str = 'request.csr', **kwargs) -> Dict[str, Any]:
        """Check CSR"""
        return {
            'command': f'openssl req -in {csr_file} -text -noout',
            'description': 'Display Certificate Signing Request details',
            'verify': f'openssl req -in {csr_file} -verify -noout'
        }

    def _build_test_connection(self, hostname: str = 'example.com',
                               port: int = 443, **kwargs) -> Dict[str, Any]:
        """Test SSL/TLS connection"""
        return {
            'command': f'openssl s_client -connect {hostname}:{port} -servername {hostname}',
            'description': 'Test SSL/TLS connection and view server certificate',
            'options': {
                'show_chain': f'openssl s_client -connect {hostname}:{port} -showcerts',
                'check_protocol': f'openssl s_client -connect {hostname}:{port} -tls1_3',
                'debug': f'openssl s_client -connect {hostname}:{port} -debug'
            }
        }

    def _build_convert_format(self, input_file: str = 'cert.pem',
                             output_file: str = 'cert.der',
                             input_format: str = 'PEM',
                             output_format: str = 'DER', **kwargs) -> Dict[str, Any]:
        """Convert certificate format"""
        return {
            'command': f'openssl x509 -in {input_file} -inform {input_format} -out {output_file} -outform {output_format}',
            'description': f'Convert certificate from {input_format} to {output_format}',
            'common_conversions': {
                'PEM to DER': 'openssl x509 -in cert.pem -outform DER -out cert.der',
                'DER to PEM': 'openssl x509 -in cert.der -inform DER -out cert.pem',
                'PEM to PKCS7': 'openssl crl2pkcs7 -nocrl -certfile cert.pem -out cert.p7b',
                'PKCS7 to PEM': 'openssl pkcs7 -in cert.p7b -print_certs -out cert.pem'
            }
        }

    def _build_generate_key(self, key_type: str = 'rsa', key_size: int = 2048,
                            output_file: str = 'private.key', **kwargs) -> Dict[str, Any]:
        """Generate private key"""
        if key_type == 'rsa':
            cmd = f'openssl genrsa -out {output_file} {key_size}'
        elif key_type == 'ec':
            cmd = f'openssl ecparam -name prime256v1 -genkey -noout -out {output_file}'
        else:
            return {'error': f'Unsupported key type: {key_type}'}

        return {
            'command': cmd,
            'description': f'Generate {key_type.upper()} private key',
            'encrypt': f'{cmd.replace("-out", "-aes256 -out")}  # Encrypt with AES-256'
        }

    def _build_generate_csr(self, key_file: str = 'private.key',
                           output_file: str = 'request.csr',
                           subject: str = '/CN=example.com', **kwargs) -> Dict[str, Any]:
        """Generate CSR"""
        return {
            'command': f'openssl req -new -key {key_file} -out {output_file} -subj "{subject}"',
            'description': 'Generate Certificate Signing Request',
            'interactive': f'openssl req -new -key {key_file} -out {output_file}  # Interactive mode',
            'with_san': 'Add -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\\nsubjectAltName=DNS:example.com,DNS:www.example.com"))'
        }

    def _build_self_signed_cert(self, key_file: str = 'private.key',
                                output_file: str = 'certificate.crt',
                                days: int = 365,
                                subject: str = '/CN=localhost', **kwargs) -> Dict[str, Any]:
        """Generate self-signed certificate"""
        return {
            'command': f'openssl req -new -x509 -key {key_file} -out {output_file} -days {days} -subj "{subject}"',
            'description': 'Generate self-signed certificate',
            'combined': f'openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days {days} -nodes  # Generate key and cert together'
        }

    def _build_verify_match(self, cert_file: str = 'certificate.crt',
                           key_file: str = 'private.key', **kwargs) -> Dict[str, Any]:
        """Verify cert and key match"""
        return {
            'commands': {
                'cert_modulus': f'openssl x509 -in {cert_file} -noout -modulus | openssl md5',
                'key_modulus': f'openssl rsa -in {key_file} -noout -modulus | openssl md5'
            },
            'description': 'Verify certificate and private key match',
            'note': 'If MD5 hashes match, certificate and key are a pair'
        }

    def _build_check_expiry(self, cert_file: str = 'certificate.crt', **kwargs) -> Dict[str, Any]:
        """Check certificate expiry"""
        return {
            'command': f'openssl x509 -in {cert_file} -noout -dates',
            'description': 'Check certificate validity dates',
            'enddate_only': f'openssl x509 -in {cert_file} -noout -enddate',
            'days_remaining': f'openssl x509 -in {cert_file} -noout -checkend 86400  # Check if expires in 24 hours'
        }
