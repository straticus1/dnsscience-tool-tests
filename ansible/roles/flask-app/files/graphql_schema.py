"""
DNS Science - GraphQL Schema
Flexible querying interface for DNS intelligence data
"""

import graphene
from graphene import ObjectType, String, Int, Float, Boolean, List, Field
import database as db
try:
    import ip_intelligence as ip_engine
except ImportError:
    ip_engine = None


# Types
class DNSRecordType(ObjectType):
    """DNS Record"""
    name = String()
    type = String()
    value = String()
    ttl = Int()


class DomainType(ObjectType):
    """Domain information"""
    domain = String()
    dnssec_enabled = Boolean()
    dnssec_valid = Boolean()
    spf_valid = Boolean()
    spf_record = String()
    dkim_valid = Boolean()
    dmarc_valid = Boolean()
    dmarc_policy = String()
    mta_sts_enabled = Boolean()
    smtp_starttls_25 = Boolean()
    smtp_starttls_587 = Boolean()
    ssl_valid = Boolean()
    ssl_issuer = String()
    ssl_expiry = String()
    created_at = String()

    dns_records = List(DNSRecordType)

    def resolve_dns_records(self, info):
        """Resolve DNS records for domain"""
        import dns.resolver
        records = []
        resolver = dns.resolver.Resolver()

        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        for rtype in record_types:
            try:
                answers = resolver.resolve(self.domain, rtype)
                for rdata in answers:
                    records.append(DNSRecordType(
                        name=self.domain,
                        type=rtype,
                        value=str(rdata),
                        ttl=answers.rrset.ttl
                    ))
            except:
                pass

        return records


class GeolocationData(ObjectType):
    """IP Geolocation data"""
    country = String()
    region = String()
    city = String()
    postal_code = String()
    latitude = Float()
    longitude = Float()
    timezone = String()


class NetworkData(ObjectType):
    """Network information"""
    asn = Int()
    asn_name = String()
    organization = String()
    isp = String()
    hostname = String()
    is_vpn = Boolean()
    is_proxy = Boolean()
    is_tor = Boolean()
    is_hosting = Boolean()


class BGPData(ObjectType):
    """BGP routing information"""
    prefix = String()
    origin_asn = Int()
    as_path = String()
    is_announced = Boolean()
    rpki_status = String()


class ReputationData(ObjectType):
    """IP reputation data"""
    abuse_confidence_score = Int()
    total_reports = Int()
    last_reported = String()
    is_whitelisted = Boolean()
    blacklist_hits = Int()


class IPAddressType(ObjectType):
    """IP Address intelligence"""
    ip = String()
    ip_version = Int()
    is_private = Boolean()
    scan_timestamp = String()

    geolocation = Field(GeolocationData)
    network = Field(NetworkData)
    bgp = Field(BGPData)
    reputation = Field(ReputationData)

    def resolve_geolocation(self, info):
        """Resolve geolocation data"""
        scan = db.get_latest_ip_scan(self.ip, max_age_hours=24)
        if scan:
            return GeolocationData(
                country=scan.get('country'),
                region=scan.get('region'),
                city=scan.get('city'),
                postal_code=scan.get('postal_code'),
                latitude=scan.get('latitude'),
                longitude=scan.get('longitude'),
                timezone=scan.get('timezone')
            )
        return None

    def resolve_network(self, info):
        """Resolve network data"""
        scan = db.get_latest_ip_scan(self.ip, max_age_hours=24)
        if scan:
            return NetworkData(
                asn=scan.get('asn'),
                asn_name=scan.get('asn_name'),
                organization=scan.get('organization'),
                isp=scan.get('isp'),
                hostname=scan.get('hostname'),
                is_vpn=scan.get('is_vpn'),
                is_proxy=scan.get('is_proxy'),
                is_tor=scan.get('is_tor'),
                is_hosting=scan.get('is_hosting')
            )
        return None

    def resolve_bgp(self, info):
        """Resolve BGP data"""
        scan = db.get_latest_ip_scan(self.ip, max_age_hours=24)
        if scan:
            return BGPData(
                prefix=scan.get('prefix'),
                origin_asn=scan.get('origin_asn'),
                as_path=scan.get('as_path'),
                is_announced=scan.get('is_announced'),
                rpki_status=scan.get('rpki_status')
            )
        return None

    def resolve_reputation(self, info):
        """Resolve reputation data"""
        scan = db.get_latest_ip_scan(self.ip, max_age_hours=24)
        if scan:
            return ReputationData(
                abuse_confidence_score=scan.get('abuse_confidence_score'),
                total_reports=scan.get('total_reports'),
                last_reported=scan.get('last_reported'),
                is_whitelisted=scan.get('is_whitelisted'),
                blacklist_hits=scan.get('blacklist_hits')
            )
        return None


class CertificateType(ObjectType):
    """SSL Certificate"""
    domain = String()
    issuer = String()
    subject = String()
    valid_from = String()
    valid_until = String()
    serial_number = String()
    signature_algorithm = String()
    is_valid = Boolean()
    is_expired = Boolean()
    days_until_expiry = Int()


class DomainStatisticsType(ObjectType):
    """Platform statistics"""
    total_domains = Int()
    total_ip_scans = Int()
    dnssec_enabled_count = Int()
    ssl_valid_count = Int()
    total_users = Int()


# Queries
class Query(ObjectType):
    """Root Query"""

    # Domain queries
    domain = Field(DomainType, domain=String(required=True))
    domains = List(DomainType, limit=Int(), offset=Int())
    search_domains = List(DomainType, query=String(required=True), limit=Int())

    # IP queries
    ip_address = Field(IPAddressType, ip=String(required=True))
    ip_scan_history = List(IPAddressType, ip=String(required=True), limit=Int())

    # Certificate queries
    certificate = Field(CertificateType, domain=String(required=True))
    expiring_certificates = List(CertificateType, days=Int())

    # Statistics
    statistics = Field(DomainStatisticsType)

    def resolve_domain(self, info, domain):
        """Get domain information"""
        scan = db.get_latest_domain_scan(domain)
        if scan:
            return DomainType(
                domain=scan.get('domain'),
                dnssec_enabled=scan.get('dnssec_enabled'),
                dnssec_valid=scan.get('dnssec_valid'),
                spf_valid=scan.get('spf_valid'),
                spf_record=scan.get('spf_record'),
                dkim_valid=scan.get('dkim_valid'),
                dmarc_valid=scan.get('dmarc_valid'),
                dmarc_policy=scan.get('dmarc_policy'),
                mta_sts_enabled=scan.get('mta_sts_enabled'),
                smtp_starttls_25=scan.get('smtp_starttls_25'),
                smtp_starttls_587=scan.get('smtp_starttls_587'),
                ssl_valid=scan.get('ssl_valid'),
                ssl_issuer=scan.get('ssl_issuer'),
                ssl_expiry=scan.get('ssl_expiry'),
                created_at=str(scan.get('created_at'))
            )
        return None

    def resolve_domains(self, info, limit=50, offset=0):
        """List all domains"""
        domains = db.list_all_domains(limit=limit, offset=offset)
        return [DomainType(
            domain=d.get('domain'),
            dnssec_enabled=d.get('dnssec_enabled'),
            created_at=str(d.get('created_at'))
        ) for d in domains]

    def resolve_search_domains(self, info, query, limit=50):
        """Search domains"""
        domains = db.search_domains(query, limit=limit)
        return [DomainType(
            domain=d.get('domain'),
            dnssec_enabled=d.get('dnssec_enabled'),
            created_at=str(d.get('created_at'))
        ) for d in domains]

    def resolve_ip_address(self, info, ip):
        """Get IP address information"""
        scan = db.get_latest_ip_scan(ip, max_age_hours=24)
        if scan:
            return IPAddressType(
                ip=ip,
                ip_version=4,
                is_private=False,
                scan_timestamp=str(scan.get('scanned_at'))
            )
        return None

    def resolve_ip_scan_history(self, info, ip, limit=10):
        """Get IP scan history"""
        scans = db.get_ip_scan_history(ip, limit=limit)
        return [IPAddressType(
            ip=ip,
            scan_timestamp=str(scan.get('scanned_at'))
        ) for scan in scans]

    def resolve_certificate(self, info, domain):
        """Get certificate information"""
        import ssl
        import socket
        from datetime import datetime

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])

                    valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until = (valid_until - datetime.now()).days

                    return CertificateType(
                        domain=domain,
                        issuer=issuer.get('commonName'),
                        subject=subject.get('commonName'),
                        valid_from=cert['notBefore'],
                        valid_until=cert['notAfter'],
                        serial_number=cert.get('serialNumber'),
                        is_valid=True,
                        is_expired=days_until < 0,
                        days_until_expiry=days_until
                    )
        except:
            return None

    def resolve_expiring_certificates(self, info, days=30):
        """Get certificates expiring within N days"""
        # This would query a database of monitored certificates
        return []

    def resolve_statistics(self, info):
        """Get platform statistics"""
        stats = db.get_platform_stats()
        return DomainStatisticsType(
            total_domains=stats.get('total_domains', 0),
            total_ip_scans=stats.get('total_ip_scans', 0),
            dnssec_enabled_count=stats.get('dnssec_enabled', 0),
            ssl_valid_count=stats.get('ssl_valid', 0),
            total_users=stats.get('total_users', 0)
        )


# Mutations
class ScanDomain(graphene.Mutation):
    """Scan a domain"""
    class Arguments:
        domain = String(required=True)
        check_ssl = Boolean(default_value=True)

    domain = Field(DomainType)
    success = Boolean()

    def mutate(self, info, domain, check_ssl=True):
        """Execute domain scan"""
        # Trigger async scan
        from celery_app import scan_domain_task
        task = scan_domain_task.delay(domain, check_ssl)

        return ScanDomain(success=True, domain=DomainType(domain=domain))


class ScanIPAddress(graphene.Mutation):
    """Scan an IP address"""
    class Arguments:
        ip = String(required=True)
        full_scan = Boolean(default_value=True)

    ip_address = Field(IPAddressType)
    success = Boolean()

    def mutate(self, info, ip, full_scan=True):
        """Execute IP scan"""
        if ip_engine:
            result = ip_engine.scan_ip(ip, full_scan=full_scan)
        return ScanIPAddress(
            success=True,
            ip_address=IPAddressType(ip=ip, ip_version=4, is_private=False)
        )


class Mutation(ObjectType):
    """Root Mutation"""
    scan_domain = ScanDomain.Field()
    scan_ip_address = ScanIPAddress.Field()


# Schema
schema = graphene.Schema(query=Query, mutation=Mutation)
