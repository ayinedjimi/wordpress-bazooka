"""SSL certificate enumeration — extract CN and SAN from certificates on port 443 in the /24."""

from __future__ import annotations

import asyncio
import ssl
import socket
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

_CONNECT_TIMEOUT = 3.0
_MAX_CONCURRENT = 20


def _extract_cert_info(ip: str, port: int = 443, timeout: float = _CONNECT_TIMEOUT) -> dict | None:
    """Connect with TLS and extract CN + SAN from the peer certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        ssock = ctx.wrap_socket(sock, server_hostname=None)
        try:
            cert_bin = ssock.getpeercert(binary_form=True)
            if not cert_bin:
                return None
            # Decode using the ssl module's DER parser
            cert = ssl.DER_cert_to_PEM_cert(cert_bin)

            # Re-wrap with hostname check off to get parsed dict
            # Alternative: parse the PEM manually; use a second connection that returns getpeercert()
            # We do a reconnection to get the parsed cert dict
        finally:
            ssock.close()
    except Exception:
        sock.close()
        return None

    # Second pass: get parsed cert dict via getpeercert(binary_form=False)
    # This requires CERT_REQUIRED and matching hostname, so we use a workaround:
    # parse the binary cert ourselves.
    try:
        from cryptography.x509 import load_der_x509_certificate
        from cryptography.x509.oid import NameOID, ExtensionOID
        from cryptography.x509.extensions import SubjectAlternativeName
        from cryptography.x509.general_name import DNSName

        cert_obj = load_der_x509_certificate(cert_bin)
        cn = ""
        try:
            cn_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attrs:
                cn = cn_attrs[0].value
        except Exception:
            pass

        sans: list[str] = []
        try:
            ext = cert_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_ext = ext.value
            sans = san_ext.get_values_for_type(DNSName)
        except Exception:
            pass

        issuer = ""
        try:
            issuer_attrs = cert_obj.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if issuer_attrs:
                issuer = issuer_attrs[0].value
        except Exception:
            pass

        return {
            "ip": ip,
            "cn": cn,
            "sans": sans,
            "issuer": issuer,
            "not_after": cert_obj.not_valid_after_utc.isoformat() if hasattr(cert_obj, "not_valid_after_utc") else str(cert_obj.not_valid_after),
        }
    except ImportError:
        # Fallback without cryptography: reconnect and use getpeercert()
        pass
    except Exception:
        pass

    # Fallback: simple SSL getpeercert (needs server_hostname for SNI, we try with IP)
    try:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.settimeout(timeout)
        sock2.connect((ip, port))
        ssock2 = ctx2.wrap_socket(sock2, server_hostname=ip)
        try:
            # This often returns empty dict without CERT_REQUIRED, but try
            cert_dict = ssock2.getpeercert()
            cn = ""
            sans_list: list[str] = []
            if cert_dict:
                subj = cert_dict.get("subject", ())
                for rdn in subj:
                    for attr_name, attr_val in rdn:
                        if attr_name == "commonName":
                            cn = attr_val
                san_entries = cert_dict.get("subjectAltName", ())
                for san_type, san_val in san_entries:
                    if san_type == "DNS":
                        sans_list.append(san_val)
                return {
                    "ip": ip,
                    "cn": cn,
                    "sans": sans_list,
                    "issuer": str(cert_dict.get("issuer", "")),
                    "not_after": str(cert_dict.get("notAfter", "")),
                }
        finally:
            ssock2.close()
    except Exception:
        pass

    return None


class SSLCertEnumModule(BazookaModule):
    name = "infra.ssl_cert_enum"
    phase = "infra"
    description = "SSL certificate CN/SAN enumeration on /24 range"
    profiles = ["aggressive"]
    intrusive = False
    dependencies = ["infra.network_scan"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        loop = asyncio.get_event_loop()

        # Collect IPs with port 443 open from network_scan data
        network_hosts = ctx.data.get("network_hosts", [])
        target_ips: list[str] = []

        if network_hosts:
            for host in network_hosts:
                for port_info in host.get("ports", []):
                    if port_info.get("port") == 443:
                        target_ips.append(host["ip"])
                        break
        else:
            # Fallback: scan /24 ourselves on port 443 only
            base_ip = ctx.target.origin_ip or ctx.target.ip
            if not base_ip:
                result.status = "skipped"
                return result
            parts = base_ip.split(".")
            if len(parts) != 4:
                result.status = "skipped"
                return result
            prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
            # Quick TCP check on 443 for all IPs
            sem = asyncio.Semaphore(_MAX_CONCURRENT)

            async def _check_443(ip: str) -> str | None:
                def _conn() -> bool:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2.0)
                    try:
                        s.connect((ip, 443))
                        return True
                    except Exception:
                        return False
                    finally:
                        s.close()

                async with sem:
                    if await loop.run_in_executor(None, _conn):
                        return ip
                return None

            checks = [_check_443(f"{prefix}.{i}") for i in range(1, 255)]
            check_results = await asyncio.gather(*checks)
            target_ips = [ip for ip in check_results if ip is not None]

        if not target_ips:
            result.status = "skipped"
            return result

        # Extract certificates concurrently
        sem = asyncio.Semaphore(_MAX_CONCURRENT)
        ssl_certs: list[dict] = []

        async def _get_cert(ip: str) -> dict | None:
            async with sem:
                return await loop.run_in_executor(None, _extract_cert_info, ip)

        tasks = [_get_cert(ip) for ip in target_ips]
        cert_results = await asyncio.gather(*tasks)

        for cert_info in cert_results:
            if cert_info is not None:
                ssl_certs.append(cert_info)

        result.add_data("ssl_certs", ssl_certs)

        # Collect all unique domains found
        all_domains: set[str] = set()
        for cert in ssl_certs:
            cn = cert.get("cn", "")
            if cn and not cn.startswith("*"):
                all_domains.add(cn)
            elif cn:
                all_domains.add(cn)
            for san in cert.get("sans", []):
                all_domains.add(san)

        # Build summary
        cert_summary: list[str] = []
        for cert in ssl_certs[:30]:
            sans_str = ", ".join(cert.get("sans", [])[:5])
            cert_summary.append(f"  {cert['ip']}: CN={cert.get('cn', 'N/A')} SAN=[{sans_str}]")
        summary = "\n".join(cert_summary)

        severity = Severity.MEDIUM if len(all_domains) > 3 else Severity.INFO

        result.add_finding(Finding(
            id="INFRA-SSL-001",
            title=f"Certificats SSL: {len(ssl_certs)} serveurs, {len(all_domains)} domaines decouverts",
            severity=severity,
            cvss_score=3.0 if severity == Severity.MEDIUM else 0.0,
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.INFORMATION_DISCLOSURE,
            description=(
                f"Enumeration des certificats SSL sur {len(target_ips)} IPs avec port 443 ouvert. "
                f"{len(ssl_certs)} certificats extraits, {len(all_domains)} domaines/sous-domaines uniques.\n"
                f"Domaines: {', '.join(sorted(all_domains)[:20])}\n{summary}"
            ),
            evidence=Evidence(
                request=f"TLS handshake on {len(target_ips)} IPs:443",
                response_body_excerpt=summary[:500],
            ),
            impact=(
                "Les certificats revelent des domaines et services heberges sur le meme reseau. "
                "Cela peut permettre de decouvrir des services caches ou des cibles supplementaires."
            ),
            remediation=(
                "Utiliser des certificats dedies par service. Segmenter le reseau. "
                "Ne pas exposer de services internes sur des IPs publiques."
            ),
            phase="infra",
            module=self.name,
            tags=["ssl", "certificate", "enumeration", "infrastructure"],
        ))

        return result
