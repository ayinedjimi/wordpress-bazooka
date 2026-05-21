"""SSL/TLS audit module — certificate and protocol analysis."""

from __future__ import annotations

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


def _get_certificate_info(hostname: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Connect via TLS and extract certificate details."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # We want to inspect even invalid certs

    info: dict = {}
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert(binary_form=False)
            cert_bin = ssock.getpeercert(binary_form=True)
            info["protocol_version"] = ssock.version()
            info["cipher"] = ssock.cipher()

    # If getpeercert() returned None with CERT_NONE, we need to try again with verification
    # to get the parsed cert dict
    if not cert:
        ctx_verify = ssl.create_default_context()
        ctx_verify.check_hostname = False
        ctx_verify.verify_mode = ssl.CERT_REQUIRED
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock2:
                with ctx_verify.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                    cert = ssock2.getpeercert(binary_form=False)
        except ssl.SSLCertVerificationError:
            # Still extract what we can
            pass

    # Try with CERT_REQUIRED to get the parsed cert
    if not cert:
        ctx_partial = ssl.create_default_context()
        ctx_partial.check_hostname = False
        ctx_partial.verify_mode = ssl.CERT_OPTIONAL
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock3:
                with ctx_partial.wrap_socket(sock3, server_hostname=hostname) as ssock3:
                    cert = ssock3.getpeercert(binary_form=False)
        except Exception:
            pass

    if cert:
        # Subject
        subject_parts = {}
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                subject_parts[key] = value
        info["subject_cn"] = subject_parts.get("commonName", "")
        info["subject_org"] = subject_parts.get("organizationName", "")

        # Issuer
        issuer_parts = {}
        for rdn in cert.get("issuer", ()):
            for key, value in rdn:
                issuer_parts[key] = value
        info["issuer_cn"] = issuer_parts.get("commonName", "")
        info["issuer_org"] = issuer_parts.get("organizationName", "")

        # Dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        if not_before:
            info["not_before"] = not_before
            try:
                info["not_before_dt"] = ssl.cert_time_to_seconds(not_before)
            except Exception:
                pass
        if not_after:
            info["not_after"] = not_after
            try:
                info["not_after_dt"] = ssl.cert_time_to_seconds(not_after)
            except Exception:
                pass

        # SAN names
        san_list = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            san_list.append(f"{san_type}:{san_value}")
        info["san"] = san_list
        info["san_dns"] = [
            v for t, v in cert.get("subjectAltName", ()) if t == "DNS"
        ]

        # Serial number
        info["serial_number"] = cert.get("serialNumber", "")

    return info


def _check_legacy_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, bool]:
    """Check if legacy TLS 1.0 and TLS 1.1 are supported."""
    results: dict[str, bool] = {"tls_1_0": False, "tls_1_1": False}

    # Check TLS 1.0
    try:
        ctx_10 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_10.check_hostname = False
        ctx_10.verify_mode = ssl.CERT_NONE
        ctx_10.maximum_version = ssl.TLSVersion.TLSv1
        ctx_10.minimum_version = ssl.TLSVersion.TLSv1
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx_10.wrap_socket(sock, server_hostname=hostname) as ssock:
                results["tls_1_0"] = True
    except (ssl.SSLError, OSError, AttributeError):
        results["tls_1_0"] = False

    # Check TLS 1.1
    try:
        ctx_11 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_11.check_hostname = False
        ctx_11.verify_mode = ssl.CERT_NONE
        ctx_11.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx_11.minimum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx_11.wrap_socket(sock, server_hostname=hostname) as ssock:
                results["tls_1_1"] = True
    except (ssl.SSLError, OSError, AttributeError):
        results["tls_1_1"] = False

    return results


class SSLScanModule(BazookaModule):
    name = "recon.ssl_scan"
    phase = "recon"
    description = "SSL/TLS certificate and protocol security audit"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        domain = ctx.target.domain
        url = ctx.target.url

        # Only scan HTTPS targets
        if not url.startswith("https://"):
            result.add_data("ssl_info", {"skipped": True, "reason": "not_https"})
            result.add_finding(Finding(
                id="RECON-SSL-NOSSL",
                title=f"Pas de HTTPS: {domain} utilise HTTP",
                severity=Severity.HIGH,
                cvss_score=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"Le site {url} est accessible en HTTP sans chiffrement TLS. "
                    f"Toutes les communications (credentials, cookies, donnees) sont en clair."
                ),
                impact="Interception des credentials, cookies, et donnees sensibles (MITM).",
                remediation="Configurer HTTPS avec un certificat valide (Let's Encrypt) et rediriger HTTP vers HTTPS.",
                compliance=Compliance(owasp_2021="A02:2021", cwe="CWE-319", pci_dss_v4="4.1"),
                phase="recon",
                module=self.name,
                tags=["ssl", "tls", "encryption"],
            ))
            return result

        ssl_info: dict = {}
        port = 443

        # Step 1: Get certificate info
        try:
            cert_info = await asyncio.to_thread(_get_certificate_info, domain, port)
            ssl_info.update(cert_info)
        except Exception as exc:
            ssl_info["error"] = f"{type(exc).__name__}: {exc}"
            result.add_data("ssl_info", ssl_info)
            result.status = "partial"
            result.add_finding(Finding(
                id="RECON-SSL-ERR",
                title=f"Erreur connexion SSL: {type(exc).__name__}",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=f"Impossible d'etablir une connexion TLS a {domain}:{port}: {exc}",
                phase="recon",
                module=self.name,
            ))
            return result

        # Step 2: Check for legacy TLS versions
        try:
            legacy_tls = await asyncio.to_thread(_check_legacy_tls, domain, port)
            ssl_info["tls_1_0_supported"] = legacy_tls["tls_1_0"]
            ssl_info["tls_1_1_supported"] = legacy_tls["tls_1_1"]
        except Exception:
            ssl_info["tls_1_0_supported"] = False
            ssl_info["tls_1_1_supported"] = False

        result.add_data("ssl_info", ssl_info)
        ctx.data["ssl_info"] = ssl_info

        # --- Generate findings ---

        now_ts = datetime.now(timezone.utc).timestamp()

        # Check certificate expiry
        not_after_ts = ssl_info.get("not_after_dt")
        not_after_str = ssl_info.get("not_after", "unknown")
        if not_after_ts:
            if not_after_ts < now_ts:
                # Certificate is expired
                result.add_finding(Finding(
                    id="RECON-SSL-001",
                    title=f"Certificat SSL expire: {not_after_str}",
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        f"Le certificat TLS de {domain} a expire le {not_after_str}. "
                        f"Les navigateurs affichent un avertissement de securite. "
                        f"Un attaquant pourrait exploiter cette situation pour du phishing MITM."
                    ),
                    evidence=Evidence(
                        request=f"TLS handshake to {domain}:443",
                        response_body_excerpt=(
                            f"Subject CN: {ssl_info.get('subject_cn', '?')}\n"
                            f"Issuer: {ssl_info.get('issuer_cn', '?')}\n"
                            f"Not After: {not_after_str}\n"
                            f"Protocol: {ssl_info.get('protocol_version', '?')}"
                        ),
                    ),
                    impact="Avertissements navigateur, perte de confiance, MITM possible.",
                    remediation="Renouveler immediatement le certificat SSL/TLS.",
                    compliance=Compliance(owasp_2021="A02:2021", cwe="CWE-295", pci_dss_v4="4.1"),
                    phase="recon",
                    module=self.name,
                    tags=["ssl", "certificate", "expired", "critical"],
                ))
            else:
                # Check if expiring soon (within 30 days)
                days_remaining = (not_after_ts - now_ts) / 86400
                if days_remaining < 30:
                    result.add_finding(Finding(
                        id="RECON-SSL-002",
                        title=f"Certificat SSL expire dans {int(days_remaining)} jours",
                        severity=Severity.MEDIUM,
                        cvss_score=4.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=(
                            f"Le certificat TLS de {domain} expire le {not_after_str} "
                            f"(dans {int(days_remaining)} jours). "
                            f"Un renouvellement rapide est recommande."
                        ),
                        evidence=Evidence(
                            request=f"TLS handshake to {domain}:443",
                            response_body_excerpt=f"Not After: {not_after_str}",
                        ),
                        remediation="Renouveler le certificat avant expiration. Configurer le renouvellement automatique.",
                        compliance=Compliance(owasp_2021="A02:2021", cwe="CWE-295"),
                        phase="recon",
                        module=self.name,
                        tags=["ssl", "certificate", "expiring"],
                    ))

        # Check CN mismatch
        subject_cn = ssl_info.get("subject_cn", "")
        san_dns = ssl_info.get("san_dns", [])
        if subject_cn or san_dns:
            cn_matches = (
                domain == subject_cn
                or subject_cn.startswith("*.") and domain.endswith(subject_cn[1:])
            )
            san_matches = any(
                domain == san or (san.startswith("*.") and domain.endswith(san[1:]))
                for san in san_dns
            )
            if not cn_matches and not san_matches:
                result.add_finding(Finding(
                    id="RECON-SSL-003",
                    title=f"CN mismatch: certificat pour {subject_cn}, domaine {domain}",
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        f"Le certificat TLS est emis pour '{subject_cn}' (SAN: {', '.join(san_dns[:5])}) "
                        f"mais le domaine cible est '{domain}'. Les navigateurs signalent cette erreur. "
                        f"Cela peut indiquer un certificat mal configure ou un serveur partage."
                    ),
                    evidence=Evidence(
                        request=f"TLS handshake to {domain}:443",
                        response_body_excerpt=(
                            f"Subject CN: {subject_cn}\n"
                            f"SAN DNS: {', '.join(san_dns[:10])}\n"
                            f"Target domain: {domain}"
                        ),
                    ),
                    impact="Avertissements navigateur, echec de la verification du certificat.",
                    remediation=f"Emettre un certificat incluant {domain} dans le CN ou les SAN.",
                    compliance=Compliance(owasp_2021="A02:2021", cwe="CWE-295"),
                    phase="recon",
                    module=self.name,
                    tags=["ssl", "certificate", "cn-mismatch"],
                ))

        # Check legacy TLS support
        if ssl_info.get("tls_1_0_supported"):
            result.add_finding(Finding(
                id="RECON-SSL-004",
                title=f"TLS 1.0 supporte sur {domain}",
                severity=Severity.MEDIUM,
                cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"Le serveur {domain} accepte les connexions TLS 1.0, "
                    f"un protocole obsolete vulnerable a BEAST et POODLE. "
                    f"TLS 1.0 est deprecie depuis 2020 (RFC 8996)."
                ),
                evidence=Evidence(
                    request=f"TLS 1.0 handshake to {domain}:443",
                    response_body_excerpt="TLS 1.0 connection succeeded",
                ),
                impact="Attaques BEAST, POODLE, dechiffrement potentiel du trafic.",
                remediation="Desactiver TLS 1.0 dans la configuration du serveur. Supporter uniquement TLS 1.2+.",
                compliance=Compliance(
                    owasp_2021="A02:2021",
                    cwe="CWE-326",
                    pci_dss_v4="4.1",
                ),
                phase="recon",
                module=self.name,
                tags=["ssl", "tls", "legacy", "tls1.0"],
            ))

        if ssl_info.get("tls_1_1_supported"):
            result.add_finding(Finding(
                id="RECON-SSL-005",
                title=f"TLS 1.1 supporte sur {domain}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"Le serveur {domain} accepte les connexions TLS 1.1, "
                    f"un protocole deprecie (RFC 8996). "
                    f"TLS 1.1 n'offre pas les protections modernes de TLS 1.2/1.3."
                ),
                evidence=Evidence(
                    request=f"TLS 1.1 handshake to {domain}:443",
                    response_body_excerpt="TLS 1.1 connection succeeded",
                ),
                impact="Protocole cryptographique faible, non conforme PCI DSS.",
                remediation="Desactiver TLS 1.1. Supporter uniquement TLS 1.2 et TLS 1.3.",
                compliance=Compliance(
                    owasp_2021="A02:2021",
                    cwe="CWE-326",
                    pci_dss_v4="4.1",
                ),
                phase="recon",
                module=self.name,
                tags=["ssl", "tls", "legacy", "tls1.1"],
            ))

        # Summary finding with all SSL info
        protocol = ssl_info.get("protocol_version", "unknown")
        cipher_info = ssl_info.get("cipher", ("unknown", "unknown", 0))
        cipher_name = cipher_info[0] if isinstance(cipher_info, tuple) else str(cipher_info)
        issuer = ssl_info.get("issuer_cn", "unknown")
        san_count = len(san_dns)

        # Only add summary if no critical/high findings were added
        critical_or_high = [
            f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if not critical_or_high:
            result.add_finding(Finding(
                id="RECON-SSL-INFO",
                title=f"SSL/TLS: {protocol}, certificat par {issuer}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Certificat TLS pour {domain}: emis par {issuer}, "
                    f"CN={subject_cn}, {san_count} SAN(s), "
                    f"valide jusqu'au {not_after_str}. "
                    f"Protocole negocie: {protocol}, cipher: {cipher_name}."
                ),
                evidence=Evidence(
                    request=f"TLS handshake to {domain}:443",
                    response_body_excerpt=(
                        f"Protocol: {protocol}\n"
                        f"Cipher: {cipher_name}\n"
                        f"Subject CN: {subject_cn}\n"
                        f"Issuer: {issuer}\n"
                        f"Not Before: {ssl_info.get('not_before', '?')}\n"
                        f"Not After: {not_after_str}\n"
                        f"SAN DNS ({san_count}): {', '.join(san_dns[:10])}"
                    ),
                ),
                phase="recon",
                module=self.name,
                tags=["ssl", "tls", "certificate"],
            ))

        return result
