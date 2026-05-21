"""WHOIS lookup module — registrar, dates, and registration info."""

from __future__ import annotations

import asyncio
import re
import socket
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


def _whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    """Send a WHOIS query to the given server and return the raw response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, 43))
        sock.sendall((query + "\r\n").encode("utf-8"))
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response.decode("utf-8", errors="replace")
    finally:
        sock.close()


def _find_whois_server(iana_response: str) -> str:
    """Extract the refer/whois server from the IANA WHOIS response."""
    for line in iana_response.splitlines():
        line_lower = line.strip().lower()
        if line_lower.startswith("refer:") or line_lower.startswith("whois:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                server = parts[1].strip()
                if server:
                    return server
    return ""


def _parse_whois(raw: str) -> dict[str, str]:
    """Parse common WHOIS fields from raw response text."""
    info: dict[str, str] = {}

    patterns = {
        "registrar": [
            r"Registrar:\s*(.+)",
            r"Registrar Name:\s*(.+)",
            r"registrar:\s*(.+)",
        ],
        "creation_date": [
            r"Creation Date:\s*(.+)",
            r"Created Date:\s*(.+)",
            r"created:\s*(.+)",
            r"Registration Date:\s*(.+)",
            r"Created on:\s*(.+)",
        ],
        "expiration_date": [
            r"Expir(?:y|ation) Date:\s*(.+)",
            r"Registry Expiry Date:\s*(.+)",
            r"paid-till:\s*(.+)",
            r"Expiration Date:\s*(.+)",
            r"expires:\s*(.+)",
        ],
        "updated_date": [
            r"Updated Date:\s*(.+)",
            r"Last Updated:\s*(.+)",
            r"last-modified:\s*(.+)",
            r"modified:\s*(.+)",
        ],
        "name_servers": [
            r"Name Server:\s*(.+)",
            r"nserver:\s*(.+)",
        ],
        "registrant_org": [
            r"Registrant Organization:\s*(.+)",
            r"Registrant Organisation:\s*(.+)",
            r"org:\s*(.+)",
        ],
        "registrant_country": [
            r"Registrant Country:\s*(.+)",
            r"Registrant State/Province:\s*(.+)",
        ],
        "dnssec": [
            r"DNSSEC:\s*(.+)",
            r"dnssec:\s*(.+)",
        ],
        "status": [
            r"Domain Status:\s*(.+)",
            r"Status:\s*(.+)",
        ],
    }

    for field, regexes in patterns.items():
        for regex in regexes:
            match = re.search(regex, raw, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if value:
                    if field == "name_servers":
                        # Collect all name servers
                        all_ns = re.findall(regex, raw, re.IGNORECASE)
                        info[field] = ", ".join(ns.strip().lower() for ns in all_ns)
                    elif field == "status":
                        all_status = re.findall(regex, raw, re.IGNORECASE)
                        info[field] = ", ".join(s.strip() for s in all_status[:5])
                    else:
                        info[field] = value
                    break

    return info


class WhoisLookupModule(BazookaModule):
    name = "recon.whois_lookup"
    phase = "recon"
    description = "WHOIS registration information lookup"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        domain = ctx.target.domain
        whois_data: dict[str, str] = {}
        raw_response = ""

        try:
            # Step 1: Query IANA to find the appropriate WHOIS server
            iana_raw = await asyncio.to_thread(_whois_query, "whois.iana.org", domain)
            whois_server = _find_whois_server(iana_raw)

            if not whois_server:
                # Fallback to common WHOIS servers based on TLD
                tld = domain.rsplit(".", 1)[-1].lower()
                tld_servers = {
                    "com": "whois.verisign-grs.com",
                    "net": "whois.verisign-grs.com",
                    "org": "whois.pir.org",
                    "io": "whois.nic.io",
                    "co": "whois.nic.co",
                    "me": "whois.nic.me",
                    "info": "whois.afilias.net",
                    "biz": "whois.biz",
                    "fr": "whois.nic.fr",
                    "de": "whois.denic.de",
                    "uk": "whois.nic.uk",
                    "eu": "whois.eu",
                    "ru": "whois.tcinet.ru",
                    "nl": "whois.sidn.nl",
                }
                whois_server = tld_servers.get(tld, "")

            if whois_server:
                # Step 2: Query the actual WHOIS server
                raw_response = await asyncio.to_thread(_whois_query, whois_server, domain)
                whois_data = _parse_whois(raw_response)
                whois_data["whois_server"] = whois_server

                # For Verisign thin WHOIS, follow to the registrar's WHOIS server
                if whois_server == "whois.verisign-grs.com":
                    registrar_server_match = re.search(
                        r"Registrar WHOIS Server:\s*(\S+)", raw_response, re.IGNORECASE
                    )
                    if registrar_server_match:
                        registrar_whois = registrar_server_match.group(1).strip()
                        if registrar_whois and registrar_whois != whois_server:
                            try:
                                thick_raw = await asyncio.to_thread(
                                    _whois_query, registrar_whois, domain
                                )
                                thick_data = _parse_whois(thick_raw)
                                # Merge: thick data takes priority for richer fields
                                for k, v in thick_data.items():
                                    if k not in whois_data or not whois_data[k]:
                                        whois_data[k] = v
                                raw_response = thick_raw
                            except Exception:
                                pass  # Keep thin WHOIS data

        except Exception as exc:
            result.status = "partial"
            whois_data["error"] = f"{type(exc).__name__}: {exc}"

        result.add_data("whois", whois_data)
        ctx.data["whois"] = whois_data

        # Build a summary description
        summary_parts = []
        if whois_data.get("registrar"):
            summary_parts.append(f"Registrar: {whois_data['registrar']}")
        if whois_data.get("creation_date"):
            summary_parts.append(f"Creation: {whois_data['creation_date']}")
        if whois_data.get("expiration_date"):
            summary_parts.append(f"Expiration: {whois_data['expiration_date']}")
        if whois_data.get("registrant_org"):
            summary_parts.append(f"Organization: {whois_data['registrant_org']}")
        if whois_data.get("dnssec"):
            summary_parts.append(f"DNSSEC: {whois_data['dnssec']}")

        summary = "; ".join(summary_parts) if summary_parts else "No WHOIS data retrieved"

        # Truncate raw response for evidence
        raw_excerpt = raw_response[:1500] if raw_response else "No response"

        result.add_finding(Finding(
            id="RECON-WHOIS-001",
            title=f"WHOIS: {summary[:80]}",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.INFORMATION_DISCLOSURE,
            description=(
                f"Informations WHOIS pour {domain}: {summary}. "
                f"Ces informations revelent les details d'enregistrement du domaine."
            ),
            evidence=Evidence(
                request=f"WHOIS {domain} (server: {whois_data.get('whois_server', 'N/A')})",
                response_body_excerpt=raw_excerpt,
            ),
            impact="Information publique: exposition du registrar, dates d'enregistrement, organisation.",
            remediation="Activer la protection WHOIS privacy si disponible.",
            compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-200"),
            phase="recon",
            module=self.name,
            tags=["whois", "osint", "registration"],
        ))

        return result
