"""DNS enumeration module — records, SPF, DMARC analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING

import dns.resolver

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FPPotential, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class DNSEnumModule(BazookaModule):
    name = "recon.dns_enum"
    phase = "recon"
    description = "DNS records, SPF, DMARC analysis"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        domain = ctx.target.domain
        records: dict[str, list[str]] = {}

        # Resolve standard record types
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                records[rtype] = []
            except Exception:
                records[rtype] = []

        result.add_data("dns_records", records)

        # Parse SPF
        spf_record = ""
        for txt in records.get("TXT", []):
            if "v=spf1" in txt:
                spf_record = txt
                break

        result.add_data("spf_record", spf_record)
        if not spf_record:
            result.add_finding(Finding(
                id="RECON-SPF-001",
                title=f"SPF record absent pour {domain}",
                severity=Severity.CRITICAL,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=f"Aucun enregistrement SPF trouve pour {domain}. Un attaquant peut envoyer des emails au nom du domaine.",
                impact="Email spoofing possible, phishing cible.",
                remediation=f'Ajouter un enregistrement TXT: "{domain}. IN TXT \\"v=spf1 include:_spf.google.com -all\\""',
                compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-290"),
                phase="recon",
                module=self.name,
            ))
        elif "~all" in spf_record:
            result.add_finding(Finding(
                id="RECON-SPF-002",
                title=f"SPF soft fail (~all) pour {domain}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=f"SPF utilise ~all (soft fail) au lieu de -all (hard fail). Les emails usurpes ne sont pas rejetes.",
                evidence=Evidence(request=f"dig TXT {domain}", response_body_excerpt=spf_record),
                impact="Les emails spoofe ne sont pas rejetes par les serveurs destinataires.",
                remediation="Remplacer ~all par -all dans l'enregistrement SPF.",
                compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-290"),
                phase="recon",
                module=self.name,
            ))

        # Parse DMARC
        dmarc_record = ""
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for r in answers:
                txt = str(r).strip('"')
                if "v=DMARC1" in txt:
                    dmarc_record = txt
                    break
        except Exception:
            pass

        result.add_data("dmarc_record", dmarc_record)
        if not dmarc_record:
            result.add_finding(Finding(
                id="RECON-DMARC-001",
                title=f"DMARC absent pour {domain}",
                severity=Severity.CRITICAL,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=f"Aucun enregistrement DMARC pour {domain}. Aucune politique de verification des emails.",
                impact="Spoofing total possible, aucune action DMARC.",
                remediation=f'Ajouter: "_dmarc.{domain}. IN TXT \\"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}\\""',
                compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-290"),
                phase="recon",
                module=self.name,
            ))
        elif "p=none" in dmarc_record:
            result.add_finding(Finding(
                id="RECON-DMARC-002",
                title=f"DMARC policy p=none pour {domain}",
                severity=Severity.HIGH,
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=f"DMARC est configure avec p=none : les emails echouant la verification ne sont pas bloques.",
                evidence=Evidence(request=f"dig TXT _dmarc.{domain}", response_body_excerpt=dmarc_record),
                impact="Les emails spoofe sont livres normalement.",
                remediation="Passer progressivement a p=quarantine puis p=reject.",
                compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-290"),
                phase="recon",
                module=self.name,
            ))

        # Summary log
        a_records = records.get("A", [])
        if a_records:
            ctx.target.ip = a_records[0]

        return result
