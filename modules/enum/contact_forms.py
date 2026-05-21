"""Contact Form enumeration — CF7, WPForms, Gravity Forms via REST API."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class ContactFormsModule(BazookaModule):
    name = "enum.contact_forms"
    phase = "enum"
    description = "Contact form enumeration (CF7, WPForms)"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        namespaces = ctx.data.get("rest_api_namespaces", [])

        # Contact Form 7
        cf7_ns = [ns for ns in namespaces if ns.startswith("contact-form-7")]
        if cf7_ns:
            resp = await session.get(f"{base}/wp-json/contact-form-7/v1/contact-forms")
            if resp.status_code == 200:
                try:
                    forms = resp.json()
                    if isinstance(forms, dict):
                        forms_list = forms.get("contact_forms", [])
                    elif isinstance(forms, list):
                        forms_list = forms
                    else:
                        forms_list = []

                    if forms_list:
                        result.add_finding(Finding(
                            id="ENUM-CF7-001",
                            title=f"{len(forms_list)} formulaire(s) CF7 exposes sans authentification",
                            severity=Severity.HIGH,
                            cvss_score=5.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.INFORMATION_DISCLOSURE,
                            description=(
                                f"L'API Contact Form 7 expose {len(forms_list)} formulaires sans authentification. "
                                "La structure des formulaires revele les champs collectes (emails, tel, etc.)."
                            ),
                            evidence=Evidence(
                                request=f"GET {base}/wp-json/contact-form-7/v1/contact-forms",
                                response_status=200,
                            ),
                            impact="Structure des formulaires exposee. Aide au phishing cible.",
                            remediation="Restreindre l'acces a l'API CF7 via plugin ou filtre REST.",
                            compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-200"),
                            phase="enum", module=self.name,
                        ))
                        result.add_data("cf7_forms_count", len(forms_list))
                except Exception:
                    pass

        # WPForms
        wpforms_ns = [ns for ns in namespaces if "wpforms" in ns.lower()]
        if wpforms_ns:
            result.add_data("wpforms_detected", True)

        return result
