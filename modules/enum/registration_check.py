"""WordPress registration check — is signup open, what default role."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class RegistrationCheckModule(BazookaModule):
    name = "enum.registration_check"
    phase = "enum"
    description = "WordPress registration/signup check"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        resp = await session.get(f"{base}/wp-login.php?action=register", use_cache=True)

        if resp.status_code == 200 and ("registration-form" in resp.text.lower() or "user_login" in resp.text.lower()):
            result.add_finding(Finding(
                id="ENUM-REG-001",
                title="Inscription WordPress ouverte",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description="Le formulaire d'inscription WordPress est accessible. N'importe qui peut creer un compte.",
                evidence=Evidence(
                    request=f"GET {base}/wp-login.php?action=register",
                    response_status=200,
                ),
                impact="Creation de comptes spam/malveillants. Acces au tableau de bord selon le role par defaut.",
                remediation="Desactiver l'inscription dans Reglages > General si non necessaire.",
                compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-287"),
                phase="enum", module=self.name,
            ))
            result.add_data("registration_open", True)
        else:
            result.add_data("registration_open", False)

        # Check wp-signup.php (Multisite)
        resp = await session.get(f"{base}/wp-signup.php", use_cache=True)
        if resp.status_code == 200 and "signup" in resp.text.lower():
            result.add_data("multisite_signup_open", True)

        return result
