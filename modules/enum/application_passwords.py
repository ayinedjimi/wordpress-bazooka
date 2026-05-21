"""WordPress Application Passwords (WP 5.6+) detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class ApplicationPasswordsModule(BazookaModule):
    name = "enum.application_passwords"
    phase = "enum"
    description = "WordPress Application Passwords (WP 5.6+) detection"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        app_pw_url = f"{base}/wp-json/wp/v2/users/me/application-passwords"

        resp = await session.get(app_pw_url)
        status = resp.status_code
        body = resp.text

        result.add_data("app_passwords_status", status)

        if status == 200:
            # Application passwords listed without authentication = CRITICAL
            try:
                data = resp.json()
                is_list = isinstance(data, list)
            except Exception:
                is_list = False

            if is_list:
                result.add_data("app_passwords_exposed", True)
                result.add_data("app_passwords_count", len(data) if isinstance(data, list) else 0)

                result.add_finding(Finding(
                    id="ENUM-APPPW-001",
                    title="Application Passwords accessibles SANS authentification!",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        f"L'endpoint Application Passwords ({app_pw_url}) retourne des donnees "
                        f"sans authentification. Cela permet de lister, creer ou supprimer "
                        f"des mots de passe d'application pour les utilisateurs."
                    ),
                    evidence=Evidence(
                        request=f"GET {app_pw_url}",
                        response_status=200,
                        response_body_excerpt=body[:300],
                    ),
                    impact=(
                        "Un attaquant peut creer un mot de passe d'application et obtenir "
                        "un acces API complet au compte, contournant 2FA et les protections "
                        "de connexion classiques."
                    ),
                    remediation=(
                        "Verifier immediatement les filtres d'authentification REST API. "
                        "Desactiver Application Passwords si non utilise: "
                        "add_filter('wp_is_application_passwords_available', '__return_false');"
                    ),
                    compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-862"),
                    phase="enum",
                    module=self.name,
                ))
            else:
                # 200 but not a list — likely an error message or unexpected response
                result.add_data("app_passwords_exposed", False)
                result.add_data("app_passwords_note", "200 response but not a valid list")

        elif status == 401:
            # Feature exists but properly protected
            result.add_data("app_passwords_exposed", False)
            result.add_data("app_passwords_enabled", True)

            result.add_finding(Finding(
                id="ENUM-APPPW-002",
                title="Application Passwords active (protege par authentification)",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"La fonctionnalite Application Passwords (WP 5.6+) est active "
                    f"et correctement protegee par authentification. "
                    f"Endpoint: {app_pw_url} retourne 401."
                ),
                evidence=Evidence(
                    request=f"GET {app_pw_url}",
                    response_status=401,
                    response_body_excerpt=body[:200],
                ),
                impact=(
                    "La fonctionnalite est active — les utilisateurs peuvent creer des "
                    "mots de passe d'application. Verifier que la politique est appropriee."
                ),
                remediation=(
                    "Si Application Passwords n'est pas necessaire, le desactiver: "
                    "add_filter('wp_is_application_passwords_available', '__return_false');"
                ),
                phase="enum",
                module=self.name,
            ))

        elif status == 404:
            # Feature disabled or endpoint removed — no finding needed
            result.add_data("app_passwords_exposed", False)
            result.add_data("app_passwords_enabled", False)

        else:
            # Other status codes (403, 500, etc.)
            result.add_data("app_passwords_status_note", f"Unexpected status: {status}")

        return result
