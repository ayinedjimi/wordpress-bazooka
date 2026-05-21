"""Host header injection detection module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class HostHeaderInjectionModule(BazookaModule):
    name = "vuln.host_header_injection"
    phase = "vuln"
    description = "Host header injection detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        # Test 1: Password reset poisoning
        await self._test_password_reset_poisoning(ctx, session, result, base)

        # Test 2: X-Forwarded-Host injection
        await self._test_x_forwarded_host(ctx, session, result, base)

        # Test 3: General Host header reflection
        await self._test_host_reflection(ctx, session, result, base)

        return result

    async def _test_password_reset_poisoning(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Test password reset link poisoning via Host header."""
        reset_url = f"{base}/wp-login.php?action=lostpassword"
        evil_host = "evil.bazooka-test.com"

        # Determine the username to test with
        test_username = "admin"
        if ctx.target.users:
            test_username = ctx.target.users[0].username or ctx.target.users[0].slug or "admin"

        try:
            resp = await session.post(
                reset_url,
                data={
                    "user_login": test_username,
                    "redirect_to": "",
                    "wp-submit": "Get New Password",
                },
                headers={"Host": evil_host},
                follow_redirects=False,
                use_cache=False,
            )

            body = resp.text
            location = resp.headers.get("Location", "")

            # Check if evil host appears in response body or Location header
            evil_in_body = evil_host in body
            evil_in_location = evil_host in location

            if evil_in_body or evil_in_location:
                where = []
                if evil_in_body:
                    where.append("corps de la reponse")
                if evil_in_location:
                    where.append("en-tete Location")

                result.add_finding(Finding(
                    id="VULN-HOSTINJ-001",
                    title=f"Password reset poisoning via Host header sur {ctx.target.domain}",
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        f"L'en-tete Host est injecte dans la procedure de reinitialisation de mot de passe. "
                        f"Le domaine '{evil_host}' apparait dans: {', '.join(where)}. "
                        f"Un attaquant peut envoyer une demande de reset pour n'importe quel utilisateur, "
                        f"et le lien de reinitialisation contiendra le domaine de l'attaquant. "
                        f"Si la victime clique sur le lien dans l'email, le token de reset est envoye "
                        f"au serveur de l'attaquant."
                    ),
                    evidence=Evidence(
                        request=(
                            f"POST {reset_url}\n"
                            f"Host: {evil_host}\n"
                            f"Content-Type: application/x-www-form-urlencoded\n\n"
                            f"user_login={test_username}&wp-submit=Get+New+Password"
                        ),
                        response_status=resp.status_code,
                        response_headers={"Location": location} if evil_in_location else {},
                        response_body_excerpt=body[max(0, body.find(evil_host) - 100):body.find(evil_host) + 150] if evil_in_body else "",
                    ),
                    impact=(
                        "Prise de controle de compte: l'attaquant recupere le token de reinitialisation "
                        "de mot de passe et peut changer le mot de passe de n'importe quel utilisateur, "
                        "y compris les administrateurs."
                    ),
                    remediation=(
                        "Utiliser $_SERVER['SERVER_NAME'] au lieu de $_SERVER['HTTP_HOST'] pour "
                        "construire les URLs. Definir explicitement le domaine dans wp-config.php: "
                        "define('WP_HOME', 'https://yourdomain.com'); "
                        "define('WP_SITEURL', 'https://yourdomain.com'); "
                        "Configurer le serveur web pour rejeter les Host headers non reconnus."
                    ),
                    compliance=Compliance(
                        owasp_2021="A01:2021 - Broken Access Control",
                        cwe="CWE-74",
                        mitre_attack="T1557 - Adversary-in-the-Middle",
                    ),
                    references=[
                        "https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning",
                        "https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["host-header", "password-reset", "account-takeover"],
                ))
        except Exception:
            pass

    async def _test_x_forwarded_host(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Test X-Forwarded-Host header injection for cache poisoning."""
        evil_host = "evil.bazooka-test.com"

        try:
            resp = await session.get(
                base,
                headers={"X-Forwarded-Host": evil_host},
                use_cache=False,
            )

            body = resp.text
            if evil_host in body:
                # Find where it appears (link tags, script sources, meta tags, etc.)
                contexts = []
                body_lower = body.lower()
                if f'href="http://{evil_host}' in body_lower or f'href="https://{evil_host}' in body_lower:
                    contexts.append("liens href")
                if f'src="http://{evil_host}' in body_lower or f'src="https://{evil_host}' in body_lower:
                    contexts.append("sources de scripts/images")
                if f'action="http://{evil_host}' in body_lower or f'action="https://{evil_host}' in body_lower:
                    contexts.append("actions de formulaires")
                if not contexts:
                    contexts.append("texte de la page")

                # Extract excerpt around the injection point
                idx = body.find(evil_host)
                excerpt = body[max(0, idx - 80):idx + len(evil_host) + 80]

                result.add_finding(Finding(
                    id="VULN-HOSTINJ-002",
                    title=f"X-Forwarded-Host injecte dans le HTML — cache poisoning possible",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        f"L'en-tete X-Forwarded-Host est reflete dans le HTML de la page d'accueil. "
                        f"Le domaine '{evil_host}' apparait dans: {', '.join(contexts)}. "
                        f"Si un cache (CDN, reverse proxy) met en cache cette reponse, tous les visiteurs "
                        f"recevront du contenu pointe vers le domaine de l'attaquant (web cache poisoning)."
                    ),
                    evidence=Evidence(
                        request=f"GET {base}\nX-Forwarded-Host: {evil_host}",
                        response_status=resp.status_code,
                        response_body_excerpt=excerpt,
                    ),
                    impact=(
                        "Web cache poisoning: redirection des visiteurs vers un site controle "
                        "par l'attaquant via la corruption du cache. Potentiel phishing, "
                        "vol de credentials et distribution de malware."
                    ),
                    remediation=(
                        "Ignorer l'en-tete X-Forwarded-Host dans la generation des URLs. "
                        "Configurer le reverse proxy pour supprimer cet en-tete. "
                        "Utiliser des URLs relatives ou definir WP_HOME/WP_SITEURL explicitement."
                    ),
                    compliance=Compliance(
                        owasp_2021="A05:2021 - Security Misconfiguration",
                        cwe="CWE-644",
                    ),
                    references=[
                        "https://portswigger.net/research/practical-web-cache-poisoning",
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_HTTP_Incoming_Requests",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["host-header", "x-forwarded-host", "cache-poisoning"],
                ))
        except Exception:
            pass

    async def _test_host_reflection(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Test general Host header reflection."""
        evil_host = "evil.bazooka-test.com"

        try:
            # Use the IP or the resolved URL to avoid connection issues
            # when sending a different Host header
            resp = await session.get(
                base,
                headers={"Host": evil_host},
                use_cache=False,
            )

            body = resp.text
            response_headers = dict(resp.headers)

            reflected_in_body = evil_host in body
            reflected_in_headers = any(evil_host in v for v in response_headers.values())

            if reflected_in_body or reflected_in_headers:
                where = []
                if reflected_in_body:
                    where.append("corps HTML")
                if reflected_in_headers:
                    where.append("en-tetes de reponse")

                excerpt = ""
                if reflected_in_body:
                    idx = body.find(evil_host)
                    excerpt = body[max(0, idx - 80):idx + len(evil_host) + 80]

                reflected_headers = {
                    k: v for k, v in response_headers.items() if evil_host in v
                }

                result.add_finding(Finding(
                    id="VULN-HOSTINJ-003",
                    title=f"Host header reflete dans la reponse ({', '.join(where)})",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        f"Le serveur reflete l'en-tete Host dans sa reponse. "
                        f"Le domaine '{evil_host}' apparait dans: {', '.join(where)}. "
                        f"Bien que ce ne soit pas toujours exploitable directement, "
                        f"cela indique que le serveur n'applique pas de validation stricte "
                        f"de l'en-tete Host et pourrait etre vulnerable a d'autres attaques "
                        f"basees sur le Host header (SSRF, cache poisoning)."
                    ),
                    evidence=Evidence(
                        request=f"GET {base}\nHost: {evil_host}",
                        response_status=resp.status_code,
                        response_headers=reflected_headers if reflected_headers else {},
                        response_body_excerpt=excerpt if excerpt else None,
                    ),
                    impact=(
                        "Information: le serveur ne valide pas l'en-tete Host. "
                        "Peut faciliter des attaques de type cache poisoning, SSRF ou "
                        "redirection ouverte selon la configuration."
                    ),
                    remediation=(
                        "Configurer le serveur web (Apache/Nginx) pour n'accepter que les "
                        "Host headers correspondant au domaine configure. "
                        "Apache: utiliser ServerName et rejeter les requetes avec un Host invalide. "
                        "Nginx: utiliser un bloc server par defaut qui retourne 444."
                    ),
                    compliance=Compliance(
                        owasp_2021="A05:2021 - Security Misconfiguration",
                        cwe="CWE-644",
                    ),
                    references=[
                        "https://portswigger.net/web-security/host-header",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["host-header", "reflection", "information"],
                ))
        except Exception:
            pass
