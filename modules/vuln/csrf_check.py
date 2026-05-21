"""CSRF protection audit module."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class CSRFCheckModule(BazookaModule):
    name = "vuln.csrf_check"
    phase = "vuln"
    description = "CSRF protection audit"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        # Test 1: admin-ajax.php nonce validation
        await self._test_ajax_nonce(ctx, session, result, base)

        # Test 2: Form CSRF tokens
        await self._test_form_csrf(ctx, session, result, base)

        # Test 3: REST API nonce enforcement
        await self._test_rest_nonce(ctx, session, result, base)

        return result

    async def _test_ajax_nonce(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Check if admin-ajax.php validates _wpnonce on heartbeat action."""
        ajax_url = f"{base}/wp-admin/admin-ajax.php"

        # Request without nonce
        try:
            resp_no_nonce = await session.post(
                ajax_url,
                data={"action": "heartbeat", "data[wp-auth-check]": "true"},
                use_cache=False,
            )
        except Exception:
            return

        # Request with random/invalid nonce
        try:
            resp_bad_nonce = await session.post(
                ajax_url,
                data={
                    "action": "heartbeat",
                    "data[wp-auth-check]": "true",
                    "_wpnonce": "invalid_nonce_12345",
                },
                use_cache=False,
            )
        except Exception:
            return

        no_nonce_status = resp_no_nonce.status_code
        bad_nonce_status = resp_bad_nonce.status_code
        no_nonce_body = resp_no_nonce.text.strip()
        bad_nonce_body = resp_bad_nonce.text.strip()

        # If both return same result and neither is an error, nonce might not be validated
        if (
            no_nonce_status == bad_nonce_status == 200
            and no_nonce_body == bad_nonce_body
            and no_nonce_body not in ("0", "-1", "")
            and len(no_nonce_body) > 5
        ):
            result.add_finding(Finding(
                id="VULN-CSRF-001",
                title="Nonce non valide sur admin-ajax.php (action heartbeat)",
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                confidence=Confidence.LIKELY,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    "L'action AJAX 'heartbeat' retourne la meme reponse avec ou sans nonce valide. "
                    "Cela indique que la verification du nonce _wpnonce n'est pas appliquee, "
                    "ce qui pourrait permettre des attaques CSRF sur cette action."
                ),
                evidence=Evidence(
                    request=f"POST {ajax_url}\naction=heartbeat (sans nonce vs nonce invalide)",
                    response_status=200,
                    response_body_excerpt=f"Sans nonce: {no_nonce_body[:200]}\nAvec nonce invalide: {bad_nonce_body[:200]}",
                ),
                impact=(
                    "Un attaquant peut forger des requetes AJAX au nom d'un utilisateur connecte. "
                    "L'impact depend des actions AJAX non protegees disponibles."
                ),
                remediation=(
                    "S'assurer que toutes les actions AJAX appellent check_ajax_referer() "
                    "pour verifier le nonce. Utiliser wp_create_nonce() cote frontend."
                ),
                compliance=Compliance(
                    owasp_2021="A01:2021 - Broken Access Control",
                    cwe="CWE-352",
                ),
                phase="vuln",
                module=self.name,
                tags=["csrf", "ajax", "nonce"],
            ))

    async def _test_form_csrf(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Check if forms on the site contain CSRF tokens."""
        pages_to_check = [
            (f"{base}/", "homepage"),
            (f"{base}/wp-login.php", "login page"),
        ]

        for url, page_name in pages_to_check:
            try:
                resp = await session.get(url, use_cache=False)
                if resp.status_code != 200:
                    continue
                body = resp.text

                # Find all forms
                forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
                if not forms:
                    continue

                for form_html in forms:
                    # Check if form has method="post"
                    # Only care about POST forms — GET forms don't need CSRF
                    form_tag_match = re.search(
                        r'<form[^>]*method=["\']?post["\']?[^>]*>',
                        body,
                        re.IGNORECASE,
                    )
                    if not form_tag_match:
                        continue

                    # Check for CSRF tokens
                    has_wpnonce = bool(re.search(
                        r'name=["\']_wpnonce["\']', form_html, re.IGNORECASE
                    ))
                    has_csrf = bool(re.search(
                        r'name=["\'](?:csrf|_csrf|csrfmiddlewaretoken|_token|authenticity_token)["\']',
                        form_html, re.IGNORECASE
                    ))
                    has_wp_referer = bool(re.search(
                        r'name=["\']_wp_http_referer["\']', form_html, re.IGNORECASE
                    ))

                    if not has_wpnonce and not has_csrf and not has_wp_referer:
                        # Check if it's the login form (special case)
                        is_login_form = bool(re.search(
                            r'name=["\'](?:log|user_login|pwd|user_pass)["\']',
                            form_html, re.IGNORECASE
                        ))

                        severity = Severity.MEDIUM if is_login_form else Severity.LOW
                        form_desc = "formulaire de connexion" if is_login_form else "formulaire POST"

                        result.add_finding(Finding(
                            id=f"VULN-CSRF-002",
                            title=f"Absence de token CSRF dans le {form_desc} ({page_name})",
                            severity=severity,
                            cvss_score=4.3 if is_login_form else 3.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                            confidence=Confidence.LIKELY,
                            finding_type=FindingType.MISCONFIGURATION,
                            description=(
                                f"Un {form_desc} sur {page_name} ({url}) ne contient pas de token "
                                f"CSRF (_wpnonce ou equivalent). "
                                + ("Le formulaire de connexion sans CSRF permet des attaques de "
                                   "login CSRF (forcer la connexion sur un compte controle par l'attaquant)."
                                   if is_login_form else
                                   "Les formulaires POST sans token CSRF sont vulnerables aux attaques "
                                   "de type Cross-Site Request Forgery.")
                            ),
                            evidence=Evidence(
                                request=f"GET {url}",
                                response_status=resp.status_code,
                                response_body_excerpt=form_html[:300],
                            ),
                            impact=(
                                "Attaque CSRF: un site malveillant peut soumettre le formulaire "
                                "au nom d'un utilisateur connecte sans son consentement."
                            ),
                            remediation=(
                                "Ajouter wp_nonce_field() dans tous les formulaires POST. "
                                "Verifier le nonce cote serveur avec wp_verify_nonce(). "
                                "Utiliser l'attribut SameSite=Strict sur les cookies de session."
                            ),
                            compliance=Compliance(
                                owasp_2021="A01:2021 - Broken Access Control",
                                cwe="CWE-352",
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                                "https://developer.wordpress.org/plugins/security/nonces/",
                            ],
                            phase="vuln",
                            module=self.name,
                            tags=["csrf", "forms", "nonce"],
                        ))
                        # Report only one missing CSRF per page
                        break

            except Exception:
                continue

    async def _test_rest_nonce(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Check if REST API enforces nonce for write operations."""
        api_url = f"{base}/wp-json/wp/v2/posts"

        try:
            # POST without any auth headers (no X-WP-Nonce, no cookie)
            resp = await session.post(
                api_url,
                data={"title": "bazooka_csrf_test", "status": "draft"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                use_cache=False,
            )

            body = resp.text
            status = resp.status_code

            # Expected: 401 with "rest_cookie_invalid_nonce" or "rest_not_logged_in"
            if status == 401:
                # Normal behavior — REST API requires auth
                try:
                    data = resp.json()
                    code = data.get("code", "")
                    if code in ("rest_cookie_invalid_nonce", "rest_not_logged_in", "rest_cannot_create"):
                        # This is correct behavior, no finding needed
                        return
                except Exception:
                    return
            elif status == 403:
                # Also acceptable — forbidden
                return
            elif status in (200, 201):
                # POST succeeded without nonce — critical issue
                result.add_finding(Finding(
                    id="VULN-CSRF-003",
                    title="REST API accepte les ecritures sans nonce ni authentification",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        "L'API REST WordPress accepte les requetes POST sur /wp/v2/posts "
                        "sans en-tete X-WP-Nonce ni authentification. "
                        "Le serveur a retourne un status {status}, indiquant que la creation "
                        "de contenu est possible sans verification d'identite."
                    ),
                    evidence=Evidence(
                        request=f"POST {api_url}\nContent-Type: application/x-www-form-urlencoded\n\ntitle=bazooka_csrf_test&status=draft",
                        response_status=status,
                        response_body_excerpt=body[:300],
                    ),
                    impact=(
                        "Creation, modification et suppression de contenu sans authentification. "
                        "Un attaquant peut publier du contenu malveillant, modifier des articles existants "
                        "ou effectuer un defacement complet du site."
                    ),
                    remediation=(
                        "Verifier que l'API REST exige X-WP-Nonce pour les ecritures. "
                        "S'assurer qu'aucun plugin ne desactive la verification d'authentification REST. "
                        "Tester: add_filter('rest_authentication_errors', ...)."
                    ),
                    compliance=Compliance(
                        owasp_2021="A01:2021 - Broken Access Control",
                        cwe="CWE-352",
                        mitre_attack="T1565 - Data Manipulation",
                    ),
                    phase="vuln",
                    module=self.name,
                    tags=["csrf", "rest-api", "nonce", "critical"],
                ))
        except Exception:
            pass
