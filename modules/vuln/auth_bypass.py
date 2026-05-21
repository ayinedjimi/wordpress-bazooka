"""Authentication bypass detection module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Admin AJAX actions that should require authentication/nonce
PROTECTED_AJAX_ACTIONS = [
    ("heartbeat", "WordPress heartbeat"),
    ("wp-remove-post-lock", "remove post lock"),
    ("save-attachment", "save attachment metadata"),
    ("save-attachment-compat", "save attachment compat"),
    ("query-attachments", "query media attachments"),
    ("get-comments", "get comments"),
    ("replyto-comment", "reply to comment"),
    ("edit-comment", "edit comment"),
    ("trash-post", "trash a post"),
    ("get-permalink", "get post permalink"),
]


class AuthBypassModule(BazookaModule):
    name = "vuln.auth_bypass"
    phase = "vuln"
    description = "Authentication bypass detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        # Test 1: REST API context=edit without auth
        await self._test_rest_context_edit(ctx, session, result, base)

        # Test 2: Admin AJAX without nonce
        await self._test_ajax_no_nonce(ctx, session, result, base)

        # Test 3: admin-post.php access
        await self._test_admin_post(ctx, session, result, base)

        # Test 4: Application Passwords endpoint
        await self._test_app_passwords(ctx, session, result, base)

        return result

    async def _test_rest_context_edit(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Test if REST API context=edit is accessible without authentication."""
        api_base = f"{base}/wp-json"

        # Test users endpoint with context=edit
        try:
            url = f"{api_base}/wp/v2/users/1?context=edit"
            resp = await session.get(url, use_cache=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = {}
                if isinstance(data, dict) and ("email" in data or "capabilities" in data):
                    result.add_finding(Finding(
                        id="VULN-AUTHBYPASS-001",
                        title="Bypass auth: /wp/v2/users/1?context=edit retourne 200 sans authentification",
                        severity=Severity.CRITICAL,
                        cvss_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=(
                            "L'endpoint REST API /wp/v2/users/1?context=edit est accessible sans "
                            "authentification. Ce context devrait exiger un token ou cookie valide. "
                            "Les donnees d'edition completes de l'utilisateur (email, capabilities, "
                            "roles) sont exposees."
                        ),
                        evidence=Evidence(
                            request=f"GET {url}",
                            response_status=200,
                            response_body_excerpt=str({
                                k: data.get(k) for k in ["id", "email", "roles", "capabilities"]
                                if k in data
                            })[:500],
                        ),
                        impact=(
                            "Acces complet aux donnees d'edition des utilisateurs sans authentification. "
                            "Permet l'enumeration de tous les comptes, emails et roles."
                        ),
                        remediation=(
                            "Verifier que le filtre rest_authentication_errors est correctement configure. "
                            "S'assurer qu'un plugin de securite ne desactive pas la verification d'auth REST. "
                            "Ajouter: add_filter('rest_authentication_errors', function($result) { "
                            "if (!is_user_logged_in()) return new WP_Error('rest_not_logged_in', '', array('status' => 401)); "
                            "return $result; });"
                        ),
                        compliance=Compliance(
                            owasp_2021="A07:2021 - Identification and Authentication Failures",
                            cwe="CWE-306",
                            mitre_attack="T1078 - Valid Accounts",
                        ),
                        references=[
                            "https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/",
                        ],
                        phase="vuln",
                        module=self.name,
                        tags=["auth-bypass", "rest-api", "context-edit", "critical"],
                    ))
                    return
        except Exception:
            pass

        # Test posts endpoint with context=edit
        try:
            url = f"{api_base}/wp/v2/posts?context=edit"
            resp = await session.get(url, use_cache=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = []
                if isinstance(data, list) and len(data) > 0:
                    # Check if we got edit-level fields (raw content, password, etc.)
                    first_post = data[0] if data else {}
                    has_edit_fields = any(
                        k in first_post for k in ["password", "raw"]
                    )
                    # Also check nested raw content
                    content = first_post.get("content", {})
                    if isinstance(content, dict) and "raw" in content:
                        has_edit_fields = True

                    if has_edit_fields:
                        result.add_finding(Finding(
                            id="VULN-AUTHBYPASS-002",
                            title="Bypass auth: /wp/v2/posts?context=edit accessible sans authentification",
                            severity=Severity.CRITICAL,
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.MISCONFIGURATION,
                            description=(
                                "L'endpoint REST API /wp/v2/posts?context=edit retourne des donnees "
                                "d'edition (contenu raw, mots de passe) sans authentification."
                            ),
                            evidence=Evidence(
                                request=f"GET {api_base}/wp/v2/posts?context=edit",
                                response_status=200,
                                response_body_excerpt=str(first_post)[:500],
                            ),
                            impact="Acces au contenu brut des articles, y compris les brouillons et contenus proteges.",
                            remediation="Restreindre le context=edit aux utilisateurs authentifies.",
                            compliance=Compliance(
                                owasp_2021="A07:2021 - Identification and Authentication Failures",
                                cwe="CWE-306",
                            ),
                            phase="vuln",
                            module=self.name,
                            tags=["auth-bypass", "rest-api", "context-edit"],
                        ))
        except Exception:
            pass

    async def _test_ajax_no_nonce(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Test admin-ajax.php actions without nonce validation."""
        ajax_url = f"{base}/wp-admin/admin-ajax.php"
        vulnerable_actions = []

        for action, action_desc in PROTECTED_AJAX_ACTIONS:
            try:
                resp = await session.post(
                    ajax_url,
                    data={"action": action},
                    use_cache=False,
                )
                if resp.status_code == 200:
                    body = resp.text.strip()
                    # A "0" or "-1" response typically means auth/nonce failure — that's expected
                    # An empty response or HTML/JSON with content means the action executed
                    if body and body != "0" and body != "-1" and len(body) > 5:
                        vulnerable_actions.append({
                            "action": action,
                            "description": action_desc,
                            "response_length": len(body),
                            "response_excerpt": body[:200],
                        })
            except Exception:
                continue

        if vulnerable_actions:
            actions_str = ", ".join(a["action"] for a in vulnerable_actions)
            result.add_finding(Finding(
                id="VULN-AUTHBYPASS-003",
                title=f"AJAX actions sans auth/nonce: {actions_str}",
                severity=Severity.HIGH,
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                confidence=Confidence.LIKELY,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"{len(vulnerable_actions)} action(s) admin-ajax.php retournent des donnees "
                    f"significatives sans authentification ni nonce: {actions_str}. "
                    f"Ces actions devraient exiger une session WordPress valide et un nonce."
                ),
                evidence=Evidence(
                    request=f"POST {ajax_url}\naction={vulnerable_actions[0]['action']}",
                    response_status=200,
                    response_body_excerpt=vulnerable_actions[0]["response_excerpt"],
                ),
                impact=(
                    "Des actions administratives peuvent etre executees sans authentification. "
                    "Selon l'action, cela peut permettre la lecture de donnees, la modification "
                    "de contenus ou l'execution d'operations privilegiees."
                ),
                remediation=(
                    "S'assurer que chaque handler AJAX verifie: "
                    "1) check_ajax_referer() pour le nonce, "
                    "2) current_user_can() pour les permissions. "
                    "Verifier les hooks wp_ajax_nopriv_ non voulus."
                ),
                compliance=Compliance(
                    owasp_2021="A07:2021 - Identification and Authentication Failures",
                    cwe="CWE-306",
                ),
                phase="vuln",
                module=self.name,
                tags=["auth-bypass", "ajax", "nonce"],
            ))

    async def _test_admin_post(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Test if admin-post.php is accessible without redirect to login."""
        url = f"{base}/wp-admin/admin-post.php"
        try:
            resp = await session.get(url, follow_redirects=False, use_cache=False)
            # Normal behavior: 302 redirect to wp-login.php
            # Vulnerable: 200 without redirect
            if resp.status_code == 200:
                body = resp.text.lower()
                # Make sure it's not just the login page content
                if "wp-login.php" not in body and "log in" not in body:
                    result.add_finding(Finding(
                        id="VULN-AUTHBYPASS-004",
                        title="admin-post.php accessible sans redirection vers login",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        confidence=Confidence.LIKELY,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=(
                            "L'endpoint /wp-admin/admin-post.php retourne une reponse 200 "
                            "au lieu de rediriger vers la page de connexion. "
                            "Ce fichier est normalement protege et devrait exiger une authentification."
                        ),
                        evidence=Evidence(
                            request=f"GET {url}",
                            response_status=200,
                            response_body_excerpt=resp.text[:300],
                        ),
                        impact=(
                            "Acces potentiel a des fonctionnalites administratives. "
                            "Les actions admin-post.php enregistrees via admin_post_nopriv_ "
                            "pourraient etre exploitees."
                        ),
                        remediation=(
                            "Verifier la configuration .htaccess/nginx pour la protection de /wp-admin/. "
                            "S'assurer que admin-post.php redirige les utilisateurs non-connectes."
                        ),
                        compliance=Compliance(
                            owasp_2021="A07:2021 - Identification and Authentication Failures",
                            cwe="CWE-306",
                        ),
                        phase="vuln",
                        module=self.name,
                        tags=["auth-bypass", "admin", "access-control"],
                    ))
        except Exception:
            pass

    async def _test_app_passwords(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Check if Application Passwords endpoint is accessible without auth."""
        url = f"{base}/wp-json/wp/v2/users/me/application-passwords"
        try:
            resp = await session.get(url, use_cache=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = None

                # If we get a list of application passwords, this is critical
                if isinstance(data, list):
                    result.add_finding(Finding(
                        id="VULN-AUTHBYPASS-005",
                        title="Application Passwords listees sans authentification!",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=(
                            f"L'endpoint /wp/v2/users/me/application-passwords retourne la liste "
                            f"des mots de passe d'application sans authentification. "
                            f"{len(data)} mot(s) de passe d'application trouve(s). "
                            f"Cela permet un acces complet a l'API REST avec les privileges de l'utilisateur."
                        ),
                        evidence=Evidence(
                            request=f"GET {url}",
                            response_status=200,
                            response_body_excerpt=str(data[:2])[:500] if data else "empty list",
                        ),
                        impact=(
                            "Acces complet aux mots de passe d'application. "
                            "Permet l'authentification API REST avec tous les privileges de l'utilisateur. "
                            "Compromission totale du site WordPress."
                        ),
                        remediation=(
                            "Corriger immediatement le mecanisme d'authentification REST API. "
                            "Revoquer tous les mots de passe d'application existants. "
                            "Verifier qu'aucun plugin ne desactive l'authentification REST API."
                        ),
                        compliance=Compliance(
                            owasp_2021="A07:2021 - Identification and Authentication Failures",
                            cwe="CWE-306",
                            mitre_attack="T1078 - Valid Accounts",
                        ),
                        references=[
                            "https://developer.wordpress.org/rest-api/reference/application-passwords/",
                            "https://make.wordpress.org/core/2020/11/05/application-passwords-integration-guide/",
                        ],
                        phase="vuln",
                        module=self.name,
                        tags=["auth-bypass", "app-passwords", "critical", "rest-api"],
                    ))
        except Exception:
            pass
