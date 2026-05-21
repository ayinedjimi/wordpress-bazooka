"""WordPress misconfiguration detection — checks for common security misconfigurations."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# PHP versions considered end-of-life (< 8.0)
_EOL_PHP_PREFIXES = ("5.", "7.0", "7.1", "7.2", "7.3", "7.4")


class MisconfigCheckModule(BazookaModule):
    name = "vuln.misconfig_check"
    phase = "vuln"
    description = "WordPress misconfiguration detection"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        # ----------------------------------------------------------------
        # Check 1: WP_DEBUG enabled in production
        # ----------------------------------------------------------------
        try:
            homepage = await session.get(base, use_cache=True)
            body = homepage.text
            headers = dict(homepage.headers)

            debug_indicators = [
                "Notice:" in body and "on line" in body,
                "Warning:" in body and "on line" in body,
                "Fatal error:" in body,
                "Deprecated:" in body and "on line" in body,
                "WP_DEBUG" in body,
                "xdebug" in body.lower(),
            ]

            # Also check X-Debug-* headers
            debug_headers_found = [
                k for k in headers if k.lower().startswith("x-debug")
            ]

            if any(debug_indicators) or debug_headers_found:
                evidence_excerpt = ""
                for indicator_text in ["Notice:", "Warning:", "Fatal error:", "Deprecated:"]:
                    idx = body.find(indicator_text)
                    if idx >= 0:
                        evidence_excerpt = body[max(0, idx - 20):idx + 200]
                        break
                if debug_headers_found:
                    evidence_excerpt += f"\nDebug headers: {', '.join(debug_headers_found)}"

                result.add_finding(Finding(
                    id="VULN-MISCONF-DEBUG",
                    title="WP_DEBUG active en production",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        "WP_DEBUG est active en production. Des messages d'erreur PHP "
                        "sont visibles dans le HTML, revelant des chemins internes, "
                        "des noms de fichiers, et potentiellement des informations sensibles."
                    ),
                    evidence=Evidence(
                        request=f"GET {base}",
                        response_status=homepage.status_code,
                        response_body_excerpt=evidence_excerpt[:500],
                    ),
                    impact=(
                        "Divulgation d'informations: chemins du serveur, structure des fichiers, "
                        "versions des composants, stack traces avec parametres de fonctions."
                    ),
                    remediation=(
                        "Desactiver WP_DEBUG dans wp-config.php: define('WP_DEBUG', false); "
                        "En production, utiliser WP_DEBUG_LOG pour logger sans afficher."
                    ),
                    compliance=Compliance(
                        owasp_2021="A05:2021 - Security Misconfiguration",
                        cwe="CWE-209",
                        mitre_attack="T1592 - Gather Victim Host Information",
                    ),
                    references=[
                        "https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["debug", "misconfiguration", "information-disclosure"],
                ))
        except Exception:
            pass

        # ----------------------------------------------------------------
        # Check 2: File editing enabled (theme-editor.php accessible without 403)
        # ----------------------------------------------------------------
        try:
            resp = await session.get(
                f"{base}/wp-admin/theme-editor.php",
                use_cache=False,
                follow_redirects=False,
            )

            # If we get a 200 or a redirect to the login page (not a 403), editing is enabled
            # A 403 means the server explicitly blocks it
            # Note: without auth we'd get a redirect to login, which is normal
            # But if we get 200 with the editor content, that's worse (open editor)
            if resp.status_code == 200 and "textarea" in resp.text:
                result.add_finding(Finding(
                    id="VULN-MISCONF-EDITOR",
                    title="Editeur de fichiers WordPress accessible sans authentification",
                    severity=Severity.MEDIUM,
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        "L'editeur de themes WordPress est accessible. "
                        "Si un attaquant obtient des identifiants admin, il pourra "
                        "modifier les fichiers PHP directement pour injecter un webshell."
                    ),
                    evidence=Evidence(
                        request=f"GET {base}/wp-admin/theme-editor.php",
                        response_status=resp.status_code,
                    ),
                    impact=(
                        "En cas de compromission d'un compte admin, execution de code "
                        "arbitraire sur le serveur via modification des fichiers de theme."
                    ),
                    remediation=(
                        "Ajouter define('DISALLOW_FILE_EDIT', true); dans wp-config.php."
                    ),
                    compliance=Compliance(
                        owasp_2021="A05:2021 - Security Misconfiguration",
                        cwe="CWE-732",
                    ),
                    references=[
                        "https://developer.wordpress.org/plugins/security/securing-output/",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["file-editor", "misconfiguration", "hardening"],
                ))
            elif resp.status_code != 403:
                # Not explicitly blocked — editing is likely still enabled server-side
                result.add_finding(Finding(
                    id="VULN-MISCONF-EDITOR-SOFT",
                    title="Editeur de fichiers WordPress non bloque (HTTP 403 absent)",
                    severity=Severity.MEDIUM,
                    cvss_score=4.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N",
                    confidence=Confidence.LIKELY,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        "L'editeur de themes ne retourne pas un HTTP 403, ce qui indique "
                        "que DISALLOW_FILE_EDIT n'est probablement pas configure. "
                        "Un admin authentifie pourrait modifier les fichiers PHP."
                    ),
                    evidence=Evidence(
                        request=f"GET {base}/wp-admin/theme-editor.php",
                        response_status=resp.status_code,
                        response_headers={"Location": resp.headers.get("location", "")},
                    ),
                    impact="Risque de RCE en cas de compromission d'un compte admin.",
                    remediation="Ajouter define('DISALLOW_FILE_EDIT', true); dans wp-config.php.",
                    compliance=Compliance(
                        owasp_2021="A05:2021 - Security Misconfiguration",
                        cwe="CWE-732",
                    ),
                    phase="vuln",
                    module=self.name,
                    tags=["file-editor", "misconfiguration", "hardening"],
                ))
        except Exception:
            pass

        # ----------------------------------------------------------------
        # Check 3: PHP version in headers is EOL (< 8.0)
        # ----------------------------------------------------------------
        try:
            # Check multiple sources for PHP version
            php_version: str | None = None

            resp = await session.get(base, use_cache=True)
            # X-Powered-By header
            powered_by = resp.headers.get("x-powered-by", "")
            if "PHP" in powered_by:
                match = re.search(r"PHP/(\d+\.\d+(?:\.\d+)?)", powered_by)
                if match:
                    php_version = match.group(1)

            # Server header may also contain PHP version
            if not php_version:
                server_header = resp.headers.get("server", "")
                match = re.search(r"PHP/(\d+\.\d+(?:\.\d+)?)", server_header)
                if match:
                    php_version = match.group(1)

            if php_version and any(php_version.startswith(prefix) for prefix in _EOL_PHP_PREFIXES):
                result.add_finding(Finding(
                    id="VULN-MISCONF-PHP-EOL",
                    title=f"PHP {php_version} est en fin de vie (EOL)",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        f"Le serveur utilise PHP {php_version}, une version en fin de vie "
                        f"qui ne recoit plus de correctifs de securite. "
                        f"Toutes les versions PHP < 8.0 sont considerees EOL."
                    ),
                    evidence=Evidence(
                        request=f"GET {base}",
                        response_status=resp.status_code,
                        response_headers={"X-Powered-By": powered_by},
                    ),
                    impact=(
                        "Vulnerabilites PHP connues non corrigees. Risque d'exploitation "
                        "de failles dans le moteur PHP lui-meme (buffer overflow, type juggling, etc.)."
                    ),
                    remediation=(
                        f"Mettre a jour PHP vers une version supportee (>= 8.1). "
                        f"Verifier la compatibilite des plugins avant la migration."
                    ),
                    compliance=Compliance(
                        owasp_2021="A06:2021 - Vulnerable and Outdated Components",
                        cwe="CWE-1104",
                    ),
                    references=[
                        "https://www.php.net/supported-versions.php",
                        "https://www.php.net/eol.php",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["php", "eol", "outdated", "misconfiguration"],
                ))
        except Exception:
            pass

        # ----------------------------------------------------------------
        # Check 4: Default table prefix wp_ (from debug.log data if available)
        # ----------------------------------------------------------------
        debug_log_data = ctx.data.get("debug_log_data", {})
        table_prefix = debug_log_data.get("table_prefix", "")

        # Also check for wp_ prefix in error messages from debug mode
        if not table_prefix:
            try:
                resp = await session.get(base, use_cache=True)
                # Look for table names in error messages
                match = re.search(r"(wp_\w+)", resp.text)
                if match:
                    table_prefix = "wp_"
            except Exception:
                pass

        if table_prefix == "wp_" or (debug_log_data and debug_log_data.get("default_prefix")):
            result.add_finding(Finding(
                id="VULN-MISCONF-PREFIX",
                title="Prefixe de table WordPress par defaut (wp_)",
                severity=Severity.MEDIUM,
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.LIKELY,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    "Le site utilise le prefixe de table par defaut 'wp_'. "
                    "Cela facilite les attaques par injection SQL car l'attaquant "
                    "n'a pas besoin de deviner le nom des tables."
                ),
                evidence=Evidence(
                    request="Configuration analysis",
                    response_body_excerpt=f"Table prefix detected: {table_prefix or 'wp_'}",
                ),
                impact=(
                    "En cas d'injection SQL, les noms de tables (wp_users, wp_options) "
                    "sont previsibles, facilitant l'extraction de donnees."
                ),
                remediation=(
                    "Changer le prefixe de table dans wp-config.php ($table_prefix). "
                    "Utiliser un outil comme WP-CLI pour migrer les tables existantes."
                ),
                compliance=Compliance(
                    owasp_2021="A05:2021 - Security Misconfiguration",
                    cwe="CWE-1188",
                ),
                references=[
                    "https://developer.wordpress.org/advanced-administration/before-install/howto-install/#step-3-set-up-wp-config-php",
                ],
                phase="vuln",
                module=self.name,
                tags=["table-prefix", "hardening", "misconfiguration"],
            ))

        # ----------------------------------------------------------------
        # Check 5: User registration open (possibly with admin role)
        # ----------------------------------------------------------------
        registration_open = ctx.data.get("registration_open", False)
        default_role = ctx.data.get("default_registration_role", "")

        # Also check by trying to access the registration page
        if not registration_open:
            try:
                resp = await session.get(
                    f"{base}/wp-login.php?action=register",
                    use_cache=False,
                    follow_redirects=False,
                )
                # If we get a 200 with a registration form, registration is open
                if resp.status_code == 200 and (
                    "user_login" in resp.text or "Register" in resp.text
                ):
                    registration_open = True
                # If redirected back to login with "registration disabled" message, it's closed
                elif "registration" in resp.text.lower() and "disabled" in resp.text.lower():
                    registration_open = False
            except Exception:
                pass

        if registration_open:
            is_admin_role = default_role.lower() in ("administrator", "admin", "editor")
            severity = Severity.CRITICAL if is_admin_role else Severity.MEDIUM
            cvss = 9.8 if is_admin_role else 5.3

            result.add_finding(Finding(
                id="VULN-MISCONF-REGISTRATION",
                title=(
                    f"Inscription ouverte avec role '{default_role}'" if is_admin_role
                    else "Inscription des utilisateurs ouverte"
                ),
                severity=severity,
                cvss_score=cvss,
                cvss_vector=(
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if is_admin_role
                    else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                ),
                confidence=Confidence.CONFIRMED if is_admin_role else Confidence.LIKELY,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"L'inscription des utilisateurs est ouverte"
                    + (f" avec le role par defaut '{default_role}', "
                       f"permettant a n'importe qui de creer un compte avec des privileges eleves."
                       if is_admin_role
                       else ". Un attaquant peut creer un compte et acceder "
                            "aux fonctionnalites reservees aux utilisateurs connectes.")
                ),
                evidence=Evidence(
                    request=f"GET {base}/wp-login.php?action=register",
                    response_status=200,
                    response_body_excerpt=f"Registration open, default role: {default_role or 'subscriber'}",
                ),
                impact=(
                    "Prise de controle complete du site si le role par defaut est admin."
                    if is_admin_role else
                    "Acces utilisateur non autorise. Superficie d'attaque elargie pour "
                    "les vulnerabilites necessitant une authentification."
                ),
                remediation=(
                    "Desactiver l'inscription dans Reglages > General. "
                    "Si l'inscription est necessaire, verifier que le role par defaut est 'Abonne' (subscriber)."
                ),
                compliance=Compliance(
                    owasp_2021="A01:2021 - Broken Access Control",
                    cwe="CWE-732",
                ),
                phase="vuln",
                module=self.name,
                tags=["registration", "access-control", "misconfiguration"],
            ))

        return result
