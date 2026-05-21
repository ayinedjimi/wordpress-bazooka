"""WordPress cron analysis — wp-cron.php accessibility and configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class CronJobsModule(BazookaModule):
    name = "enum.cron_jobs"
    phase = "enum"
    description = "WordPress cron analysis"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        cron_accessible = False
        cron_data: dict = {}

        # Test 1: Direct wp-cron.php access
        cron_url = f"{base}/wp-cron.php"
        resp = await session.get(cron_url)
        cron_status = resp.status_code
        cron_body = resp.text
        cron_size = len(resp.content) if resp.content else 0

        if cron_status == 200:
            # wp-cron.php returns empty 200 when accessible and executed successfully
            # A blocked cron would return 403/404 or a custom error page
            cron_accessible = True
            cron_data["status_code"] = cron_status
            cron_data["response_size"] = cron_size

            # Also test with a POST (wp-cron.php accepts POST for triggering)
            post_resp = await session.post(cron_url, data={})
            cron_data["post_status"] = post_resp.status_code

        elif cron_status == 403:
            cron_data["status_code"] = 403
            cron_data["note"] = "wp-cron.php blocked (403 Forbidden)"

        elif cron_status == 404:
            cron_data["status_code"] = 404
            cron_data["note"] = "wp-cron.php not found (possibly renamed or removed)"

        # Test 2: Check for DISABLE_WP_CRON indicator
        # If wp-cron.php returns quickly with an empty body, cron is likely running via system cron
        # If it returns slowly, WP pseudo-cron is active
        if cron_accessible and cron_size == 0:
            cron_data["likely_system_cron"] = False
            cron_data["note"] = "wp-cron.php responds empty — standard WP pseudo-cron"

        # Test 3: Check REST API for cron-related endpoints or data
        api_url = f"{base}/wp-json/wp/v2/"
        api_resp = await session.get(api_url, use_cache=True)
        if api_resp.status_code == 200:
            try:
                api_data = api_resp.json()
                # Look for cron-related info in the root response
                if isinstance(api_data, dict):
                    # Some plugins expose cron info
                    routes = list(api_data.get("routes", {}).keys()) if "routes" in api_data else []
                    cron_routes = [r for r in routes if "cron" in r.lower()]
                    if cron_routes:
                        cron_data["cron_api_routes"] = cron_routes
            except Exception:
                pass

        # Test 4: Check wp-cron.php with doing_cron parameter
        cron_doing_url = f"{base}/wp-cron.php?doing_wp_cron=1"
        doing_resp = await session.get(cron_doing_url)
        cron_data["doing_cron_status"] = doing_resp.status_code

        result.add_data("cron_accessible", cron_accessible)
        result.add_data("cron_details", cron_data)

        if cron_accessible:
            result.add_finding(Finding(
                id="ENUM-CRON-001",
                title="wp-cron.php accessible publiquement",
                severity=Severity.LOW,
                cvss_score=3.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"wp-cron.php est accessible publiquement a {cron_url}. "
                    f"Status: {cron_status}, taille reponse: {cron_size} bytes."
                ),
                evidence=Evidence(
                    request=f"GET {cron_url}",
                    response_status=cron_status,
                    response_body_excerpt=cron_body[:200] if cron_body else "(empty)",
                ),
                impact=(
                    "wp-cron.php accessible peut etre utilise comme vecteur DDoS (amplification). "
                    "Il revele aussi des informations de timing sur les taches planifiees. "
                    "Des appels repetes peuvent surcharger le serveur."
                ),
                remediation=(
                    "Bloquer l'acces public a wp-cron.php via .htaccess ou le pare-feu. "
                    "Utiliser un vrai cron systeme: define('DISABLE_WP_CRON', true); dans wp-config.php "
                    "et configurer: */15 * * * * wget -q -O - {cron_url} > /dev/null 2>&1"
                ),
                compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-400"),
                phase="enum",
                module=self.name,
            ))

        return result
