"""Redis/Memcached object cache detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class ObjectCacheModule(BazookaModule):
    name = "enum.object_cache"
    phase = "enum"
    description = "Redis/Memcached object cache detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        wp_content = ctx.target.wp_content_path
        cache_type: str | None = None
        cache_exposed = False
        cache_details: dict = {}

        # Test 1: Check for object-cache.php (drop-in)
        object_cache_url = f"{base}{wp_content}object-cache.php"
        resp = await session.get(object_cache_url)

        if resp.status_code == 200:
            body = resp.text
            body_lower = body.lower()

            # Check if it's actual PHP source code (misconfigured server serving raw PHP)
            is_php_source = any(marker in body for marker in [
                "<?php", "<?=", "class ", "function ", "namespace ",
            ])

            if is_php_source:
                cache_exposed = True
                cache_details["object_cache_url"] = object_cache_url
                cache_details["response_size"] = len(resp.content)

                # Identify cache type from content
                if "redis" in body_lower:
                    cache_type = "Redis"
                elif "memcache" in body_lower:
                    cache_type = "Memcached"
                elif "apcu" in body_lower:
                    cache_type = "APCu"
                elif "xcache" in body_lower:
                    cache_type = "XCache"
                else:
                    cache_type = "Unknown"

                cache_details["cache_type"] = cache_type

                # Look for connection details in the exposed source
                connection_indicators = []
                if "host" in body_lower and ("127.0.0.1" in body or "localhost" in body):
                    connection_indicators.append("localhost connection")
                if "port" in body_lower:
                    connection_indicators.append("port configured")
                if "password" in body_lower or "auth" in body_lower:
                    connection_indicators.append("authentication configured")
                if "socket" in body_lower:
                    connection_indicators.append("unix socket connection")

                cache_details["connection_indicators"] = connection_indicators

        # Test 2: Check for Redis admin panels
        redis_admin_paths = [
            "/redis/",
            "/phpredmin/",
            "/redis-commander/",
            "/redis-admin/",
            "/redisinsight/",
        ]
        for path in redis_admin_paths:
            admin_url = f"{base}{path}"
            admin_resp = await session.get(admin_url)
            if admin_resp.status_code == 200:
                body = admin_resp.text.lower()
                if any(kw in body for kw in ["redis", "commander", "redisinsight", "phpredmin"]):
                    cache_details["redis_admin_url"] = admin_url
                    cache_type = cache_type or "Redis"
                    cache_exposed = True
                    result.add_finding(Finding(
                        id="ENUM-CACHE-002",
                        title=f"Interface d'administration Redis accessible: {path}",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=f"Panneau d'administration Redis accessible a {admin_url}.",
                        evidence=Evidence(
                            request=f"GET {admin_url}",
                            response_status=200,
                            response_body_excerpt=admin_resp.text[:200],
                        ),
                        impact="Acces direct au cache Redis permettant lecture/ecriture/suppression de donnees.",
                        remediation="Restreindre l'acces a l'interface Redis par IP ou authentification.",
                        compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-284"),
                        phase="enum",
                        module=self.name,
                    ))
                    break

        # Test 3: Check for Memcached admin panels
        memcached_admin_paths = [
            "/memcached/",
            "/phpmemcachedadmin/",
            "/memcache-admin/",
            "/memcache/",
        ]
        for path in memcached_admin_paths:
            admin_url = f"{base}{path}"
            admin_resp = await session.get(admin_url)
            if admin_resp.status_code == 200:
                body = admin_resp.text.lower()
                if any(kw in body for kw in ["memcache", "memcached", "slab", "stats"]):
                    cache_details["memcached_admin_url"] = admin_url
                    cache_type = cache_type or "Memcached"
                    cache_exposed = True
                    result.add_finding(Finding(
                        id="ENUM-CACHE-003",
                        title=f"Interface d'administration Memcached accessible: {path}",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=f"Panneau d'administration Memcached accessible a {admin_url}.",
                        evidence=Evidence(
                            request=f"GET {admin_url}",
                            response_status=200,
                            response_body_excerpt=admin_resp.text[:200],
                        ),
                        impact="Acces direct au cache Memcached permettant lecture/suppression de donnees.",
                        remediation="Restreindre l'acces a l'interface Memcached par IP ou authentification.",
                        compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-284"),
                        phase="enum",
                        module=self.name,
                    ))
                    break

        result.add_data("cache_type", cache_type)
        result.add_data("cache_exposed", cache_exposed)
        result.add_data("cache_details", cache_details)

        # Main finding for object-cache.php exposure
        if cache_exposed and cache_type:
            result.add_finding(Finding(
                id="ENUM-CACHE-001",
                title=f"Object cache expose: {cache_type} (object-cache.php accessible)",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Le fichier object-cache.php est accessible et revele l'utilisation "
                    f"de {cache_type} comme systeme de cache objet. "
                    f"URL: {object_cache_url}."
                ),
                evidence=Evidence(
                    request=f"GET {object_cache_url}",
                    response_status=200,
                    response_body_excerpt=resp.text[:300] if resp.status_code == 200 else "",
                ),
                impact=(
                    f"Le code source PHP du drop-in {cache_type} est expose, revelant "
                    f"la configuration du cache, potentiellement des hotes et ports de connexion."
                ),
                remediation=(
                    "Configurer le serveur web pour ne pas servir les fichiers PHP bruts. "
                    "Ajouter une regle deny dans .htaccess pour object-cache.php."
                ),
                compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-540"),
                phase="enum",
                module=self.name,
            ))

        return result
