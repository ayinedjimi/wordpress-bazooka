"""Insecure Direct Object Reference (IDOR) detection module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class IDORCheckModule(BazookaModule):
    name = "vuln.idor_check"
    phase = "vuln"
    description = "Insecure Direct Object Reference detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        api_base = f"{base}/wp-json"

        # Detect WooCommerce presence
        woo_detected = any(
            p.slug in ("woocommerce", "woo-commerce")
            for p in ctx.target.plugins
        ) if ctx.target.plugins else False
        # Also check from context data (other modules may have flagged it)
        if not woo_detected:
            namespaces = ctx.data.get("rest_api_namespaces", [])
            if isinstance(namespaces, list) and any("wc/" in ns for ns in namespaces):
                woo_detected = True

        # Test 1: User context=edit IDOR (should return 401)
        await self._test_user_context_edit(ctx, session, result, api_base)

        # Test 2: Media IDOR (check for private/unlisted media)
        await self._test_media_idor(ctx, session, result, api_base)

        # Test 3: Posts IDOR (draft/private posts)
        await self._test_posts_idor(ctx, session, result, api_base)

        # Test 4: WooCommerce orders IDOR
        if woo_detected:
            await self._test_woo_orders_idor(ctx, session, result, api_base)
            await self._test_woo_customers_idor(ctx, session, result, api_base)

        return result

    async def _test_user_context_edit(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, api_base: str
    ) -> None:
        """Test if user details are accessible with context=edit without auth."""
        for user_id in range(1, 6):
            url = f"{api_base}/wp/v2/users/{user_id}?context=edit"
            try:
                resp = await session.get(url, use_cache=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        continue
                    # context=edit should expose email, capabilities, etc.
                    if isinstance(data, dict) and ("email" in data or "capabilities" in data or "roles" in data):
                        username = data.get("slug", data.get("name", f"ID {user_id}"))
                        email = data.get("email", "non expose")
                        roles = data.get("roles", [])
                        result.add_finding(Finding(
                            id=f"VULN-IDOR-001",
                            title=f"IDOR: donnees utilisateur edit accessibles sans auth (user {user_id})",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.MISCONFIGURATION,
                            description=(
                                f"L'endpoint /wp/v2/users/{user_id}?context=edit retourne les donnees "
                                f"d'edition de l'utilisateur '{username}' sans authentification. "
                                f"Email: {email}, Roles: {', '.join(roles) if roles else 'non expose'}. "
                                f"Ce context devrait exiger une authentification."
                            ),
                            evidence=Evidence(
                                request=f"GET {url}",
                                response_status=200,
                                response_body_excerpt=str({
                                    k: data.get(k) for k in ["id", "slug", "email", "roles", "capabilities"]
                                    if k in data
                                })[:500],
                            ),
                            impact=(
                                "Exposition d'emails, roles et capacites des utilisateurs. "
                                "Permet l'enumeration complete des comptes et la preparation d'attaques ciblees."
                            ),
                            remediation=(
                                "S'assurer que le context=edit exige une authentification. "
                                "Verifier les filtres REST API et les permissions des endpoints."
                            ),
                            compliance=Compliance(
                                owasp_2021="A01:2021 - Broken Access Control",
                                cwe="CWE-639",
                                mitre_attack="T1087 - Account Discovery",
                            ),
                            references=[
                                "https://developer.wordpress.org/rest-api/reference/users/",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                            ],
                            phase="vuln",
                            module=self.name,
                            tags=["idor", "users", "api", "access-control"],
                        ))
                        # One finding is enough for this category
                        return
            except Exception:
                continue

    async def _test_media_idor(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, api_base: str
    ) -> None:
        """Test sequential media ID access for private/unlisted media."""
        private_media_count = 0
        sample_urls = []

        for media_id in range(1, 21):
            url = f"{api_base}/wp/v2/media/{media_id}"
            try:
                resp = await session.get(url, use_cache=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        continue
                    if isinstance(data, dict):
                        status = data.get("status", "")
                        source_url = data.get("source_url", "")
                        # Flag media that isn't public/inheriting
                        if status in ("private", "draft", "trash"):
                            private_media_count += 1
                            if len(sample_urls) < 3:
                                sample_urls.append(source_url)
            except Exception:
                continue

        if private_media_count > 0:
            result.add_finding(Finding(
                id="VULN-IDOR-002",
                title=f"IDOR: {private_media_count} media(s) prive(s) accessibles via REST API",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"{private_media_count} fichier(s) media avec statut prive accessible(s) sans authentification "
                    f"via enumeration sequentielle des IDs sur /wp/v2/media/{{id}}. "
                    f"Exemples: {', '.join(sample_urls) if sample_urls else 'N/A'}."
                ),
                evidence=Evidence(
                    request=f"GET {api_base}/wp/v2/media/1..20",
                    response_status=200,
                    response_body_excerpt=f"Private media found: {private_media_count} items",
                ),
                impact=(
                    "Documents, images et fichiers prives accessibles publiquement. "
                    "Potentielle fuite de donnees confidentielles."
                ),
                remediation=(
                    "Configurer les permissions REST API pour les medias. "
                    "Utiliser un plugin de securite pour restreindre l'acces aux medias prives."
                ),
                compliance=Compliance(
                    owasp_2021="A01:2021 - Broken Access Control",
                    cwe="CWE-639",
                ),
                phase="vuln",
                module=self.name,
                tags=["idor", "media", "api", "access-control"],
            ))

    async def _test_posts_idor(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, api_base: str
    ) -> None:
        """Test sequential post ID access for draft/private posts."""
        exposed_posts = []

        for post_id in range(1, 11):
            url = f"{api_base}/wp/v2/posts/{post_id}?_embed"
            try:
                resp = await session.get(url, use_cache=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        continue
                    if isinstance(data, dict):
                        status = data.get("status", "")
                        title_rendered = data.get("title", {}).get("rendered", "sans titre")
                        if status in ("draft", "private", "pending"):
                            exposed_posts.append({
                                "id": post_id,
                                "status": status,
                                "title": title_rendered,
                            })
            except Exception:
                continue

        if exposed_posts:
            post_details = "; ".join(
                f"ID {p['id']}: '{p['title']}' ({p['status']})" for p in exposed_posts[:5]
            )
            result.add_finding(Finding(
                id="VULN-IDOR-003",
                title=f"IDOR: {len(exposed_posts)} article(s) non publie(s) accessible(s) via REST API",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"{len(exposed_posts)} article(s) avec statut non-publie accessible(s) par enumeration "
                    f"d'IDs: {post_details}."
                ),
                evidence=Evidence(
                    request=f"GET {api_base}/wp/v2/posts/1..10?_embed",
                    response_status=200,
                    response_body_excerpt=str(exposed_posts[:3])[:500],
                ),
                impact="Fuite de contenu non publie, potentiellement sensible ou confidentiel.",
                remediation="Restreindre l'acces REST API aux articles non publies.",
                compliance=Compliance(
                    owasp_2021="A01:2021 - Broken Access Control",
                    cwe="CWE-639",
                ),
                phase="vuln",
                module=self.name,
                tags=["idor", "posts", "api", "access-control"],
            ))

    async def _test_woo_orders_idor(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, api_base: str
    ) -> None:
        """Test WooCommerce orders endpoint for IDOR."""
        for order_id in range(1, 6):
            url = f"{api_base}/wc/v3/orders/{order_id}"
            try:
                resp = await session.get(url, use_cache=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        continue
                    if isinstance(data, dict) and ("billing" in data or "total" in data or "line_items" in data):
                        billing = data.get("billing", {})
                        total = data.get("total", "inconnu")
                        result.add_finding(Finding(
                            id="VULN-IDOR-004",
                            title=f"IDOR CRITIQUE: commandes WooCommerce accessibles sans auth (order {order_id})",
                            severity=Severity.CRITICAL,
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.MISCONFIGURATION,
                            description=(
                                f"La commande WooCommerce #{order_id} est accessible sans authentification. "
                                f"Montant: {total}. Donnees de facturation exposees (nom, adresse, email). "
                                f"Un attaquant peut enumerer toutes les commandes par ID sequentiel."
                            ),
                            evidence=Evidence(
                                request=f"GET {url}",
                                response_status=200,
                                response_body_excerpt=str({
                                    "id": order_id,
                                    "total": total,
                                    "billing_email": billing.get("email", ""),
                                    "billing_name": f"{billing.get('first_name', '')} {billing.get('last_name', '')}",
                                })[:500],
                            ),
                            impact=(
                                "Exposition massive de donnees personnelles: noms, adresses, emails, "
                                "numeros de telephone, historique d'achats. Violation RGPD majeure."
                            ),
                            remediation=(
                                "Configurer l'authentification WooCommerce REST API correctement. "
                                "S'assurer que les endpoints WC requierent des cles API ou des tokens OAuth. "
                                "Verifier les permissions dans WooCommerce > Settings > Advanced > REST API."
                            ),
                            compliance=Compliance(
                                owasp_2021="A01:2021 - Broken Access Control",
                                cwe="CWE-639",
                                pci_dss_v4="6.2.4",
                            ),
                            references=[
                                "https://woocommerce.github.io/woocommerce-rest-api-docs/#authentication",
                                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                            ],
                            phase="vuln",
                            module=self.name,
                            tags=["idor", "woocommerce", "orders", "pii", "critical"],
                        ))
                        return
            except Exception:
                continue

    async def _test_woo_customers_idor(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, api_base: str
    ) -> None:
        """Test WooCommerce customers endpoint for IDOR."""
        for customer_id in range(1, 6):
            url = f"{api_base}/wc/v3/customers/{customer_id}"
            try:
                resp = await session.get(url, use_cache=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        continue
                    if isinstance(data, dict) and ("email" in data or "billing" in data):
                        email = data.get("email", "non expose")
                        first_name = data.get("first_name", "")
                        last_name = data.get("last_name", "")
                        result.add_finding(Finding(
                            id="VULN-IDOR-005",
                            title=f"IDOR CRITIQUE: clients WooCommerce accessibles sans auth (customer {customer_id})",
                            severity=Severity.CRITICAL,
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.MISCONFIGURATION,
                            description=(
                                f"Le profil client WooCommerce #{customer_id} est accessible sans authentification. "
                                f"Client: {first_name} {last_name}, Email: {email}. "
                                f"Un attaquant peut enumerer tous les clients par ID sequentiel."
                            ),
                            evidence=Evidence(
                                request=f"GET {url}",
                                response_status=200,
                                response_body_excerpt=str({
                                    "id": customer_id,
                                    "email": email,
                                    "name": f"{first_name} {last_name}",
                                })[:500],
                            ),
                            impact=(
                                "Exposition de donnees personnelles des clients: emails, noms, adresses. "
                                "Violation RGPD et risque de phishing cible."
                            ),
                            remediation=(
                                "Configurer l'authentification WooCommerce REST API. "
                                "Exiger des cles API pour tout acces aux donnees clients."
                            ),
                            compliance=Compliance(
                                owasp_2021="A01:2021 - Broken Access Control",
                                cwe="CWE-639",
                                pci_dss_v4="6.2.4",
                            ),
                            phase="vuln",
                            module=self.name,
                            tags=["idor", "woocommerce", "customers", "pii", "critical"],
                        ))
                        return
            except Exception:
                continue
