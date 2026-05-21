"""WooCommerce enumeration — products, routes, store API."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class WooCommerceModule(BazookaModule):
    name = "enum.woocommerce"
    phase = "enum"
    description = "WooCommerce enumeration"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        namespaces = ctx.data.get("rest_api_namespaces", [])

        wc_detected = any(ns.startswith("wc/") for ns in namespaces)
        if not wc_detected:
            return result

        result.add_data("woocommerce_detected", True)

        # 1. Store API products (public by design)
        resp = await session.get(f"{base}/wp-json/wc/store/v1/products?per_page=20")
        if resp.status_code == 200:
            try:
                products = resp.json()
                if isinstance(products, list) and products:
                    result.add_data("wc_products_count", len(products))
                    result.add_finding(Finding(
                        id="ENUM-WC-001",
                        title=f"WooCommerce Store API: {len(products)} produit(s) exposes",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.INFORMATION_DISCLOSURE,
                        description=f"L'API Store WooCommerce expose {len(products)} produits (public par design).",
                        phase="enum", module=self.name,
                    ))
            except Exception:
                pass

        # 2. REST API v3 products (should require auth)
        resp = await session.get(f"{base}/wp-json/wc/v3/products?per_page=20")
        if resp.status_code == 200:
            try:
                products = resp.json()
                if isinstance(products, list) and products:
                    result.add_finding(Finding(
                        id="ENUM-WC-002",
                        title=f"WooCommerce REST API v3 products accessible sans auth!",
                        severity=Severity.CRITICAL,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=f"/wc/v3/products retourne {len(products)} produits sans authentification. Normalement protege.",
                        impact="Donnees catalogue exposees, potentiellement prix B2B, stock, etc.",
                        remediation="Verifier les cles API WooCommerce et restreindre l'acces REST.",
                        compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-862"),
                        phase="enum", module=self.name,
                    ))
            except Exception:
                pass

        # 3. Customers endpoint (must be 401)
        resp = await session.get(f"{base}/wp-json/wc/v3/customers")
        if resp.status_code == 200:
            result.add_finding(Finding(
                id="ENUM-WC-003",
                title="WooCommerce customers accessible sans authentification!",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description="Les donnees clients WooCommerce sont accessibles sans auth.",
                impact="Fuite de donnees personnelles clients (noms, emails, adresses). Violation RGPD.",
                remediation="Securiser l'API WooCommerce avec des cles consumer.",
                compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-862"),
                phase="enum", module=self.name,
            ))

        # 4. Orders endpoint (must be 401)
        resp = await session.get(f"{base}/wp-json/wc/v3/orders")
        if resp.status_code == 200:
            result.add_finding(Finding(
                id="ENUM-WC-004",
                title="WooCommerce orders accessible sans authentification!",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description="Les commandes WooCommerce sont accessibles sans auth.",
                impact="Fuite de commandes, montants, adresses de livraison. Violation RGPD.",
                remediation="Securiser l'API WooCommerce.",
                compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-862"),
                phase="enum", module=self.name,
            ))

        return result

    def should_run(self, ctx) -> bool:
        namespaces = ctx.data.get("rest_api_namespaces", [])
        return any(ns.startswith("wc/") for ns in namespaces)
