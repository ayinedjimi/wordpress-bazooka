"""WPGraphQL introspection enumeration module."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

SENSITIVE_TYPES = [
    "User", "UserConnection", "UserEdge",
    "Order", "OrderConnection", "OrderEdge",
    "Customer", "CustomerConnection", "CustomerEdge",
    "Payment", "Coupon", "Refund",
    "MediaItem", "RootMutation", "RootQuery",
]

DANGEROUS_MUTATIONS = [
    "createUser", "updateUser", "deleteUser",
    "createPost", "updatePost", "deletePost",
    "createPage", "updatePage", "deletePage",
    "createMediaItem", "deleteMediaItem",
    "createComment", "updateComment", "deleteComment",
    "updateSettings", "createOrder", "updateOrder",
    "sendPasswordResetEmail", "registerUser",
]

INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { types { name kind fields { name } } } }"
})

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/wp-graphql",
    "/index.php?graphql",
]


class GraphQLEnumModule(BazookaModule):
    name = "enum.graphql_enum"
    phase = "enum"
    description = "WPGraphQL introspection enumeration"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        schema_data = None
        successful_endpoint = None

        for endpoint in GRAPHQL_ENDPOINTS:
            url = f"{base}{endpoint}"
            try:
                resp = await session.post(
                    url,
                    content=INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except Exception:
                        continue

                    if isinstance(body, dict) and "__schema" in body.get("data", {}):
                        schema_data = body["data"]["__schema"]
                        successful_endpoint = endpoint
                        break
            except Exception:
                continue

        if schema_data is None:
            return result

        # Parse schema
        types_list = schema_data.get("types", [])
        total_types = len(types_list)
        total_fields = 0
        found_sensitive = []
        found_mutations = []

        for t in types_list:
            type_name = t.get("name", "")
            fields = t.get("fields") or []
            total_fields += len(fields)

            # Check for sensitive types
            for sensitive in SENSITIVE_TYPES:
                if type_name == sensitive:
                    found_sensitive.append(type_name)
                    break

            # Check mutation fields for dangerous operations
            if type_name in ("RootMutation", "Mutation"):
                for field in fields:
                    field_name = field.get("name", "")
                    for dangerous in DANGEROUS_MUTATIONS:
                        if field_name == dangerous:
                            found_mutations.append(field_name)
                            break

        # Store schema summary in ctx.data
        schema_summary = {
            "endpoint": successful_endpoint,
            "total_types": total_types,
            "total_fields": total_fields,
            "sensitive_types": found_sensitive,
            "mutations": found_mutations,
            "introspection_enabled": True,
        }
        ctx.data["graphql_schema"] = schema_summary
        result.add_data("graphql_schema", schema_summary)

        # Determine severity
        has_mutations = len(found_mutations) > 0

        if has_mutations:
            severity = Severity.HIGH
            cvss = 7.5
            description = (
                f"L'introspection GraphQL est activee sur {successful_endpoint}. "
                f"Le schema expose {total_types} types et {total_fields} champs. "
                f"Types sensibles detectes: {', '.join(found_sensitive) if found_sensitive else 'aucun'}. "
                f"Mutations dangereuses exposees: {', '.join(found_mutations)}. "
                f"Un attaquant peut comprendre la structure complete de l'API et exploiter les mutations."
            )
        else:
            severity = Severity.MEDIUM
            cvss = 5.3
            description = (
                f"L'introspection GraphQL est activee sur {successful_endpoint}. "
                f"Le schema expose {total_types} types et {total_fields} champs (lecture seule). "
                f"Types sensibles detectes: {', '.join(found_sensitive) if found_sensitive else 'aucun'}. "
                f"Aucune mutation dangereuse detectee, mais la structure de l'API est entierement exposee."
            )

        result.add_finding(Finding(
            id="ENUM-GRAPHQL-001",
            title=f"Introspection GraphQL activee sur {ctx.target.domain} ({successful_endpoint})",
            severity=severity,
            cvss_score=cvss,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if not has_mutations
                       else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.MISCONFIGURATION,
            description=description,
            evidence=Evidence(
                request=f"POST {base}{successful_endpoint}\nContent-Type: application/json\n\n{INTROSPECTION_QUERY}",
                response_status=200,
                response_body_excerpt=json.dumps(schema_summary, indent=2)[:500],
            ),
            impact=(
                "Exposition complete de la structure de l'API GraphQL. "
                "Permet a un attaquant de decouvrir tous les types, champs et mutations disponibles, "
                "facilitant l'exploitation de failles IDOR, l'enumeration d'utilisateurs et l'acces "
                "a des donnees sensibles."
            ),
            remediation=(
                "Desactiver l'introspection GraphQL en production. "
                "Ajouter dans wp-config.php: add_filter('graphql_introspection_enabled', '__return_false'); "
                "Ou configurer le plugin WPGraphQL pour desactiver l'introspection."
            ),
            compliance=Compliance(
                owasp_2021="A01:2021 - Broken Access Control",
                cwe="CWE-200",
                mitre_attack="T1530 - Data from Cloud Storage",
            ),
            references=[
                "https://graphql.org/learn/introspection/",
                "https://www.wpgraphql.com/docs/security",
                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
            ],
            phase="enum",
            module=self.name,
            tags=["graphql", "introspection", "api", "enumeration"],
        ))

        return result
