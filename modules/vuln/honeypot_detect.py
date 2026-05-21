"""Honeypot detection — heuristic checks to identify WordPress honeypots."""

from __future__ import annotations

import math
import re
import time
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Plugin pairs that are unlikely to coexist in real deployments
_CONFLICTING_PLUGIN_PAIRS: list[tuple[str, str]] = [
    ("wordfence", "sucuri-scanner"),
    ("wordfence", "ithemes-security-pro"),
    ("all-in-one-wp-security-and-firewall", "wordfence"),
    ("sucuri-scanner", "ithemes-security-pro"),
    ("jetpack", "flavor"),  # Unlikely combo
    ("w3-total-cache", "wp-super-cache"),  # Both full-page caches
    ("wp-rocket", "w3-total-cache"),
    ("wp-rocket", "wp-super-cache"),
]


def _stddev(values: list[float]) -> float:
    """Calculate the standard deviation of a list of float values."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


class HoneypotDetectModule(BazookaModule):
    name = "vuln.honeypot_detect"
    phase = "vuln"
    description = "Honeypot detection via multiple heuristics"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        heuristic_scores: list[dict[str, object]] = []
        honeypot_suspected = False

        # ----------------------------------------------------------------
        # Heuristic 1: Suspiciously uniform response times
        # Send 5 requests and check if timing stddev is < 5ms
        # ----------------------------------------------------------------
        response_times: list[float] = []
        for i in range(5):
            try:
                t_start = time.time()
                await session.get(
                    f"{base}/?bz_honeypot_probe={i}",
                    use_cache=False,
                )
                elapsed = (time.time() - t_start) * 1000  # Convert to ms
                response_times.append(elapsed)
            except Exception:
                pass

        if len(response_times) >= 3:
            timing_stddev = _stddev(response_times)
            avg_time = sum(response_times) / len(response_times)
            timing_suspicious = timing_stddev < 5.0 and avg_time < 50.0  # Very uniform AND very fast

            heuristic_scores.append({
                "name": "Timing uniformity",
                "stddev_ms": round(timing_stddev, 2),
                "avg_ms": round(avg_time, 2),
                "suspicious": timing_suspicious,
                "detail": f"stddev={timing_stddev:.2f}ms, avg={avg_time:.2f}ms (threshold: stddev < 5ms)",
            })

            if timing_suspicious:
                honeypot_suspected = True

        # ----------------------------------------------------------------
        # Heuristic 2: Hidden form fields on login page (trap fields)
        # ----------------------------------------------------------------
        trap_fields_found: list[str] = []
        try:
            resp = await session.get(f"{base}/wp-login.php", use_cache=False)
            body = resp.text

            # Look for hidden fields that don't belong to standard WordPress login
            standard_hidden = {
                "redirect_to", "testcookie", "interim-login", "reauth",
                "action", "wp-submit", "log", "pwd", "_wpnonce",
            }

            # Find all hidden input fields
            hidden_inputs = re.findall(
                r'<input[^>]+type=["\']hidden["\'][^>]*>',
                body,
                re.IGNORECASE,
            )

            for field_html in hidden_inputs:
                name_match = re.search(r'name=["\']([^"\']+)["\']', field_html)
                if name_match:
                    field_name = name_match.group(1)
                    if field_name not in standard_hidden and not field_name.startswith("_wp"):
                        trap_fields_found.append(field_name)

            # Also look for CSS-hidden fields (display:none / visibility:hidden / position:absolute + left:-9999px)
            hidden_css_fields = re.findall(
                r'<(?:input|div|span)[^>]*style=["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|'
                r'position\s*:\s*absolute[^"\']*left\s*:\s*-\d+)[^"\']*["\'][^>]*>',
                body,
                re.IGNORECASE,
            )
            if hidden_css_fields:
                for field_html in hidden_css_fields:
                    name_match = re.search(r'name=["\']([^"\']+)["\']', field_html)
                    if name_match:
                        trap_fields_found.append(f"css-hidden:{name_match.group(1)}")

            trap_suspicious = len(trap_fields_found) > 0

            heuristic_scores.append({
                "name": "Login trap fields",
                "fields": trap_fields_found,
                "suspicious": trap_suspicious,
                "detail": f"Found {len(trap_fields_found)} suspicious hidden fields",
            })

            if trap_suspicious:
                honeypot_suspected = True

        except Exception:
            pass

        # ----------------------------------------------------------------
        # Heuristic 3: Impossible plugin coexistence
        # ----------------------------------------------------------------
        active_plugins: set[str] = set()
        for plugin in ctx.target.plugins:
            active_plugins.add(plugin.slug.lower())

        conflicting_pairs: list[tuple[str, str]] = []
        for plugin_a, plugin_b in _CONFLICTING_PLUGIN_PAIRS:
            if plugin_a in active_plugins and plugin_b in active_plugins:
                conflicting_pairs.append((plugin_a, plugin_b))

        plugin_suspicious = len(conflicting_pairs) > 0

        heuristic_scores.append({
            "name": "Conflicting plugins",
            "pairs": conflicting_pairs,
            "suspicious": plugin_suspicious,
            "detail": (
                f"Found {len(conflicting_pairs)} conflicting plugin pairs: "
                + ", ".join(f"{a}+{b}" for a, b in conflicting_pairs)
                if conflicting_pairs
                else "No conflicting plugins detected"
            ),
        })

        if plugin_suspicious:
            honeypot_suspected = True

        # ----------------------------------------------------------------
        # Store results
        # ----------------------------------------------------------------
        result.add_data("honeypot_suspected", honeypot_suspected)
        result.add_data("honeypot_heuristics", heuristic_scores)

        suspicious_count = sum(1 for h in heuristic_scores if h.get("suspicious"))

        if honeypot_suspected:
            detail_lines = []
            for h in heuristic_scores:
                status = "SUSPECT" if h.get("suspicious") else "OK"
                detail_lines.append(f"  [{status}] {h['name']}: {h['detail']}")

            result.add_finding(Finding(
                id="VULN-HONEYPOT-001",
                title=f"Honeypot suspecte ({suspicious_count}/{len(heuristic_scores)} heuristiques positives)",
                severity=Severity.INFO,
                cvss_score=0.0,
                confidence=Confidence.POSSIBLE,
                finding_type=FindingType.DESIGN_FLAW,
                description=(
                    f"Ce site presente {suspicious_count} indicateur(s) de honeypot:\n"
                    + "\n".join(detail_lines)
                    + "\n\nATTENTION: les resultats du scan peuvent etre manipules. "
                    "Les vulnerabilites trouvees peuvent etre des leurres."
                ),
                evidence=Evidence(
                    request=f"Multiple probes against {base}",
                    response_body_excerpt="\n".join(detail_lines),
                ),
                impact=(
                    "Si le site est un honeypot, les resultats du scan ne sont pas fiables. "
                    "Les 'vulnerabilites' detectees sont des leurres destines a pieger les attaquants. "
                    "Les IP et requetes de l'attaquant sont probablement loguees."
                ),
                remediation=(
                    "Verifier manuellement si le site est un vrai WordPress ou un honeypot. "
                    "Croiser avec des sources OSINT (Shodan, Censys) pour valider l'hebergement."
                ),
                compliance=Compliance(
                    mitre_attack="T1583.003 - Acquire Infrastructure: Virtual Private Server",
                ),
                references=[
                    "https://github.com/mushorg/snare",
                    "https://github.com/magisterquis/wphoneypot",
                ],
                phase="vuln",
                module=self.name,
                tags=["honeypot", "detection", "warning", "opsec"],
            ))
        else:
            # No honeypot indicators — informational note
            result.add_finding(Finding(
                id="VULN-HONEYPOT-CLEAR",
                title="Aucun indicateur de honeypot detecte",
                severity=Severity.INFO,
                cvss_score=0.0,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.DESIGN_FLAW,
                description=(
                    f"0/{len(heuristic_scores)} heuristiques de detection de honeypot positives. "
                    "Le site ne presente aucun signe d'etre un honeypot."
                ),
                phase="vuln",
                module=self.name,
                tags=["honeypot", "detection"],
            ))

        return result
