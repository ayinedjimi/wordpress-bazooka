"""Optional wrapper around the `nuclei` binary for WordPress-tagged templates."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Map nuclei severity strings to BAZOOKA Severity
SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

NUCLEI_TIMEOUT = 300  # 5 minutes
MAX_FINDINGS = 200    # safety cap on emitted findings


def _run_nuclei_blocking(target: str) -> tuple[int, str, str]:
    """Synchronous helper executed in a thread — runs nuclei and returns (rc, stdout, stderr)."""
    cmd = [
        "nuclei",
        "-u", target,
        "-tags", "wordpress,wp",
        "-severity", "critical,high,medium",
        "-silent",
        "-rate-limit", "10",
        "-timeout", "10",
        "-j",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT,
            shell=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", "nuclei timeout"
    except (OSError, FileNotFoundError) as exc:
        return 127, "", str(exc)


class NucleiWrapperModule(BazookaModule):
    name = "vuln.nuclei_wrapper"
    phase = "vuln"
    description = "Optional wrapper around the nuclei scanner (wordpress templates)"
    profiles = ["aggressive", "bugbounty"]
    intrusive = True

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        target = ctx.target.url

        # 1) Detect binary
        if shutil.which("nuclei") is None:
            result.add_finding(Finding(
                id="VULN-NUCLEI-SKIP",
                title="Binaire nuclei introuvable — module ignore",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    "Le binaire 'nuclei' n'est pas present dans le PATH. "
                    "Installez-le (https://github.com/projectdiscovery/nuclei) "
                    "pour activer le scan de templates WordPress."
                ),
                remediation="Installer nuclei et le placer dans le PATH du systeme.",
                phase="vuln",
                module=self.name,
                tags=["nuclei", "skipped"],
            ))
            return result

        # 2) Run nuclei in a thread with a hard async timeout
        try:
            rc, stdout, stderr = await asyncio.wait_for(
                asyncio.to_thread(_run_nuclei_blocking, target),
                timeout=NUCLEI_TIMEOUT + 10,
            )
        except asyncio.TimeoutError:
            result.add_finding(Finding(
                id="VULN-NUCLEI-TIMEOUT",
                title="Timeout du scan nuclei",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Le scan nuclei a depasse {NUCLEI_TIMEOUT}s et a ete interrompu.",
                phase="vuln",
                module=self.name,
                tags=["nuclei", "timeout"],
            ))
            return result

        # 3) Parse JSONL output
        hits_emitted = 0
        finding_idx = 1
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(hit, dict):
                continue

            info = hit.get("info") or {}
            severity_str = str(info.get("severity", "info")).lower()
            severity = SEVERITY_MAP.get(severity_str, Severity.INFO)
            template_id = hit.get("template-id") or hit.get("templateID") or "unknown"
            name = info.get("name") or template_id
            matched_url = hit.get("matched-at") or hit.get("matched") or target
            description = info.get("description") or f"Match nuclei sur le template {template_id}."
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            classification = info.get("classification") or {}
            cve_id = ""
            if isinstance(classification, dict):
                cve_list = classification.get("cve-id") or []
                if isinstance(cve_list, list) and cve_list:
                    cve_id = str(cve_list[0])
                elif isinstance(cve_list, str):
                    cve_id = cve_list

            result.add_finding(Finding(
                id=f"VULN-NUCLEI-{finding_idx:03d}",
                title=f"nuclei[{severity_str}] {name}",
                severity=severity,
                confidence=Confidence.LIKELY,
                finding_type=FindingType.CVE if cve_id else FindingType.MISCONFIGURATION,
                description=description,
                evidence=Evidence(
                    request=f"nuclei -u {target} (template={template_id})",
                    response_status=0,
                    response_body_excerpt=(matched_url if isinstance(matched_url, str) else str(matched_url))[:500],
                ),
                impact=info.get("impact") or "Voir la description du template nuclei.",
                remediation=info.get("remediation") or "Voir la documentation du template / CVE associe.",
                compliance=Compliance(cwe=cve_id) if cve_id else Compliance(),
                references=[r for r in refs if isinstance(r, str)][:10],
                phase="vuln",
                module=self.name,
                tags=["nuclei", template_id, severity_str],
            ))
            finding_idx += 1
            hits_emitted += 1
            if hits_emitted >= MAX_FINDINGS:
                break

        if hits_emitted == 0:
            result.add_finding(Finding(
                id="VULN-NUCLEI-CLEAR",
                title="Aucun match nuclei (templates wordpress, severites critical/high/medium)",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"nuclei retour code={rc}. Aucune ligne JSON exploitable. "
                    f"stderr (extrait): {stderr[:200]}"
                ),
                phase="vuln",
                module=self.name,
                tags=["nuclei", "clear"],
            ))

        result.add_data("nuclei_hits", hits_emitted)
        result.add_data("nuclei_returncode", rc)
        return result

    def should_run(self, ctx) -> bool:
        return ctx.profile in ("aggressive", "bugbounty")
