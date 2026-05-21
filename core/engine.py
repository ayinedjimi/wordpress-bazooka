"""Main scan engine — orchestrates module execution across all phases."""

from __future__ import annotations

import asyncio
import importlib
import pkgutil
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from core.models import Finding, ScanMeta, Severity, Target
from core.session import BazookaSession
from modules.base import BazookaModule, ModuleResult

import sys as _sys
console = Console(legacy_windows=False, force_terminal=_sys.stdout.isatty() if hasattr(_sys.stdout, "isatty") else False)

PHASE_ORDER = ["recon", "enum", "vuln", "exploit", "infra"]
SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


class ScanContext:
    """Shared context accumulating results across all modules."""

    def __init__(self, target: Target) -> None:
        self.target = target
        self.findings: list[Finding] = []
        self.data: dict = {}
        self.profile: str = "standard"
        self.pentest: bool = False
        self.infra: bool = False
        # Per-module live sub-action shown in the GUI activity bar
        # (e.g. "Fetching CVE for litespeed-cache")
        self._actions: dict[str, str] = {}

    def set_current_action(self, module: str, action: str) -> None:
        """Modules can call this to surface what they are doing right now."""
        if action:
            self._actions[module] = action
        else:
            self._actions.pop(module, None)

    def get_current_actions(self) -> dict[str, str]:
        return dict(self._actions)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.target.findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add_finding(f)

    def set_data(self, key: str, value: object) -> None:
        self.data[key] = value

    def get_data(self, key: str, default: object = None) -> object:
        return self.data.get(key, default)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def max_cvss(self) -> float:
        if not self.findings:
            return 0.0
        return max(f.cvss_score for f in self.findings)


class ScanEngine:
    """Orchestrates the full scan pipeline."""

    def __init__(
        self,
        url: str,
        profile: str = "standard",
        pentest: bool = False,
        infra: bool = False,
        rate_limit: float = 10.0,
        timeout: float = 10.0,
        proxy: Optional[str] = None,
        origin: Optional[str] = None,
        threads: int = 10,
    ) -> None:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        # Extract root domain (strip www. prefix for DNS lookups)
        root_domain = hostname
        if root_domain.startswith("www."):
            root_domain = root_domain[4:]
        self.target = Target(
            url=url.rstrip("/"),
            domain=root_domain,
            ip=None,
            origin_ip=origin,
            meta=ScanMeta(target=url, profile=profile),
        )
        self.profile = profile
        self.pentest = pentest
        self.infra = infra
        self.threads = threads
        self.session = BazookaSession(
            rate_limit=rate_limit,
            timeout=timeout,
            proxy=proxy,
        )
        self.ctx = ScanContext(self.target)
        self.ctx.profile = profile
        self.ctx.pentest = pentest
        self.ctx.infra = infra
        self._modules: dict[str, list[BazookaModule]] = {p: [] for p in PHASE_ORDER}

    def discover_modules(self) -> None:
        """Auto-discover all modules in the modules/ directory.

        Works both from a normal source checkout and from a PyInstaller bundle
        (where modules live inside the frozen archive, not a real filesystem dir).
        """
        for phase in PHASE_ORDER:
            phase_pkg_name = f"modules.{phase}"
            try:
                phase_pkg = importlib.import_module(phase_pkg_name)
            except Exception:
                continue
            search_path = getattr(phase_pkg, "__path__", None)
            if not search_path:
                continue
            for importer, modname, ispkg in pkgutil.iter_modules(search_path):
                if modname.startswith("_"):
                    continue
                full_module = f"{phase_pkg_name}.{modname}"
                try:
                    mod = importlib.import_module(full_module)
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, BazookaModule)
                            and attr is not BazookaModule
                            and attr.name
                        ):
                            instance = attr()
                            if self.profile in instance.profiles or "all" in instance.profiles:
                                if not instance.intrusive or self.pentest:
                                    self._modules[phase].append(instance)
                except Exception as e:
                    console.print(f"  [dim]Skip {full_module}: {e}[/dim]")

    async def _run_phase(self, phase: str) -> None:
        """Run all modules for a given phase."""
        modules = self._modules.get(phase, [])
        if not modules:
            return

        # Sort by dependencies
        modules.sort(key=lambda m: len(m.dependencies))

        phase_label = phase.upper()
        console.print(f"\n [bold cyan]\\[{phase_label}][/bold cyan] Running {len(modules)} checks...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            disable=not console.is_terminal,
        ) as progress:
            task = progress.add_task(f"[cyan]{phase_label}", total=len(modules))

            sem = asyncio.Semaphore(self.threads)

            async def run_module(mod: BazookaModule) -> Optional[ModuleResult]:
                async with sem:
                    if not mod.should_run(self.ctx):
                        progress.advance(task)
                        self.target.meta.modules_skipped += 1
                        return None
                    try:
                        result = await mod.run(self.ctx, self.session)
                        self.target.meta.modules_executed += 1
                        if result.findings:
                            self.ctx.add_findings(result.findings)
                        for k, v in result.data.items():
                            self.ctx.set_data(k, v)
                        progress.advance(task)
                        return result
                    except Exception as e:
                        console.print(f"    [red]ERROR[/red] {mod.name}: {e}")
                        self.target.meta.modules_failed += 1
                        progress.advance(task)
                        return None

            await asyncio.gather(*(run_module(m) for m in modules))

        # Print phase summary
        phase_findings = [f for f in self.ctx.findings if f.phase == phase]
        if phase_findings:
            for f in sorted(phase_findings, key=lambda x: x.cvss_score, reverse=True)[:10]:
                color = SEVERITY_COLORS.get(f.severity, "white")
                conf = f"[{f.confidence.value}]"
                console.print(f"    [{color}]{f.severity.value:8s}[/{color}] {conf:12s} {f.title}")

    async def run(self) -> ScanContext:
        """Execute the full scan pipeline."""
        self.target.meta.start_time = datetime.utcnow()
        start = time.time()

        console.print()
        console.print(" [bold magenta]WORDPRESS BAZOOKA[/bold magenta] v0.1.0")
        console.print(f" Target: [bold]{self.target.url}[/bold]")
        console.print(f" Profile: {self.profile} | Threads: {self.threads} | Rate: {self.session.rate_limit} req/s")
        console.print()

        self.discover_modules()

        # Phase 0: WAF detection & calibration (before any module runs)
        console.print(" [bold cyan]\\[BOOTSTRAP][/bold cyan] WAF detection & calibration...")
        waf_profile = await self.session.detect_waf(self.target.url)
        if waf_profile.detected:
            self.target.waf_detected = waf_profile.name
            self.ctx.set_data("waf_profile", waf_profile.to_dict())
            console.print(f"   WAF: [bold yellow]{waf_profile.name}[/bold yellow] "
                          f"(blocks_dotfiles={waf_profile.blocks_dotfiles}, "
                          f"generic_403={waf_profile.generic_403_size})")
            if self.session.rate_limit < self.session._original_rate_limit:
                console.print(f"   Rate limit adapted: {self.session.rate_limit} req/s")
        else:
            console.print("   WAF: [green]None detected[/green]")
        console.print(f"   Baseline 404 sizes: {self.session.waf.baseline_404_sizes or 'N/A'}")
        console.print(f"   Baseline 403 sizes: {self.session.waf.baseline_403_sizes or 'N/A'}")

        for phase in PHASE_ORDER:
            if phase == "exploit" and not self.pentest:
                continue
            if phase == "infra" and not self.infra:
                continue
            await self._run_phase(phase)

        self.target.meta.end_time = datetime.utcnow()
        self.target.meta.total_requests = self.session.request_count
        elapsed = time.time() - start

        # Print final summary
        console.print()
        counts = self.ctx.severity_counts
        score_line = " | ".join(
            f"[{SEVERITY_COLORS[Severity(k)]}]{k}: {v}[/{SEVERITY_COLORS[Severity(k)]}]"
            for k, v in counts.items()
            if v > 0
        )
        console.print(f" [bold]\\[SCORE][/bold] Max CVSS: {self.ctx.max_cvss}/10")
        console.print(f"   {score_line}")
        console.print(f"\n Completed in {elapsed:.1f}s | {self.session.request_count} requests sent")
        console.print()

        await self.session.close()
        return self.ctx
