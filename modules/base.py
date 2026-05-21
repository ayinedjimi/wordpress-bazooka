"""Base module class — all BAZOOKA modules inherit from this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from core.models import Finding

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class ModuleResult:
    """Result returned by a module after execution."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.data: dict = {}
        self.status: str = "success"  # success | partial | failed | skipped

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_data(self, key: str, value: object) -> None:
        self.data[key] = value


class BazookaModule(ABC):
    """Abstract base class for all scan modules."""

    name: str = ""
    phase: str = ""  # recon | enum | vuln | exploit | infra
    description: str = ""
    profiles: list[str] = ["standard", "aggressive"]
    intrusive: bool = False
    dependencies: list[str] = []

    @abstractmethod
    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        """Execute the module and return findings."""
        ...

    def should_run(self, ctx: ScanContext) -> bool:
        """Override for dynamic prioritization based on context."""
        return True
