"""Placeholder — security headers check is handled by recon.headers_analysis.
This module is kept for phase consistency (vuln findings generated from recon data)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class SecurityHeadersModule(BazookaModule):
    name = "vuln.security_headers"
    phase = "vuln"
    description = "Security headers (delegated to recon.headers_analysis)"
    profiles: list[str] = []  # Disabled — handled by recon module

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        return ModuleResult()
