#!/usr/bin/env python3
"""WordPress BAZOOKA — Automated WordPress penetration testing framework.

Usage:
    bazooka scan https://target.com
    bazooka scan https://target.com --profile quick
    bazooka scan https://target.com --pentest --scope-file scope.yaml
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

# Force UTF-8 stdout/stderr on Windows so em-dashes, accents and box-drawing
# characters render correctly in cmd.exe (default CP-1252 mangles them).
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

import typer
from rich.console import Console
from rich.panel import Panel

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import ScanEngine
from report.generator import generate_reports

console = Console()
app = typer.Typer(
    name="bazooka",
    help="WordPress BAZOOKA — Automated WordPress pentest & security audit framework.",
    no_args_is_help=True,
    add_completion=False,
)

BANNER = r"""
[bold magenta]
██████╗  █████╗ ███████╗ ██████╗  ██████╗ ██╗  ██╗ █████╗
██╔══██╗██╔══██╗╚══███╔╝██╔═══██╗██╔═══██╗██║ ██╔╝██╔══██╗
██████╔╝███████║  ███╔╝ ██║   ██║██║   ██║█████╔╝ ███████║
██╔══██╗██╔══██║ ███╔╝  ██║   ██║██║   ██║██╔═██╗ ██╔══██║
██████╔╝██║  ██║███████╗╚██████╔╝╚██████╔╝██║  ██╗██║  ██║
╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
[/bold magenta]      [dim]WordPress Penetration Testing Framework - v1.0.0[/dim]
"""


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target WordPress URL (https://target.com)"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile: quick, standard, aggressive, bugbounty"),
    pentest: bool = typer.Option(False, "--pentest", help="Enable exploitation modules (requires --scope-file)"),
    infra: bool = typer.Option(False, "--infra", help="Enable infrastructure scanning (/24)"),
    scope_file: Optional[str] = typer.Option(None, "--scope-file", help="Scope YAML file (required for --pentest)"),
    rate_limit: float = typer.Option(10.0, "--rate-limit", "-r", help="Max requests per second"),
    timeout: float = typer.Option(10.0, "--timeout", help="HTTP timeout in seconds"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/SOCKS5 proxy URL"),
    origin: Optional[str] = typer.Option(None, "--origin", help="Origin IP for CDN bypass"),
    output: str = typer.Option("./loot", "--output", "-o", help="Output directory"),
    threads: int = typer.Option(10, "--threads", "-t", help="Number of concurrent threads"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show tests without executing"),
    verbose: int = typer.Option(1, "--verbose", "-v", help="Verbosity level (1-3)"),
) -> None:
    """Scan a WordPress target for vulnerabilities."""
    console.print(BANNER)

    # Validate inputs
    url = url.strip().rstrip("/.")
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    if pentest and not scope_file:
        console.print("[bold red]ERROR:[/bold red] --pentest requires --scope-file. "
                      "Provide an authorization scope file.")
        raise typer.Exit(1)

    if dry_run:
        console.print(Panel(
            f"[bold]DRY RUN[/bold] — No requests will be sent.\n"
            f"Target: {url}\n"
            f"Profile: {profile}\n"
            f"Pentest: {pentest}\n"
            f"Infra: {infra}\n"
            f"Rate limit: {rate_limit} req/s\n"
            f"Threads: {threads}",
            title="Scan Configuration",
            border_style="yellow",
        ))
        raise typer.Exit(0)

    # Run the scan
    engine = ScanEngine(
        url=url,
        profile=profile,
        pentest=pentest,
        infra=infra,
        rate_limit=rate_limit,
        timeout=timeout,
        proxy=proxy,
        origin=origin,
        threads=threads,
    )

    ctx = asyncio.run(engine.run())

    # Generate reports
    console.print("\n [bold]\\[REPORT][/bold] Generating reports...")
    generated = generate_reports(ctx, output_dir=output)

    console.print(Panel(
        f"[bold green]Scan complete![/bold green]\n"
        f"Findings: {len(ctx.findings)} | Max CVSS: {ctx.max_cvss}\n"
        f"Reports: {len(generated)} files generated in {output}/{ctx.target.domain}/",
        border_style="green",
    ))


@app.command()
def doctor() -> None:
    """Check prerequisites and dependencies."""
    console.print(BANNER)
    console.print(" [bold]Checking prerequisites...[/bold]\n")

    checks = []

    # Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    ok = sys.version_info >= (3, 11)
    checks.append(("Python >= 3.11", py_ver, ok))

    # Required packages
    for pkg in ["httpx", "dns.resolver", "typer", "rich", "pydantic", "bs4", "yaml", "jinja2"]:
        try:
            __import__(pkg)
            checks.append((pkg, "installed", True))
        except ImportError:
            checks.append((pkg, "MISSING", False))

    # Optional packages
    for pkg, name in [("nmap", "python-nmap"), ("playwright", "playwright"), ("graphviz", "graphviz")]:
        try:
            __import__(pkg)
            checks.append((f"{name} (optional)", "installed", True))
        except ImportError:
            checks.append((f"{name} (optional)", "not installed", None))

    # Print results
    for label, status, ok in checks:
        if ok is True:
            console.print(f"  [green]OK[/green]   {label}: {status}")
        elif ok is False:
            console.print(f"  [red]FAIL[/red] {label}: {status}")
        else:
            console.print(f"  [yellow]SKIP[/yellow] {label}: {status}")

    all_ok = all(ok for _, _, ok in checks if ok is not None)
    console.print()
    if all_ok:
        console.print("  [bold green]All prerequisites met![/bold green]")
    else:
        console.print("  [bold red]Some prerequisites are missing. Run: pip install -e .[/bold red]")


@app.command(name="update-db")
def update_db() -> None:
    """Update the CVE database from online sources."""
    console.print(BANNER)
    console.print(" [bold]Updating CVE database...[/bold]")
    console.print("  [yellow]Not yet implemented in v0.1 - using embedded signatures.[/yellow]")


@app.command()
def gui(
    port: int = typer.Option(8666, "--port", "-p", help="Port to bind the web UI"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Don't open browser"),
) -> None:
    """Launch the real-time web GUI."""
    import webbrowser
    import uvicorn

    console.print(BANNER)
    console.print(Panel.fit(
        f"  WordPress BAZOOKA - Web GUI\n  http://{host}:{port}\n  Ctrl+C to stop",
        border_style="magenta",
    ))
    if not no_browser:
        try:
            webbrowser.open(f"http://{host}:{port}")
        except Exception:
            pass
    uvicorn.run("gui.app:app", host=host, port=port, reload=False, log_level="warning")


if __name__ == "__main__":
    app()
