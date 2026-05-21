"""Report generator — produces HTML, JSON, and terminal output."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, BaseLoader, select_autoescape
from rich.console import Console

from report.html_template import HTML_TEMPLATE

if TYPE_CHECKING:
    from core.engine import ScanContext

import sys as _sys
console = Console(legacy_windows=False, force_terminal=_sys.stdout.isatty() if hasattr(_sys.stdout, "isatty") else False)


def _score_class(cvss: float) -> str:
    if cvss >= 9.0:
        return "score-critical"
    if cvss >= 7.0:
        return "score-high"
    if cvss >= 4.0:
        return "score-medium"
    if cvss >= 0.1:
        return "score-low"
    return "score-good"


def _build_remediation_plan(findings: list) -> list[dict]:
    """Group findings by remediation action, sorted by severity."""
    remed_map: dict[str, dict] = {}
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    for f in findings:
        key = f.remediation or "Aucune remediation specifiee"
        if key not in remed_map:
            remed_map[key] = {
                "action": key,
                "severity": f.severity.value,
                "severity_rank": severity_order.get(f.severity.value, 5),
                "finding_ids": [],
            }
        remed_map[key]["finding_ids"].append(f.id)
        # Keep worst severity
        if severity_order.get(f.severity.value, 5) < remed_map[key]["severity_rank"]:
            remed_map[key]["severity"] = f.severity.value
            remed_map[key]["severity_rank"] = severity_order.get(f.severity.value, 5)

    plan = sorted(remed_map.values(), key=lambda x: x["severity_rank"])
    for item in plan:
        item["finding_ids"] = ", ".join(item["finding_ids"])
        del item["severity_rank"]
    return plan


def generate_html_report(ctx: ScanContext, output_dir: Path) -> Path:
    """Generate the HTML report file (PingCastle-style)."""
    findings = sorted(ctx.findings, key=lambda f: f.cvss_score, reverse=True)
    meta = ctx.target.meta
    counts = ctx.severity_counts

    duration = ""
    if meta.end_time and meta.start_time:
        delta = meta.end_time - meta.start_time
        duration = f"{delta.total_seconds():.0f}s"

    # Prepare template data
    template_data = {
        "target_url": ctx.target.url,
        "target_domain": ctx.target.domain,
        "scan_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "profile": ctx.profile,
        "authorization_ref": meta.authorization_ref or "",
        "duration": duration,
        "total_requests": meta.total_requests,
        "bazooka_version": meta.bazooka_version,
        "max_cvss": f"{ctx.max_cvss:.1f}",
        "score_class": _score_class(ctx.max_cvss),
        "counts": counts,
        "total_findings": len(findings),
        "wp_version": ctx.target.wp_version or "",
        "waf": ctx.target.waf_detected or "",
        "origin_ip": ctx.target.origin_ip or "",
        "user_count": len(ctx.target.users),
        "plugin_count": len(ctx.target.plugins),
        "findings": findings,
        "users_data": [u.model_dump() for u in ctx.target.users],
        "plugins_data": [p.model_dump() for p in ctx.target.plugins],
        "dns_records": json.dumps(ctx.data.get("dns_records", {}), indent=2, default=str),
        "remediation_plan": _build_remediation_plan(findings),
    }

    # Autoescape: any value rendered with {{ }} in the template is HTML-escaped.
    # Pre-rendered HTML blocks (banner, score blocks built by this module) are
    # marked with `| safe` in the template so they remain raw. Target-controlled
    # data (titles, descriptions, slugs, etc.) cannot inject XSS into the report.
    env = Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(enabled_extensions=("html", "xml"), default_for_string=True),
    )
    template = env.from_string(HTML_TEMPLATE)
    html_content = template.render(**template_data)

    output_file = output_dir / f"RAPPORT_BAZOOKA_{ctx.target.domain}.html"
    output_file.write_text(html_content, encoding="utf-8")
    return output_file


def generate_json_report(ctx: ScanContext, output_dir: Path) -> Path:
    """Generate the JSON findings file."""
    findings_data = [f.model_dump(mode="json") for f in ctx.findings]
    meta_data = ctx.target.meta.model_dump(mode="json")

    report = {
        "meta": meta_data,
        "target": {
            "url": ctx.target.url,
            "domain": ctx.target.domain,
            "ip": ctx.target.ip,
            "origin_ip": ctx.target.origin_ip,
            "wp_version": ctx.target.wp_version,
            "waf": ctx.target.waf_detected,
            "users": [u.model_dump() for u in ctx.target.users],
            "plugins": [p.model_dump() for p in ctx.target.plugins],
        },
        "findings": findings_data,
        "severity_counts": ctx.severity_counts,
        "max_cvss": ctx.max_cvss,
    }

    output_file = output_dir / "findings.json"
    output_file.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return output_file


def generate_reports(ctx: ScanContext, output_dir: str = "./loot") -> list[Path]:
    """Generate all report formats."""
    out = Path(output_dir) / ctx.target.domain
    out.mkdir(parents=True, exist_ok=True)

    generated = []

    # JSON
    json_path = generate_json_report(ctx, out)
    generated.append(json_path)
    console.print(f"   [green]JSON[/green]  {json_path}")

    # HTML
    html_path = generate_html_report(ctx, out)
    generated.append(html_path)
    console.print(f"   [green]HTML[/green]  {html_path}")

    # DOCX
    try:
        from report.docx_exporter import generate_docx_report
        docx_path = generate_docx_report(ctx, out)
        generated.append(docx_path)
        console.print(f"   [green]DOCX[/green]  {docx_path}")
    except Exception as e:
        console.print(f"   [yellow]DOCX[/yellow]  skipped ({e})")

    return generated
