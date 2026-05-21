"""WordPress BAZOOKA — Web GUI (FastAPI + WebSocket for real-time scan)."""

from __future__ import annotations

import asyncio
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Add project root to path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.engine import ScanEngine, ScanContext
from core.models import Severity
from report.generator import generate_reports

app = FastAPI(title="WordPress BAZOOKA", version="1.0.0")

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# Loot must be written to the directory the user launched bazooka.exe from,
# NOT inside the PyInstaller _MEI temp extraction dir.
# When frozen, Path(__file__).parent is _MEIxxx; we use the CWD instead.
import os as _os
_FROZEN = getattr(sys, "frozen", False)
LOOT_DIR = (Path(_os.getcwd()) if _FROZEN else ROOT) / "loot"
LOOT_DIR.mkdir(parents=True, exist_ok=True)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# In-memory scan state — bounded: only keep the N most recent completed scans
scans: dict[str, dict] = {}
MAX_COMPLETED_SCANS = 20


def _purge_old_scans() -> None:
    """Keep at most MAX_COMPLETED_SCANS finished scans in memory."""
    completed = [(sid, s) for sid, s in scans.items()
                 if s.get("status") in ("complete", "error")]
    if len(completed) > MAX_COMPLETED_SCANS:
        completed.sort(key=lambda kv: kv[1].get("started", ""))
        for sid, _ in completed[: len(completed) - MAX_COMPLETED_SCANS]:
            scans.pop(sid, None)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard — scan form + history."""
    # Load scan history from loot directory (limit to 20 most recent, sorted by mtime)
    history = []
    if LOOT_DIR.exists():
        domain_dirs = [d for d in LOOT_DIR.iterdir() if d.is_dir()]
        domain_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
        for domain_dir in domain_dirs[:20]:
            findings_file = domain_dir / "findings.json"
            if findings_file.exists():
                try:
                    data = json.loads(findings_file.read_text(encoding="utf-8"))
                    meta = data.get("meta", {})
                    history.append({
                        "domain": domain_dir.name,
                        "date": meta.get("start_time", ""),
                        "findings": len(data.get("findings", [])),
                        "max_cvss": data.get("max_cvss", 0),
                        "counts": data.get("severity_counts", {}),
                        "requests": meta.get("total_requests", 0),
                        "profile": meta.get("profile", ""),
                    })
                except Exception:
                    pass

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "history": history,
        "active_scans": {k: v for k, v in scans.items() if v.get("status") == "running"},
    })


@app.post("/scan/start")
async def start_scan(request: Request):
    """Start a new scan — returns scan ID, scan runs in background."""
    form = await request.form()
    url = str(form.get("url", "")).strip()
    profile = str(form.get("profile", "standard"))
    rate_limit = float(form.get("rate_limit", 10))
    threads = int(form.get("threads", 10))
    use_tor = bool(form.get("use_tor"))

    if not url:
        return RedirectResponse("/", status_code=303)
    # Clean URL: strip trailing dots, spaces, slashes
    url = url.strip().rstrip("/.")
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {
        "id": scan_id,
        "url": url,
        "profile": profile,
        "status": "running",
        "progress": 0,
        "phase": "starting",
        "findings_count": 0,
        "logs": [],
        # Absolute count of lines that were ever dropped from the head of `logs`
        # (because of the live-log truncation in _run_scan). The WS handler uses
        # this to translate its absolute `last_log_idx` into a valid slice index
        # — without it, truncation makes new_logs always return [] until restart.
        "logs_offset": 0,
        "started": datetime.utcnow().isoformat(),
        "ctx": None,
    }

    # Launch scan in background. Store the Task ref so the GC cannot collect
    # it mid-execution (CPython will silently cancel orphan tasks).
    task = asyncio.create_task(
        _run_scan(scan_id, url, profile, rate_limit, threads, use_tor)
    )
    scans[scan_id]["_task"] = task

    return RedirectResponse(f"/scan/{scan_id}", status_code=303)


async def _run_scan(scan_id: str, url: str, profile: str, rate_limit: float,
                    threads: int, use_tor: bool = False):
    """Background scan task — mirrors console output to live log."""
    scan = scans[scan_id]
    log = scan["logs"]
    # Cap live-log size to avoid unbounded growth on long scans (GUI history)
    MAX_LOG_LINES = 5000
    # Track the engine so we can close its httpx session in `finally` even when
    # an exception aborts the scan mid-flight (otherwise the AsyncClient + its
    # whole connection pool leaks on every failed scan).
    engine: Optional["ScanEngine"] = None

    def L(msg: str):
        log.append(f"[{_ts()}] {msg}")
        if len(log) > MAX_LOG_LINES:
            drop = len(log) - MAX_LOG_LINES
            del log[:drop]
            # Bump the offset so the WS handler still computes a correct slice
            # after truncation; otherwise live streaming silently dies.
            scan["logs_offset"] += drop

    try:
        # Banner
        L("WORDPRESS BAZOOKA v1.0.0")
        L(f"Target: {url}")
        L(f"Profile: {profile} | Threads: {threads} | Rate: {rate_limit} req/s")
        L("")

        scan["phase"] = "initializing"

        # Optional: route through embedded Tor (for IP-banned targets)
        tor_proc = None
        proxy_url: Optional[str] = None
        if use_tor:
            L("[TOR] Demarrage de Tor embarque (SOCKS5 local)...")
            scan["phase"] = "tor-bootstrap"
            try:
                from core.tor_proxy import TorProcess
                tor_proc = TorProcess()
                # Run blocking start() in a thread so the event loop stays free.
                await asyncio.to_thread(tor_proc.start, 90)
                proxy_url = tor_proc.proxy_url
                L(f"[TOR] OK — proxy {proxy_url} (control: {tor_proc.control_port})")
                scan["_tor"] = tor_proc
            except Exception as e:
                L(f"[TOR] Echec demarrage Tor: {e}")
                tor_proc = None

        engine = ScanEngine(
            url=url,
            profile=profile,
            rate_limit=rate_limit,
            threads=threads,
            proxy=proxy_url,
        )
        engine.discover_modules()
        # Allow the WebSocket loop to pull live sub-actions from the running engine.
        scan["_engine"] = engine

        # Count modules per phase
        active_phases = []
        for phase in ["recon", "enum", "vuln", "exploit", "infra"]:
            mods = engine._modules.get(phase, [])
            if mods:
                active_phases.append(phase)

        total_phases = len(active_phases)

        # Bootstrap WAF detection — tolerant to network errors
        scan["phase"] = "bootstrap"
        L("[BOOTSTRAP] WAF detection & calibration...")
        try:
            waf_profile = await asyncio.wait_for(
                engine.session.detect_waf(engine.target.url), timeout=20
            )
            if waf_profile.detected:
                engine.target.waf_detected = waf_profile.name
                engine.ctx.set_data("waf_profile", waf_profile.to_dict())
                L(f"  WAF: {waf_profile.name} (blocks_dotfiles={waf_profile.blocks_dotfiles})")
                if engine.session.rate_limit < engine.session._original_rate_limit:
                    L(f"  Rate limit adapted: {engine.session.rate_limit} req/s")
            else:
                L("  WAF: None detected")
            baseline_404 = engine.session.waf.baseline_404_sizes
            baseline_403 = engine.session.waf.baseline_403_sizes
            L(f"  Baseline 404 sizes: {baseline_404 or 'N/A'}")
            L(f"  Baseline 403 sizes: {baseline_403 or 'N/A'}")
        except asyncio.TimeoutError:
            L("  WAF detection: TIMEOUT (>20s) — la cible repond tres lentement, scan continue")
        except Exception as e:
            L(f"  WAF detection: ECHEC ({type(e).__name__}: {e}) — scan continue sans baseline")
        L("")

        # Verify target is reachable before running modules
        try:
            probe = await asyncio.wait_for(
                engine.session.get(engine.target.url), timeout=15
            )
            L(f"  Cible joignable: HTTP {probe.status_code}")
        except Exception as e:
            L(f"  ERREUR: cible injoignable ({type(e).__name__}: {e})")
            L("  Verifiez l'URL, votre connexion, ou si la cible bloque votre IP.")
            scan["status"] = "error"
            return
        L("")

        # Run each phase
        for phase_idx, phase in enumerate(active_phases):
            mods = engine._modules.get(phase, [])
            if not mods:
                continue

            scan["phase"] = phase
            phase_label = phase.upper()
            L(f"[{phase_label}] Running {len(mods)} checks...")

            # Run the phase manually to log each module (replaces engine._run_phase)
            findings_before = len(engine.ctx.findings)
            mods_sorted = sorted(mods, key=lambda m: len(m.dependencies))
            sem = asyncio.Semaphore(engine.threads)

            # Per-module safety timeout (seconds). Heavy modules (cve_matcher
            # with N API calls, source_maps, wordlist) need more headroom.
            MODULE_TIMEOUT = 180
            HEAVY_TIMEOUT = 300

            async def _run_one(mod):
                async with sem:
                    if not mod.should_run(engine.ctx):
                        L(f"  - {mod.name}: skipped")
                        engine.target.meta.modules_skipped += 1
                        return
                    L(f"  > {mod.name}...")
                    t0 = asyncio.get_event_loop().time()
                    timeout = HEAVY_TIMEOUT if mod.name in (
                        "vuln.cve_matcher", "enum.wp_plugins",
                        "enum.source_maps", "recon.ct_logs", "recon.wayback_machine",
                    ) else MODULE_TIMEOUT
                    try:
                        result = await asyncio.wait_for(
                            mod.run(engine.ctx, engine.session), timeout=timeout
                        )
                        dt = asyncio.get_event_loop().time() - t0
                        engine.target.meta.modules_executed += 1
                        if result.findings:
                            engine.ctx.add_findings(result.findings)
                        for k, v in result.data.items():
                            engine.ctx.set_data(k, v)
                        L(f"  < {mod.name} ok ({len(result.findings)} findings, {dt:.1f}s)")
                    except asyncio.TimeoutError:
                        dt = asyncio.get_event_loop().time() - t0
                        engine.target.meta.modules_failed += 1
                        engine.ctx.set_current_action(mod.name, "")
                        L(f"  ! {mod.name} TIMEOUT after {dt:.1f}s (cap: {timeout}s)")
                        return
                    except Exception as e:
                        dt = asyncio.get_event_loop().time() - t0
                        engine.target.meta.modules_failed += 1
                        L(f"  ! {mod.name} ERROR after {dt:.1f}s: {e}")

            await asyncio.gather(*(_run_one(m) for m in mods_sorted))
            findings_after = len(engine.ctx.findings)
            new_findings = engine.ctx.findings[findings_before:]

            scan["findings_count"] = findings_after
            scan["sub_actions"] = engine.ctx.get_current_actions()

            # Log each finding from this phase (sorted by CVSS)
            for f in sorted(new_findings, key=lambda x: x.cvss_score, reverse=True):
                sev = f.severity.value
                conf = f"[{f.confidence.value}]" if f.confidence.value != "confirmed" else ""
                L(f"  {sev:8s} {conf:12s} {f.title}")

            # Phase summary
            phase_counts = {}
            for f in new_findings:
                s = f.severity.value
                phase_counts[s] = phase_counts.get(s, 0) + 1
            if phase_counts:
                summary_parts = [f"{k}: {v}" for k, v in phase_counts.items()]
                L(f"  => {len(new_findings)} findings ({', '.join(summary_parts)})")

            # Extra context after enum phase
            if phase == "enum":
                wp_ver = engine.target.wp_version
                users = engine.target.users
                plugins = engine.target.plugins
                themes = engine.target.themes
                parts = []
                if wp_ver:
                    parts.append(f"WP {wp_ver}")
                if users:
                    parts.append(f"Users: {len(users)}")
                if plugins:
                    parts.append(f"Plugins: {len(plugins)}")
                if themes:
                    parts.append(f"Themes: {len(themes)}")
                if engine.target.waf_detected:
                    parts.append(f"WAF: {engine.target.waf_detected}")
                if parts:
                    L(f"  => {' | '.join(parts)}")

            L("")

            # Update progress
            scan["progress"] = int(((phase_idx + 1) / total_phases) * 90)

        # Score summary
        counts = engine.ctx.severity_counts
        max_cvss = engine.ctx.max_cvss
        score_parts = [f"{k}: {v}" for k, v in counts.items() if v > 0]
        L(f"[SCORE] Max CVSS: {max_cvss}/10")
        L(f"  {' | '.join(score_parts)}")
        L(f"  Requests: {engine.session.request_count}")
        L("")

        # Update meta before report generation
        engine.target.meta.total_requests = engine.session.request_count
        engine.target.meta.end_time = datetime.utcnow()

        # Generate reports
        scan["phase"] = "reporting"
        L("[REPORT] Generating reports...")
        generated = generate_reports(engine.ctx, output_dir=str(LOOT_DIR))
        for p in generated:
            L(f"  => {p.name}")

        # Keep only a lightweight summary, drop the heavy ctx/engine/session refs
        scan["summary"] = {
            "severity_counts": dict(engine.ctx.severity_counts),
            "max_cvss": engine.ctx.max_cvss,
            "domain": engine.ctx.target.domain,
            "findings_count": len(engine.ctx.findings),
            "requests": engine.session.request_count,
        }
        scan["progress"] = 100
        scan["status"] = "complete"
        _purge_old_scans()
        L("")
        L(f"Scan complete! {len(engine.ctx.findings)} findings | {engine.session.request_count} requests")

        # session.close() now happens in the `finally` block (covers exceptions too)
        engine.ctx = None
        engine._modules.clear()

    except Exception as e:
        scan["status"] = "error"
        L(f"ERROR: {e}")
        import traceback
        L(traceback.format_exc())
    finally:
        # Always close the engine's httpx session — even on exception — so the
        # AsyncClient and its connection pool don't leak per failed scan.
        if engine is not None:
            try:
                await engine.session.close()
            except Exception:
                pass
        tor_ref = scan.get("_tor")
        if tor_ref is not None:
            try:
                # TorProcess.stop() calls subprocess.wait(timeout=5) which would
                # block FastAPI's event loop. Off-load to a worker thread.
                await asyncio.to_thread(tor_ref.stop)
                scan.pop("_tor", None)
            except Exception:
                pass


def _ts() -> str:
    return datetime.utcnow().strftime("%H:%M:%S")


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: str):
    """Scan progress page."""
    scan = scans.get(scan_id)
    if not scan:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("scan.html", {"request": request, "scan": scan})


@app.websocket("/ws/scan/{scan_id}")
async def scan_ws(websocket: WebSocket, scan_id: str):
    """WebSocket for real-time scan progress."""
    await websocket.accept()
    scan = scans.get(scan_id)
    if not scan:
        await websocket.close()
        return

    # `total_seen` is the absolute count of log lines this WS has streamed
    # so far (across the whole scan life, including any that have been dropped
    # from `logs` by the live-log cap). We translate it to a local slice index
    # by subtracting the current `logs_offset`. This way the WS keeps streaming
    # even after the log buffer rolls over.
    total_seen = 0
    try:
        while True:
            offset = scan.get("logs_offset", 0)
            local_idx = max(0, total_seen - offset)
            new_logs = scan["logs"][local_idx:]
            total_seen = offset + len(scan["logs"])

            # Surface ctx.current_actions (e.g. CVE API calls in progress)
            engine_ref = scan.get("_engine")
            if engine_ref is not None and engine_ref.ctx is not None:
                sub_actions = engine_ref.ctx.get_current_actions()
            else:
                sub_actions = scan.get("sub_actions") or {}

            await websocket.send_json({
                "status": scan["status"],
                "phase": scan["phase"],
                "progress": scan["progress"],
                "findings_count": scan["findings_count"],
                "new_logs": new_logs,
                "sub_actions": sub_actions,
            })

            if scan["status"] in ("complete", "error"):
                await asyncio.sleep(0.5)
                summary = scan.get("summary") or {}
                final = {
                    "status": scan["status"],
                    "phase": scan["phase"],
                    "progress": 100,
                    "findings_count": scan["findings_count"],
                    "new_logs": scan["logs"][max(0, total_seen - scan.get("logs_offset", 0)):],
                    "done": True,
                    "severity_counts": summary.get("severity_counts", {}),
                    "max_cvss": summary.get("max_cvss", 0),
                    "domain": summary.get("domain", ""),
                }
                await websocket.send_json(final)
                await websocket.close()
                break

            await asyncio.sleep(0.8)

    except WebSocketDisconnect:
        pass


_BACK_BUTTON_HTML = """
<div id="bz-back-nav" style="position:fixed;top:14px;left:14px;z-index:99999;
 display:flex;gap:8px;font-family:'Segoe UI',system-ui,sans-serif;">
  <a href="/" style="background:#5851DB;color:#fff;text-decoration:none;
   padding:8px 16px;border-radius:20px;font-weight:600;font-size:14px;
   box-shadow:0 2px 8px rgba(0,0,0,0.2);">&larr; Dashboard</a>
  <button onclick="window.print()" style="background:#fff;color:#1A172A;
   border:1px solid #ddd;padding:8px 14px;border-radius:20px;font-weight:600;
   font-size:14px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
   &#128424; Imprimer</button>
</div>
<style>@media print { #bz-back-nav { display:none !important; } }</style>
"""

# NOTE: ':' is intentionally excluded — Path.resolve() raises OSError on
# Windows when a path segment contains ':' (drive-letter syntax). Domains
# with explicit port (host:port) are written by loot/ as plain `host_port`
# elsewhere, so the API never needs ':' here.
_SAFE_DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")


def _safe_domain_dir(domain: str) -> Optional[Path]:
    """Validate the domain segment and confine the resolved path to LOOT_DIR.

    Rejects path-traversal attempts (`..`, slashes, NULs) and anything that
    resolves outside the loot directory.
    """
    if not domain or not _SAFE_DOMAIN_RE.match(domain):
        return None
    if domain in (".", ".."):
        return None
    candidate = (LOOT_DIR / domain).resolve()
    try:
        candidate.relative_to(LOOT_DIR.resolve())
    except ValueError:
        return None
    return candidate


@app.get("/report/{domain}")
async def view_report(domain: str):
    """Serve the generated HTML report with an injected back-to-dashboard button."""
    safe_dir = _safe_domain_dir(domain)
    if safe_dir is None:
        return HTMLResponse("<h1>Invalid domain</h1>", status_code=400)
    report_file = safe_dir / f"RAPPORT_BAZOOKA_{domain}.html"
    if not report_file.exists():
        return HTMLResponse("<h1>Report not found</h1>", status_code=404)
    html = report_file.read_text(encoding="utf-8")
    # Inject after <body> tag (or at start if no body)
    lower = html.lower()
    idx = lower.find("<body")
    if idx >= 0:
        end = html.find(">", idx)
        if end >= 0:
            html = html[: end + 1] + _BACK_BUTTON_HTML + html[end + 1 :]
        else:
            html = _BACK_BUTTON_HTML + html
    else:
        html = _BACK_BUTTON_HTML + html
    return HTMLResponse(html)


@app.get("/api/findings/{domain}")
async def api_findings(domain: str):
    """API endpoint for findings JSON."""
    safe_dir = _safe_domain_dir(domain)
    if safe_dir is None:
        return {"error": "Invalid domain"}
    findings_file = safe_dir / "findings.json"
    if findings_file.exists():
        return json.loads(findings_file.read_text(encoding="utf-8"))
    return {"error": "Not found"}
