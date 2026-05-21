"""Per-plugin vulnerability lookup via wpvulnerability.net (free, no auth).

The Wordfence v2 endpoint was deprecated (March 2025) and v3 now requires a
token. wpvulnerability.net offers a free per-plugin JSON API that mirrors
Wordfence + Patchstack + NVD data. We query on-demand per detected slug and
cache results locally for 24h.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Optional

import httpx

WPV_URL = "https://www.wpvulnerability.net/plugin/{slug}/"
WPV_THEME_URL = "https://www.wpvulnerability.net/theme/{slug}/"
WPV_INFRA_URLS = {
    "php": "https://www.wpvulnerability.net/php/{ver}/",
    "apache": "https://www.wpvulnerability.net/apache/{ver}/",
    "nginx": "https://www.wpvulnerability.net/nginx/{ver}/",
    "mysql": "https://www.wpvulnerability.net/mysql/{ver}/",
    "mariadb": "https://www.wpvulnerability.net/mariadb/{ver}/",
    "imagemagick": "https://www.wpvulnerability.net/imagemagick/{ver}/",
    "curl": "https://www.wpvulnerability.net/curl/{ver}/",
    "redis": "https://www.wpvulnerability.net/redis/{ver}/",
    "memcached": "https://www.wpvulnerability.net/memcached/{ver}/",
    "sqlite": "https://www.wpvulnerability.net/sqlite/{ver}/",
}
WPV_CORE_URL = "https://www.wpvulnerability.net/core/{ver}/"
CACHE_PATH = Path(__file__).parent / "wpvuln_cache.json"
CACHE_TTL = 24 * 3600

_MEM_CACHE: dict[str, dict] = {}
_CACHE_LOADED = False


def _load_cache() -> dict[str, dict]:
    global _MEM_CACHE, _CACHE_LOADED
    if _CACHE_LOADED:
        return _MEM_CACHE
    _CACHE_LOADED = True
    if not CACHE_PATH.exists():
        return _MEM_CACHE
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            blob = json.load(f)
        _MEM_CACHE = blob if isinstance(blob, dict) else {}
    except Exception:
        _MEM_CACHE = {}
    return _MEM_CACHE


def _save_cache() -> None:
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_MEM_CACHE, f)
    except Exception:
        pass


def _parse_ver(v: str) -> tuple:
    if not v or v == "*":
        return ()
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else ()


def _ver_cmp(a: str, b: str) -> int:
    pa, pb = _parse_ver(a), _parse_ver(b)
    if not pa or not pb:
        return 0
    # Pad with zeros so "5.0" == "5.0.0", not "5.0" < "5.0.0"
    n = max(len(pa), len(pb))
    pa = pa + (0,) * (n - len(pa))
    pb = pb + (0,) * (n - len(pb))
    return 0 if pa == pb else (-1 if pa < pb else 1)


def _check_operator(input_version: Optional[str], operator: dict) -> bool:
    """Check if input_version satisfies the wpvulnerability operator spec."""
    if not operator:
        return False
    if input_version is None:
        return True  # unknown version → mark as possible
    min_v = operator.get("min_version")
    min_op = operator.get("min_operator")
    max_v = operator.get("max_version")
    max_op = operator.get("max_operator")
    ok_lo = True
    if min_v and min_v != "*":
        c = _ver_cmp(input_version, min_v)
        if min_op == "gt":
            ok_lo = c > 0
        elif min_op == "ge":
            ok_lo = c >= 0
        elif min_op == "eq":
            ok_lo = c == 0
        else:
            ok_lo = c >= 0
    ok_hi = True
    if max_v and max_v != "*":
        c = _ver_cmp(input_version, max_v)
        if max_op == "lt":
            ok_hi = c < 0
        elif max_op == "le":
            ok_hi = c <= 0
        elif max_op == "eq":
            ok_hi = c == 0
        else:
            ok_hi = c <= 0
    return ok_lo and ok_hi


def _normalize(vuln: dict, slug: str) -> dict:
    sources = vuln.get("source") or []
    cve_id = ""
    refs: list[str] = []
    desc = vuln.get("description") or ""
    for s in sources:
        sid = s.get("id") or s.get("name") or ""
        link = s.get("link") or ""
        if sid.startswith("CVE-") and not cve_id:
            cve_id = sid
        if link:
            refs.append(link)
        if not desc and s.get("description"):
            desc = s.get("description")
    if not cve_id and sources:
        cve_id = sources[0].get("id") or sources[0].get("name") or "WPV-" + (vuln.get("uuid", "")[:12])
    op = vuln.get("operator") or {}
    fixed = op.get("max_version") if op.get("max_operator") in ("lt",) else None
    # CVSS not always present — wpvulnerability records may have impact[]
    cvss_score = 0.0
    severity = "MEDIUM"
    impact = vuln.get("impact") or []
    if impact and isinstance(impact, list):
        try:
            score = float(impact[0].get("score", 0))
            cvss_score = score
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        except Exception:
            pass
    title = (vuln.get("name") or f"Vulnerability in {slug}").replace("&#8211;", "-").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return {
        "wf_id": vuln.get("uuid", ""),
        "cve_id": cve_id,
        "title": title,
        "cvss_score": cvss_score,
        "cvss_vector": "",
        "severity": severity,
        "slug": slug,
        "type": "plugin",
        "fixed_version": fixed,
        "references": refs[:5],
        "vuln_type": vuln.get("vulnerability_type") or "",
        "description": desc or title,
    }


async def _fetch_one(slug: str, is_theme: bool = False) -> list[dict]:
    url = (WPV_THEME_URL if is_theme else WPV_URL).format(slug=slug)
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.get(url, headers={"User-Agent": "wordpress-bazooka/0.1"})
            if resp.status_code != 200:
                return []
            data = resp.json()
    except Exception:
        return []
    if not isinstance(data, dict) or data.get("error"):
        return []
    return (data.get("data") or {}).get("vulnerability") or []


async def fetch_wordfence_vulnerabilities(force: bool = False) -> dict:
    """Legacy-compatible no-op; we now fetch lazily per-slug in match_plugin_cves."""
    _load_cache()
    return _MEM_CACHE


def match_plugin_cves(slug: str, version: Optional[str]) -> list[dict]:
    """Synchronous version. Safe outside an event loop; returns cached-only when inside one.

    Use match_plugin_cves_async from async contexts (cve_matcher does this).
    """
    _load_cache()
    if not slug:
        return []
    slug_l = slug.lower()
    entry = _MEM_CACHE.get(slug_l)
    if entry is None or (time.time() - entry.get("_ts", 0) > CACHE_TTL):
        try:
            asyncio.get_running_loop()
            # We're inside a running loop — refuse to block; return cache-only.
            vulns = entry.get("vulns") if entry else []
        except RuntimeError:
            try:
                vulns = asyncio.run(_fetch_one(slug_l))
            except Exception:
                vulns = []
            entry = {"_ts": time.time(), "vulns": vulns}
            _MEM_CACHE[slug_l] = entry
            _save_cache()
    vulns = (entry or {}).get("vulns") or []
    out: list[dict] = []
    for v in vulns:
        if _check_operator(version, v.get("operator") or {}):
            out.append(_normalize(v, slug_l))
    return out


async def match_plugin_cves_async(slug: str, version: Optional[str]) -> list[dict]:
    """Async-friendly version: safe to call from within an asyncio loop."""
    _load_cache()
    if not slug:
        return []
    slug_l = slug.lower()
    entry = _MEM_CACHE.get(slug_l)
    if entry is None or (time.time() - entry.get("_ts", 0) > CACHE_TTL):
        vulns = await _fetch_one(slug_l)
        entry = {"_ts": time.time(), "vulns": vulns}
        _MEM_CACHE[slug_l] = entry
        _save_cache()
    vulns = entry.get("vulns") or []
    out: list[dict] = []
    for v in vulns:
        if _check_operator(version, v.get("operator") or {}):
            out.append(_normalize(v, slug_l))
    return out


async def _fetch_infra(kind: str, version: str) -> list[dict]:
    """Fetch CVE list from wpvulnerability.net for php/apache/nginx/mysql/mariadb/etc."""
    url_tmpl = WPV_INFRA_URLS.get(kind)
    if not url_tmpl:
        return []
    url = url_tmpl.format(ver=version)
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.get(url, headers={"User-Agent": "wordpress-bazooka/0.1"})
            if resp.status_code != 200:
                return []
            data = resp.json()
    except Exception:
        return []
    if not isinstance(data, dict) or data.get("error"):
        return []
    payload = data.get("data") or {}
    if isinstance(payload, dict):
        return payload.get("vulnerability") or []
    return []


async def match_infra_cves_async(kind: str, version: Optional[str]) -> list[dict]:
    """Lookup CVE for an infra component (php/apache/nginx/mysql/...)."""
    _load_cache()
    if not version or not kind:
        return []
    cache_key = f"__infra_{kind}__{version}"
    entry = _MEM_CACHE.get(cache_key)
    if entry is None or (time.time() - entry.get("_ts", 0) > CACHE_TTL):
        vulns = await _fetch_infra(kind, version)
        entry = {"_ts": time.time(), "vulns": vulns}
        _MEM_CACHE[cache_key] = entry
        _save_cache()
    vulns = entry.get("vulns") or []
    out: list[dict] = []
    for v in vulns:
        # For infra endpoints the input version itself is the queried version,
        # so the API already returns only relevant vulns. We still filter by operator.
        op = v.get("operator") or {}
        if not op or _check_operator(version, op):
            out.append(_normalize(v, f"{kind}:{version}"))
    return out


async def match_core_cves_async(version: Optional[str]) -> list[dict]:
    """Lookup CVE for WordPress core version."""
    _load_cache()
    if not version:
        return []
    cache_key = f"__core__{version}"
    entry = _MEM_CACHE.get(cache_key)
    if entry is None or (time.time() - entry.get("_ts", 0) > CACHE_TTL):
        url = WPV_CORE_URL.format(ver=version)
        try:
            async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
                resp = await client.get(url, headers={"User-Agent": "wordpress-bazooka/0.1"})
                vulns = []
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict) and not data.get("error"):
                        payload = data.get("data") or {}
                        if isinstance(payload, dict):
                            vulns = payload.get("vulnerability") or []
        except Exception:
            vulns = []
        entry = {"_ts": time.time(), "vulns": vulns}
        _MEM_CACHE[cache_key] = entry
        _save_cache()
    return [_normalize(v, f"wp-core:{version}") for v in (entry.get("vulns") or [])]
