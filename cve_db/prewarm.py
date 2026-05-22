"""Pre-warm CVE cache from multiple free sources.

Collects vulnerability data from:
- wpvulnerability.net (per-plugin, per-theme, per-core, per-infra)
- CISA KEV catalog (actively exploited)
- OSV.dev (cross-source, optional)

Output: `cve_db/prewarm_cache.json` shipped inside the exe.
Refreshed by `bazooka update-db` command.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Optional

import httpx

CACHE_PATH = Path(__file__).parent / "prewarm_cache.json"

# Top WP plugin slugs to pre-warm (popularity-ordered)
PLUGIN_SEED_FILE = Path(__file__).parent.parent / "data" / "wp_plugins_priority.txt"
THEME_SEEDS = [
    "twentyeleven", "twentytwelve", "twentythirteen", "twentyfourteen",
    "twentyfifteen", "twentysixteen", "twentyseventeen", "twentynineteen",
    "twentytwenty", "twentytwentyone", "twentytwentytwo", "twentytwentythree",
    "twentytwentyfour", "twentytwentyfive",
    "astra", "hello-elementor", "oceanwp", "generatepress", "kadence",
    "neve", "blocksy", "sydney", "shapely", "zerif-lite",
    "storefront", "flatsome", "avada", "divi", "newspaper",
    "soledad", "the7", "bridge", "x", "salient",
]
WP_CORE_VERSIONS = [
    "4.7", "4.8", "4.9",
    "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8", "5.9",
    "6.0", "6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8", "6.9",
]
APACHE_VERSIONS = ["2.2.34", "2.4.38", "2.4.41", "2.4.48", "2.4.51", "2.4.54",
                   "2.4.57", "2.4.58", "2.4.59", "2.4.60"]
NGINX_VERSIONS = ["1.14.2", "1.18.0", "1.20.1", "1.22.0", "1.24.0", "1.26.0"]
PHP_VERSIONS = ["7.1.33", "7.2.34", "7.3.33", "7.4.33", "8.0.30",
                "8.1.27", "8.2.16", "8.3.4"]
MYSQL_VERSIONS = ["5.6.51", "5.7.43", "8.0.36"]
MARIADB_VERSIONS = ["10.3.39", "10.4.33", "10.5.24", "10.6.17", "10.11.7"]
REDIS_VERSIONS = ["5.0.14", "6.0.20", "6.2.14", "7.0.15", "7.2.4"]
MEMCACHED_VERSIONS = ["1.6.9", "1.6.18", "1.6.22"]
IMAGEMAGICK_VERSIONS = ["6.9.10", "7.0.10", "7.1.0", "7.1.1"]
CURL_VERSIONS = ["7.61.0", "7.74.0", "7.81.0", "7.88.0", "8.0.1", "8.4.0", "8.7.1"]

WPV_BASE = "https://www.wpvulnerability.net"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API = "https://api.osv.dev/v1/query"

_HEADERS = {"User-Agent": "wordpress-bazooka-prewarm/1.0"}


async def _fetch_json(client: httpx.AsyncClient, url: str, timeout: float = 20.0) -> Optional[dict]:
    try:
        r = await client.get(url, timeout=timeout, headers=_HEADERS)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _slug_variants(slug: str) -> list[str]:
    s = (slug or "").lower().strip()
    if not s:
        return []
    out = [s]
    if "_" in s:
        out.append(s.replace("_", "-"))
    for suf in ("-pro", "-lite", "-free", "-premium"):
        if s.endswith(suf):
            base = s[: -len(suf)]
            if base:
                out.append(base)
                out.append(base.replace("_", "-"))
    if s.startswith("wp-"):
        out.append(s[3:])
    seen, final = set(), []
    for v in out:
        if v and v not in seen:
            seen.add(v); final.append(v)
    return final


async def _fetch_wpvuln(client: httpx.AsyncClient, kind: str, ident: str) -> list:
    # For plugins/themes try canonical slug variants; for versions just one shot.
    candidates = _slug_variants(ident) if kind in ("plugin", "theme") else [ident]
    for cand in candidates:
        url = f"{WPV_BASE}/{kind}/{cand}/"
        data = await _fetch_json(client, url)
        if not isinstance(data, dict) or data.get("error"):
            continue
        payload = data.get("data") or {}
        if isinstance(payload, dict):
            vulns = payload.get("vulnerability") or []
            if vulns:
                return vulns
    return []


def _load_plugin_seeds(limit: int = 250) -> list[str]:
    out: list[str] = []
    if not PLUGIN_SEED_FILE.exists():
        return out
    seen = set()
    for line in PLUGIN_SEED_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= limit:
            break
    return out


async def _fetch_cisa_kev(client: httpx.AsyncClient) -> list[dict]:
    data = await _fetch_json(client, CISA_KEV_URL, timeout=30)
    if not isinstance(data, dict):
        return []
    # CISA KEV: filter WordPress-related entries
    entries = data.get("vulnerabilities") or []
    wp_kev: list[dict] = []
    for e in entries:
        product = (e.get("product") or "").lower()
        vendor = (e.get("vendorProject") or "").lower()
        notes = (e.get("notes") or "").lower()
        if "wordpress" in product or "wordpress" in vendor or "wordpress" in notes:
            wp_kev.append({
                "cve_id": e.get("cveID", ""),
                "vendor": e.get("vendorProject"),
                "product": e.get("product"),
                "name": e.get("vulnerabilityName"),
                "added": e.get("dateAdded"),
                "due": e.get("dueDate"),
                "kev": True,
            })
    return wp_kev


async def _fetch_osv_plugin(client: httpx.AsyncClient, slug: str) -> list[dict]:
    """Best-effort OSV query — slugs are not perfectly aligned, used only as cross-ref."""
    payload = {"package": {"name": slug, "ecosystem": "Packagist"}}
    try:
        r = await client.post(OSV_API, json=payload, headers=_HEADERS, timeout=15)
        if r.status_code != 200:
            return []
        data = r.json()
        return data.get("vulns") or []
    except Exception:
        return []


async def prewarm(
    plugin_limit: int = 250,
    include_osv: bool = False,
    include_kev: bool = True,
    concurrency: int = 8,
    verbose: bool = True,
) -> dict:
    """Fetch all CVE data and return a single bundle dict."""
    bundle: dict = {
        "_meta": {"generated_at": time.time(), "schema": "bazooka-prewarm-v1"},
        "plugins": {},
        "themes": {},
        "core": {},
        "infra": {},
        "kev": [],
        "osv": {},
    }

    plugin_slugs = _load_plugin_seeds(plugin_limit)

    sem = asyncio.Semaphore(concurrency)
    counters = {"plugins": 0, "themes": 0, "core": 0, "infra": 0}

    # SSL verification ON by default; users behind MITM proxy can opt out
    # via BAZOOKA_INSECURE_FETCH=1 (same env var as the runtime fetcher).
    import os as _os
    _verify = _os.getenv("BAZOOKA_INSECURE_FETCH", "").lower() not in ("1", "true", "yes")
    async with httpx.AsyncClient(verify=_verify) as client:

        async def fetch_plugin(slug: str) -> None:
            async with sem:
                vulns = await _fetch_wpvuln(client, "plugin", slug)
            if vulns:
                bundle["plugins"][slug.lower()] = vulns
            counters["plugins"] += 1
            if verbose and counters["plugins"] % 25 == 0:
                print(f"  plugins: {counters['plugins']}/{len(plugin_slugs)}")

        async def fetch_theme(slug: str) -> None:
            async with sem:
                vulns = await _fetch_wpvuln(client, "theme", slug)
            if vulns:
                bundle["themes"][slug.lower()] = vulns
            counters["themes"] += 1

        async def fetch_core(ver: str) -> None:
            async with sem:
                vulns = await _fetch_wpvuln(client, "core", ver)
            if vulns:
                bundle["core"][ver] = vulns
            counters["core"] += 1

        async def fetch_infra(kind: str, ver: str) -> None:
            async with sem:
                vulns = await _fetch_wpvuln(client, kind, ver)
            if vulns:
                bundle["infra"].setdefault(kind, {})[ver] = vulns
            counters["infra"] += 1

        infra_jobs = []
        for v in APACHE_VERSIONS:
            infra_jobs.append(fetch_infra("apache", v))
        for v in NGINX_VERSIONS:
            infra_jobs.append(fetch_infra("nginx", v))
        for v in PHP_VERSIONS:
            infra_jobs.append(fetch_infra("php", v))
        for v in MYSQL_VERSIONS:
            infra_jobs.append(fetch_infra("mysql", v))
        for v in MARIADB_VERSIONS:
            infra_jobs.append(fetch_infra("mariadb", v))
        for v in REDIS_VERSIONS:
            infra_jobs.append(fetch_infra("redis", v))
        for v in MEMCACHED_VERSIONS:
            infra_jobs.append(fetch_infra("memcached", v))
        for v in IMAGEMAGICK_VERSIONS:
            infra_jobs.append(fetch_infra("imagemagick", v))
        for v in CURL_VERSIONS:
            infra_jobs.append(fetch_infra("curl", v))

        if verbose:
            print(f"[prewarm] Fetching {len(plugin_slugs)} plugins, "
                  f"{len(THEME_SEEDS)} themes, {len(WP_CORE_VERSIONS)} core, "
                  f"{len(infra_jobs)} infra versions")

        await asyncio.gather(
            *(fetch_plugin(s) for s in plugin_slugs),
            *(fetch_theme(s) for s in THEME_SEEDS),
            *(fetch_core(v) for v in WP_CORE_VERSIONS),
            *infra_jobs,
            return_exceptions=True,
        )

        if include_kev:
            if verbose:
                print("[prewarm] Fetching CISA KEV catalog...")
            bundle["kev"] = await _fetch_cisa_kev(client)

        if include_osv:
            if verbose:
                print("[prewarm] Fetching OSV.dev (best-effort)...")
            osv_jobs = []
            for slug in plugin_slugs[:50]:
                async def one(s=slug):
                    async with sem:
                        vulns = await _fetch_osv_plugin(client, s)
                    if vulns:
                        bundle["osv"][s.lower()] = vulns
                osv_jobs.append(one())
            await asyncio.gather(*osv_jobs, return_exceptions=True)

    bundle["_meta"]["counts"] = {
        "plugins": len(bundle["plugins"]),
        "themes": len(bundle["themes"]),
        "core": len(bundle["core"]),
        "infra_kinds": len(bundle["infra"]),
        "kev": len(bundle["kev"]),
        "osv": len(bundle["osv"]),
    }
    return bundle


def save_bundle(bundle: dict, path: Path = CACHE_PATH) -> int:
    """Atomic write: stage to .tmp then os.replace() so a crash or a
    concurrent `update-db` cannot leave the cache half-written / corrupted."""
    import os as _os
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
    _os.replace(tmp, path)
    return path.stat().st_size


def load_bundle() -> Optional[dict]:
    if not CACHE_PATH.exists():
        return None
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


async def main_cli(verbose: bool = True) -> int:
    bundle = await prewarm(verbose=verbose)
    size = save_bundle(bundle)
    if verbose:
        c = bundle["_meta"]["counts"]
        print(f"\n[prewarm] Done. {c['plugins']} plugins, {c['themes']} themes, "
              f"{c['core']} core, {len(bundle['infra'])} infra kinds, {c['kev']} KEV.")
        print(f"[prewarm] Cache: {CACHE_PATH} ({size/1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    asyncio.run(main_cli())
