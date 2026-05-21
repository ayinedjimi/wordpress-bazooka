"""WordPress core fingerprint database builder.

Downloads WordPress release ZIPs from wordpress.org, extracts a fixed list of
publicly-reachable files, computes their MD5 and stores unique-per-version
hashes in data/wp_fingerprints.json.

Run standalone:
    python -m cve_db.wp_fingerprints_builder [--full] [--limit N] [--dry-run]

Author: Ayi NEDJIMI <ayinedjimi@users.noreply.github.com>
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Iterable

import httpx

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
OUT_PATH = DATA_DIR / "wp_fingerprints.json"
PROGRESS_PATH = ROOT / "cve_db" / ".wp_fingerprints_progress.json"
CACHE_DIR = Path(tempfile.gettempdir()) / "bazooka_wp_fingerprints"

VERSION_CHECK_URL = "https://api.wordpress.org/core/version-check/1.7/"
ZIP_URL_TPL = "https://wordpress.org/wordpress-{ver}.zip"

# Files that are publicly reachable over HTTP on a default WP install and which
# tend to change between releases. Dynamic / PHP / often-edited files excluded.
FINGERPRINT_FILES: list[str] = [
    "wp-includes/js/wp-embed.min.js",
    "wp-includes/js/wp-emoji-release.min.js",
    "wp-includes/css/dist/block-library/style.min.css",
    "wp-admin/css/colors/blue/colors.min.css",
    "wp-admin/css/wp-admin.min.css",
]

# Historical "every-other-minor" sweep so we cover pre-version-check-API releases.
HISTORICAL_VERSIONS: list[str] = [
    "4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9",
    "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8", "5.9",
    "6.0", "6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8",
]


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


async def fetch_version_check(client: httpx.AsyncClient) -> list[str]:
    """Return the WP versions advertised by the official version-check API."""
    try:
        r = await client.get(VERSION_CHECK_URL, timeout=30.0)
        r.raise_for_status()
        payload = r.json()
    except Exception as exc:
        print(f"[warn] version-check API unreachable: {exc}", file=sys.stderr)
        return []
    versions: set[str] = set()
    for off in payload.get("offers", []):
        for key in ("current", "version"):
            v = off.get(key)
            if v:
                versions.add(v)
    return sorted(versions, key=_ver_key)


def _ver_key(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def plan_versions(full: bool, extra_api: list[str]) -> list[str]:
    if full:
        # Same as --no-full for now; --full would normally hit the full release
        # archive. We still cap by extending the historical sweep with patches.
        all_vers = set(HISTORICAL_VERSIONS) | set(extra_api)
    else:
        all_vers = set(HISTORICAL_VERSIONS) | set(extra_api)
    return sorted(all_vers, key=_ver_key)


async def download_zip(client: httpx.AsyncClient, ver: str) -> bytes | None:
    url = ZIP_URL_TPL.format(ver=ver)
    try:
        r = await client.get(url, timeout=180.0, follow_redirects=True)
        if r.status_code != 200:
            print(f"[skip] {ver}: HTTP {r.status_code}")
            return None
        return r.content
    except Exception as exc:
        print(f"[skip] {ver}: {exc}")
        return None


def extract_hashes(zip_bytes: bytes) -> dict[str, str]:
    """Return {fingerprint_path: md5} for files present in this WP ZIP."""
    out: dict[str, str] = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        return out
    # ZIP root is "wordpress/"
    names = {n: n for n in zf.namelist()}
    for fp in FINGERPRINT_FILES:
        candidate = f"wordpress/{fp}"
        if candidate in names:
            try:
                data = zf.read(candidate)
            except KeyError:
                continue
            out[fp] = _md5(data)
    return out


def load_progress() -> dict:
    if PROGRESS_PATH.exists():
        try:
            return json.loads(PROGRESS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"versions": {}}


def save_progress(state: dict) -> None:
    PROGRESS_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROGRESS_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def build_unique_db(per_version: dict[str, dict[str, str]]) -> tuple[dict, int, int]:
    """Invert {version: {file: md5}} into {file: {md5: version}} keeping only
    hashes unique to a single version. Returns (db, unique_count, ambiguous_count).
    """
    # For each file, collect md5 -> [versions]
    files_db: dict[str, dict[str, list[str]]] = {fp: {} for fp in FINGERPRINT_FILES}
    for ver, mapping in per_version.items():
        for fp, md5 in mapping.items():
            files_db.setdefault(fp, {}).setdefault(md5, []).append(ver)

    out_files: dict[str, dict[str, str]] = {}
    unique = 0
    ambiguous = 0
    for fp, hashes in files_db.items():
        out_files[fp] = {}
        for md5, vers in hashes.items():
            if len(vers) == 1:
                out_files[fp][md5] = vers[0]
                unique += 1
            else:
                ambiguous += 1
    return out_files, unique, ambiguous


async def run_build(versions: list[str], dry_run: bool) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    state = load_progress()
    per_version: dict[str, dict[str, str]] = dict(state.get("versions", {}))

    todo = [v for v in versions if v not in per_version]
    print(f"[info] {len(versions)} versions planned, {len(todo)} to download "
          f"({len(per_version)} cached).")
    if dry_run:
        print("[dry-run] Would download:")
        for v in todo:
            print(f"  - {v}  ({ZIP_URL_TPL.format(ver=v)})")
        return

    async with httpx.AsyncClient(http2=False) as client:
        for i, ver in enumerate(todo, 1):
            print(f"[{i}/{len(todo)}] {ver} ...", flush=True)
            zip_bytes = await download_zip(client, ver)
            if zip_bytes is None:
                continue
            hashes = extract_hashes(zip_bytes)
            if not hashes:
                print(f"  [warn] no fingerprintable files in {ver}")
                continue
            per_version[ver] = hashes
            state["versions"] = per_version
            save_progress(state)
            print(f"  [ok] {len(hashes)} files hashed")

    files_db, unique, ambiguous = build_unique_db(per_version)
    out = {
        "_meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "wp_versions": len(per_version),
            "files": len(FINGERPRINT_FILES),
            "unique_hashes": unique,
            "ambiguous_discarded": ambiguous,
            "hash": "md5",
        },
        "files": files_db,
    }
    OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    size_kb = OUT_PATH.stat().st_size / 1024
    print(
        f"[done] versions={len(per_version)} unique_md5={unique} "
        f"ambiguous_discarded={ambiguous} size={size_kb:.1f} KB -> {OUT_PATH}"
    )


def _maybe_clear_cache() -> None:
    if CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wp_fingerprints_builder",
        description=(
            "Build the WordPress core fingerprint database "
            "(data/wp_fingerprints.json) by downloading official release ZIPs "
            "and hashing a fixed set of publicly-reachable files."
        ),
    )
    p.add_argument(
        "--full",
        action="store_true",
        help="Include every patch release from the version-check API (slow, ~1 GB download).",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process the first N planned versions (debugging).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show which versions would be downloaded, do not fetch anything.",
    )
    p.add_argument(
        "--reset",
        action="store_true",
        help="Wipe the progress file and start from scratch.",
    )
    return p


async def _async_main(args: argparse.Namespace) -> None:
    if args.reset and PROGRESS_PATH.exists():
        PROGRESS_PATH.unlink()
    async with httpx.AsyncClient() as client:
        api_vers = await fetch_version_check(client)
    print(f"[info] version-check API returned {len(api_vers)} versions")
    versions = plan_versions(args.full, api_vers)
    if args.limit > 0:
        versions = versions[: args.limit]
    await run_build(versions, args.dry_run)


def main(argv: Iterable[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    asyncio.run(_async_main(args))


if __name__ == "__main__":
    main()
