# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for a single-file portable WordPress BAZOOKA executable.

Bundles:
  - all dynamically-discovered modules under modules/
  - the GUI templates and FastAPI app
  - the CVE seed DB and data wordlists
  - all transitive deps (httpx, FastAPI, Uvicorn, Jinja2, Pydantic, etc.)
"""

import os
from pathlib import Path

ROOT = Path(os.path.abspath(SPECPATH))

# Recursively collect every module under modules/ so dynamic discovery works
hidden_modules: list[str] = []
for folder in (ROOT / "modules").rglob("*.py"):
    rel = folder.relative_to(ROOT).with_suffix("")
    if rel.name == "__init__":
        rel = rel.parent
    hidden_modules.append(".".join(rel.parts))

# GUI app, report exporters, cve_db
hidden_modules += [
    "gui.app", "core.engine", "core.session", "core.models",
    "report.generator", "report.html_template", "report.docx_exporter",
    "cve_db.manager", "cve_db.wordfence_fetcher",
]

# Things FastAPI / Uvicorn / Starlette / Pydantic need that PyInstaller often misses
hidden_modules += [
    "uvicorn.logging", "uvicorn.loops", "uvicorn.loops.auto",
    "uvicorn.protocols", "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets", "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan", "uvicorn.lifespan.on",
    "uvicorn.workers", "websockets",
    "anyio._backends._asyncio",
    "pydantic.deprecated.decorator",
    "email.mime.multipart", "email.mime.text", "email.mime.base",
    "dns.resolver", "dns.rdtypes", "dns.rdtypes.IN", "dns.rdtypes.ANY",
]

datas = [
    ("data", "data"),
    ("gui/templates", "gui/templates"),
    ("cve_db/schema.sql", "cve_db"),
    ("cve_db/bazooka_cve.db", "cve_db"),
]

# Static dir is optional
if (ROOT / "gui" / "static").exists():
    datas.append(("gui/static", "gui/static"))


a = Analysis(
    ['bazooka.py'],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_modules,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        'tkinter', 'matplotlib', 'pytest', 'playwright',
        'PyQt5', 'PyQt6', 'PySide2', 'PySide6',
        'IPython', 'ipykernel', 'notebook', 'jupyter',
        'pandas', 'numpy', 'scipy', 'sklearn',
        'PIL', 'PIL.Image', 'PIL.ImageFilter',
        'zmq', 'pyzmq',
        'black', 'lark',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='bazooka',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
