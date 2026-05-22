"""Embedded Tor SOCKS5 proxy launcher.

Spawns the bundled tor.exe as a subprocess, waits for the SOCKS port to be
ready, and exposes the proxy URL to BAZOOKA modules. On shutdown, the Tor
process is killed cleanly.

Tor binary location:
  - In source tree:  vendor/tor/tor/tor.exe
  - In frozen exe:   sys._MEIPASS/vendor/tor/tor/tor.exe (bundled by spec)
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional


def _resource_root() -> Path:
    """Return the dir that contains 'vendor/' both in dev and frozen mode."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
    return Path(__file__).parent.parent


def find_tor_binary() -> Optional[Path]:
    root = _resource_root()
    candidates = [
        root / "vendor" / "tor" / "tor" / "tor.exe",
        root / "vendor" / "tor" / "tor.exe",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def find_geoip_dir() -> Optional[Path]:
    root = _resource_root()
    for c in (root / "vendor" / "tor" / "data", root / "vendor" / "tor"):
        if (c / "geoip").exists():
            return c
    return None


def _free_port(preferred: int = 9150) -> int:
    """Return a free port (try preferred first).

    Note: there is an inherent TOCTOU window between this probe and Tor's
    bind. The caller MUST handle Tor failing to bind and retry by calling
    this again — see TorProcess.start() for the retry loop.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", preferred))
        s.close()
        return preferred
    except OSError:
        s.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class TorProcess:
    """Manages an embedded Tor process and its SOCKS proxy URL."""

    def __init__(
        self,
        socks_port: Optional[int] = None,
        control_port: Optional[int] = None,
        data_dir: Optional[Path] = None,
        verbose: bool = False,
    ) -> None:
        self.binary = find_tor_binary()
        if self.binary is None:
            raise RuntimeError(
                "Tor binary not found. Expected at vendor/tor/tor/tor.exe."
            )
        self.geoip_dir = find_geoip_dir()
        self.socks_port = socks_port or _free_port(9150)
        self.control_port = control_port or _free_port(self.socks_port + 1)
        self.data_dir = data_dir or Path(tempfile.mkdtemp(prefix="bazooka-tor-"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.process: Optional[subprocess.Popen] = None
        self.verbose = verbose

    @property
    def proxy_url(self) -> str:
        return f"socks5://127.0.0.1:{self.socks_port}"

    def _build_torrc(self) -> Path:
        torrc = self.data_dir / "torrc"
        lines = [
            f"SocksPort 127.0.0.1:{self.socks_port}",
            f"ControlPort 127.0.0.1:{self.control_port}",
            "CookieAuthentication 1",
            f"DataDirectory {self.data_dir.as_posix()}",
            "AvoidDiskWrites 1",
            "ClientOnly 1",
        ]
        if self.geoip_dir is not None:
            geoip = (self.geoip_dir / "geoip")
            if geoip.exists():
                lines.append(f"GeoIPFile {geoip.as_posix()}")
        torrc.write_text("\n".join(lines), encoding="utf-8")
        return torrc

    def start(self, ready_timeout: float = 60.0) -> None:
        """Boot tor.exe with a retry loop on port collisions (TOCTOU window
        between _free_port returning and tor binding the same port).
        """
        stdout = None if self.verbose else subprocess.DEVNULL
        creationflags = 0
        if sys.platform == "win32":
            creationflags = 0x08000000  # CREATE_NO_WINDOW

        last_exc: Optional[Exception] = None
        for attempt in range(3):
            torrc = self._build_torrc()
            self.process = subprocess.Popen(
                [str(self.binary), "-f", str(torrc)],
                stdout=stdout,
                stderr=subprocess.STDOUT,
                # Detach stdin so tor never blocks waiting for a passphrase / TTY
                # confirmation if the parent stdin is something unusual.
                stdin=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            deadline = time.time() + ready_timeout
            while time.time() < deadline:
                rc = self.process.poll()
                if rc is not None:
                    # Tor died — likely "Could not bind to ..." port collision.
                    # Re-pick fresh ports and retry up to 3 times.
                    last_exc = RuntimeError(f"Tor exited prematurely (rc={rc}) on attempt {attempt+1}")
                    self.socks_port = _free_port(0)
                    self.control_port = _free_port(0)
                    break
                if _port_open(self.socks_port):
                    time.sleep(2.0)  # bootstrap head-start
                    if _port_open(self.socks_port):
                        return
                time.sleep(0.5)
            else:
                self.stop()
                raise TimeoutError(
                    f"Tor did not open SOCKS port {self.socks_port} in {ready_timeout}s"
                )
        # All retries exhausted
        if last_exc:
            raise last_exc
        raise RuntimeError("Tor failed to start after 3 attempts")

    def rotate_identity(self) -> bool:
        """Send NEWNYM to get a fresh circuit (new exit IP). Best-effort."""
        try:
            # Read cookie auth (16 bytes hex)
            cookie_path = self.data_dir / "control_auth_cookie"
            if not cookie_path.exists():
                return False
            cookie_hex = cookie_path.read_bytes().hex().upper()
            with socket.create_connection(("127.0.0.1", self.control_port), timeout=5) as s:
                # Inherit timeout on subsequent recv calls — without this the
                # socket defaults back to blocking forever if Tor wedges.
                s.settimeout(5)
                s.sendall(f"AUTHENTICATE {cookie_hex}\r\n".encode())
                resp = s.recv(256)
                if b"250" not in resp:
                    return False
                s.sendall(b"SIGNAL NEWNYM\r\n")
                resp = s.recv(256)
                return b"250" in resp
        except Exception:
            return False

    def stop(self) -> None:
        if self.process is not None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None

    def __enter__(self) -> "TorProcess":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
