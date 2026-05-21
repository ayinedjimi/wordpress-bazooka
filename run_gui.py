#!/usr/bin/env python3
"""Launch WordPress BAZOOKA Web GUI."""

import sys
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import uvicorn


def main():
    port = 8666
    print()
    print("  +----------------------------------------------+")
    print("  |   WORDPRESS BAZOOKA -- Web GUI               |")
    print(f"  |   http://localhost:{port}                      |")
    print("  |   Press Ctrl+C to stop                       |")
    print("  +----------------------------------------------+")
    print()

    webbrowser.open(f"http://localhost:{port}")

    uvicorn.run(
        "gui.app:app",
        host="127.0.0.1",
        port=port,
        reload=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
