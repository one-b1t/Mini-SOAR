from __future__ import annotations

"""MiniSOAR alert daemon entry module.

Short-term refactor strategy:
- keep legacy behavior intact by delegating to a preserved legacy script
- expose a stable `main()` entrypoint for future internal migration
"""

from pathlib import Path
import runpy


def main() -> None:
    legacy = Path(__file__).with_name("legacy_alert_daemon.py")
    if not legacy.exists():
        raise FileNotFoundError(f"Legacy daemon script not found: {legacy}")
    runpy.run_path(str(legacy), run_name="__main__")


if __name__ == "__main__":
    main()
