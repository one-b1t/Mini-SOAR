#!/usr/bin/env python3
"""Backward-compatible entrypoint for exporting the ML dataset."""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from minisoar.ml.export import main


if __name__ == "__main__":
    main()
