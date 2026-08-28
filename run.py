#!/usr/bin/env python3
"""Convenience launcher so you can run Argus without module flags.

    python run.py status

Equivalent to `python -m argus status`. Ensures the local `argus` package is
importable regardless of how the interpreter was started.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argus.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
