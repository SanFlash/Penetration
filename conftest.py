"""Pytest bootstrap for the flat project layout.

The framework modules (for example ``config`` and ``scanners``) live at the
repository root rather than in an installed package. Adding the repository
root to ``sys.path`` keeps pytest behavior consistent across normal
Windows/macOS/Linux checkouts and CI runners.
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
