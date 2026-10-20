"""Import the vendored rigforge checkout when rigforge is not installed.

proof-studio runs from its repo clone and vendors the core library under
packages/rigforge. Call ensure_rigforge() before importing rigforge modules.
"""

from __future__ import annotations

import sys
from pathlib import Path

VENDORED = Path(__file__).resolve().parents[1] / "packages" / "rigforge"


def ensure_rigforge() -> None:
    """Make `import rigforge` resolve, preferring an installed copy."""
    try:
        import rigforge  # noqa: F401
    except ImportError:
        if not (VENDORED / "rigforge").is_dir():
            raise
        sys.path.insert(0, str(VENDORED))
