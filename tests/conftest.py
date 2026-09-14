import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import easy_firmware_opening  # noqa: E402,F401  (module-level import registers every format's Transform)
