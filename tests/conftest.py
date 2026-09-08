import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pixel_firmware_formats  # noqa: E402,F401  (module-level import registers every format's Transform)
