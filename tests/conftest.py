import importlib
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root.parent))

# Load by directory name, matching Binary Ninja's dynamic plugin loader.
importlib.import_module(repo_root.name)
