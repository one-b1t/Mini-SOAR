from pathlib import Path
import importlib
import sys

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

MODULES = [
    "minisoar",
    "minisoar.config",
    "minisoar.utils",
    "minisoar.database",
    "minisoar.bot",
    "minisoar.daemon",
    "minisoar.mitigation.core",
    "minisoar.mitigation.imperva",
    "minisoar.mitigation.paloalto",
    "minisoar.mitigation.akamai",
    "minisoar.ml.inference",
    "minisoar.ml.export",
    "minisoar.ml.train",
]

for name in MODULES:
    importlib.import_module(name)
    print(f"OK {name}")

print("All imports passed.")
