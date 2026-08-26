import os
import subprocess
from pathlib import Path
from minisoar.config import load_env
from minisoar.ai.copilot import _call_headless_cli

load_env()
cand = os.path.expanduser("~/.local/bin/agy")
print("cand:", cand, "exists:", os.path.exists(cand))
res = subprocess.run([cand, "-p", "test", "--output-format", "text", "--disable-slash-commands"], capture_output=True, text=True, encoding="utf-8", errors="replace")
print("direct code:", res.returncode)
print("direct stdout:", res.stdout[:200] if res.stdout else None)
print("direct stderr:", res.stderr[:200] if res.stderr else None)

cli_res = _call_headless_cli("gemini", "test")
print("copilot helper result:", cli_res[:200] if cli_res else None)
