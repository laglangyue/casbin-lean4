#!/usr/bin/env python3
"""Run a Lean example with the RE2 primitive loaded into Lean's interpreter."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
if len(sys.argv) < 2:
    raise SystemExit("usage: python3 scripts/run-lean.py FILE.lean [ARGS...]")
subprocess.run(["lake", "build", "Casbin"], cwd=root, check=True)
native = subprocess.check_output(["lake", "-q", "query", "Casbin.Native:dynlib"], cwd=root, text=True).strip()
suffix = Path(native).suffix
re2 = root / ".lake/build/lib" / ("libcasbin_re2" + suffix)
result = subprocess.run(["lake", "env", "lean", "--load-dynlib=" + str(re2), "--plugin=" + native,
                         "--run", *sys.argv[1:]], cwd=root)
raise SystemExit(result.returncode)
