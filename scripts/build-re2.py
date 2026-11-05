#!/usr/bin/env python3
"""Build a pinned RE2 dependency and the Lean FFI; never execute policy data."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
VERSION = "2023-03-01"
SHA256 = "7a9a4824958586980926a300b4717202485c4b4115ac031822e29aa4ef207e48"
base = ROOT / ".lake" / "native"
base.mkdir(parents=True, exist_ok=True)
archive = base / "re2.tar.gz"
if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
    with urllib.request.urlopen(f"https://codeload.github.com/google/re2/tar.gz/refs/tags/{VERSION}", timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError("RE2 archive checksum mismatch")
    archive.write_bytes(data)
source = base / f"re2-{VERSION}"
if not source.exists():
    with tarfile.open(archive) as tar:
        # The checksum authenticates the pinned archive; reject path traversal too.
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in Path(member.name).parts or member.issym() or member.islnk():
                raise RuntimeError("Unsafe RE2 archive member")
        tar.extractall(base)
compiler = os.environ.get("CXX", "c++")
include, output = sys.argv[1:]
out = Path(output).resolve()
out.parent.mkdir(parents=True, exist_ok=True)
objects = base / "objects"
objects.mkdir(exist_ok=True)
names = "bitmap256 bitstate compile dfa filtered_re2 mimics_pcre nfa onepass parse perl_groups prefilter prefilter_tree prog re2 regexp set simplify stringpiece tostring unicode_casefold unicode_groups".split()
sources = [source / "re2" / f"{name}.cc" for name in names]
sources += [source / "util" / "rune.cc", source / "util" / "strutil.cc", ROOT / "native" / "regex.cpp"]

def build(path):
    obj = objects / (path.stem + ".o")
    if not obj.exists() or obj.stat().st_mtime < path.stat().st_mtime:
        subprocess.run([compiler, "-std=c++11", "-O2", "-fPIC", "-pthread", "-I", str(source), "-I", include, "-c", str(path), "-o", str(obj)], check=True)
    return str(obj)

with concurrent.futures.ThreadPoolExecutor(max_workers=min(os.cpu_count() or 2, 4)) as pool:
    built = list(pool.map(build, sources))
temporary = out.with_suffix(".tmp.a")
subprocess.run(["ar", "rcs", str(temporary), *built], check=True)
temporary.replace(out)
shutil.copyfile(source / "LICENSE", base / "RE2-LICENSE")
