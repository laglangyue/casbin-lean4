"""Check real CLI output and exit statuses; requires only Python's standard library."""

import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / ".lake/build/bin/casbin"


def run(args, code):
    result = subprocess.run(
        [str(BINARY), *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    assert result.returncode == code, (args, result.returncode, result.stderr)
    return result


demo = run(["demo"], 0)
assert [json.loads(line)["decision"]["allow"] for line in demo.stdout.splitlines()] == [
    True, False, False
]
model, policy = "examples/basic_model.conf", "examples/basic_policy.csv"
assert json.loads(run(["enforce", model, policy, "alice", "data1", "read"], 0).stdout) == {
    "allow": True, "explain": ["alice", "data1", "read"]
}
assert json.loads(run(["enforce", model, policy, "alice", "data1", "write"], 1).stdout) == {
    "allow": False, "explain": []
}
assert "expected 3 fields" in run(["enforce", model, policy, "alice"], 2).stderr
assert "error:" in run(["enforce", "missing.conf", policy, "alice"], 2).stderr
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / "requests.json"
    path.write_text(json.dumps([["alice", "data1", "read"], ["alice", "data1", "write"]]))
    assert [d["allow"] for d in json.loads(run(["batch", model, policy, str(path)], 0).stdout)] == [
        True, False
    ]
    path.write_text('[123]')
    assert "error:" in run(["batch", model, policy, str(path)], 2).stderr
print("PASS CLI demo, allow/deny exit codes, batch JSON, and input errors")
